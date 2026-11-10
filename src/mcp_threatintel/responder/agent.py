"""HostAgent (threatintel-responder): the privileged half of mcp-threatintel.

Two listeners, each with a closed list of operations:

* agent channel (AGENT_ADDR, AGENT_TOKEN): used by the unprivileged MCP server.
  Scans, create an action, read actions, request a rollback. It cannot
  approve anything.
* admin channel (ADMIN_ADDR, token file readable by administrators only):
  used by threatintel-approve. Approve, reject, read the audit log.

A background loop executes approved actions and expires network blocks.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import logging
import os
import secrets
import sys
from datetime import datetime, timezone

from .actions import ActionManager, TransitionError
from .backends import BackendError, CommandRunner, build_backends
from .backends.nftables import NftablesBackend
from .config import ResponderConfig
from .iocs import IocIndex
from .alerts import AlertEngine
from .autonomy import Autonomy
from .monitor import ConnectionSampler, DnsMonitor, FileWatcher
from .protocol import serve
from .scanner import HostScanner
from .store import ResponderDB, now_iso
from .validators import Allowlist, ValidationError, discover_allowlist, load_allowlist_file

logger = logging.getLogger("threatintel.responder")

AGENT_OPS = {
    "ping", "scan_connections", "scan_files", "scan_auth_logs", "scan_host", "scan_dns", "scan_processes", "list_alerts",
    "investigate_host", "related_iocs", "save_alert_report", "resolve_alert",
    "create_action", "get_action", "list_actions", "request_rollback",
}
ADMIN_OPS = {"ping", "list_actions", "get_action", "approve", "reject", "audit", "list_alerts"}


def summarize(action: dict) -> dict:
    """The view of an action returned to callers (params trimmed for big feeds)."""
    params = dict(action["params"])
    if isinstance(params.get("ips"), list) and len(params["ips"]) > 10:
        params["ips"] = params["ips"][:10] + [f"... {len(action['params']['ips']) - 10} more"]
    result = action.get("result") or {}
    return {
        "id": action["id"],
        "type": action["type"],
        "target": action["target"],
        "status": action["status"],
        "params": params,
        "reason": action["reason"],
        "requested_by": action["requested_by"],
        "created_at": action["created_at"],
        "approved_by": action["approved_by"],
        "executed_at": action["executed_at"],
        "expires_at": action["expires_at"],
        "rollback_of": action["rollback_of"],
        "dry_run": action["dry_run"],
        "error": result.get("error"),
        "commands": (result.get("state") or result).get("commands"),
    }


class HostAgent:
    def __init__(self, config: ResponderConfig, *, admin_token: str | None = None,
                 discover: bool = True, backends: dict[bool, dict] | None = None):
        self.config = config
        self.db = ResponderDB(config.responder_db)
        entries = (discover_allowlist() if discover else []) + load_allowlist_file(config.allowlist_file)
        self.db.replace_allowlist(entries)
        self.allowlist = Allowlist(self.db.load_allowlist())
        self.iocs = IocIndex(config.ioc_db)
        self.sampler = ConnectionSampler()
        self.dns = DnsMonitor()
        self.scanner = HostScanner(config, self.iocs, self.sampler, self.dns)
        self.manager = ActionManager(self.db, self.allowlist, self.iocs, config)
        self.detector = AlertEngine(self.db, self.manager, self.scanner, interval_s=config.detect_interval,
                                    aggregate_minutes=config.alert_aggregate_minutes)
        self.autonomy = Autonomy(self.db, self.manager, config)
        # Event-driven detection: collectors report new observables straight to the engine.
        self.sampler.on_new = self.detector.on_connection
        self.dns.on_new = self.detector.on_dns
        self.files = FileWatcher(config.scan_paths, self.detector.on_file)
        self.detector.on_alert = self._alert_raised
        self._loop: asyncio.AbstractEventLoop | None = None
        self._new_alert = asyncio.Event()
        # One backend set per mode, chosen by each action's own dry_run flag, so an
        # action executed for real is also rolled back for real (and vice versa).
        self.backends = backends or {
            True: build_backends(config, CommandRunner(dry_run=True)),
            False: build_backends(config, CommandRunner(dry_run=False)),
        }
        self.admin_token = admin_token if admin_token is not None else load_admin_token(config)
        self._expiry_failures: set[int] = set()
        self._wake = asyncio.Event()

    # --- request handling ---------------------------------------------------

    async def handle_agent(self, req: dict) -> dict:
        return await self._handle(req, "agent", self.config.agent_token, AGENT_OPS)

    async def handle_admin(self, req: dict) -> dict:
        return await self._handle(req, "admin", self.admin_token, ADMIN_OPS)

    async def _handle(self, req: dict, channel: str, token: str, ops: set[str]) -> dict:
        if not token or not hmac.compare_digest(str(req.get("token", "")), token):
            self.db.append_audit(channel, "auth_failed", None, op=str(req.get("op"))[:50])
            return {"ok": False, "error": "invalid token"}
        op = req.get("op")
        if op not in ops:
            self.db.append_audit(channel, "op_denied", None, op=str(op)[:50])
            return {"ok": False, "error": f"operation {op!r} is not allowed on the {channel} channel"}
        params = req.get("params") or {}
        if not isinstance(params, dict):
            return {"ok": False, "error": "params must be an object"}
        try:
            return {"ok": True, "data": await self._dispatch(channel, op, params)}
        except (ValidationError, TransitionError, BackendError) as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            logger.exception("error handling %s/%s", channel, op)
            return {"ok": False, "error": f"internal error: {e}"}

    async def _dispatch(self, channel: str, op: str, p: dict):
        if op == "ping":
            return {"agent": "ok", "channel": channel, "dry_run": self.config.dry_run,
                    "platform": sys.platform, "allowlist_entries": len(self.allowlist.entries),
                    "dns_monitor": self.dns.status, "indicators_indexed": self.iocs.counts,
                    "auto_detect": self.config.auto_detect, "detect_interval_s": self.config.detect_interval,
                    "last_detection_run": self.detector.last_run, "detection_error": self.detector.last_error,
                    "autonomy": self.autonomy.status(), "file_watcher": self.files.status,
                    "event_alerts": self.detector.event_alerts}
        if op == "scan_connections":
            return await asyncio.to_thread(self.scanner.scan_connections, int(p.get("minutes", 10)))
        if op == "scan_dns":
            return await asyncio.to_thread(self.scanner.scan_dns, int(p.get("minutes", 10)))
        if op == "scan_processes":
            return await asyncio.to_thread(self.scanner.scan_processes)
        if op == "list_alerts":
            if p.get("alert_id"):  # one alert in full: evidence and report included
                alert = self.db.get_alert(int(p["alert_id"]))
                if not alert:
                    raise TransitionError(f"no alert with id {p['alert_id']}")
                alert["actions"] = [summarize(x) for x in (self.db.get_action(i) for i in alert["action_ids"]) if x]
                alert["detail"].pop("actions", None)
                alert["autonomy"] = self.autonomy.status()
                return alert
            since, limit = int(p.get("since_id") or 0), max(1, min(int(p.get("limit", 20)), 200))
            wait = max(0.0, min(float(p.get("wait_s") or 0), 25.0))  # long polling for notifiers
            deadline = asyncio.get_running_loop().time() + wait
            while True:
                self._new_alert.clear()
                alerts = self.db.list_alerts(since, limit)
                left = deadline - asyncio.get_running_loop().time()
                if alerts or not since or left <= 0:
                    break
                try:
                    await asyncio.wait_for(self._new_alert.wait(), timeout=left)
                except asyncio.TimeoutError:
                    alerts = self.db.list_alerts(since, limit)
                    break
            for a in alerts:  # current status of the actions; evidence only via alert_id (keeps lists small)
                a["actions"] = [summarize(x) for x in (self.db.get_action(i) for i in a["action_ids"]) if x]
                a["detail"].pop("actions", None)
                a["has_evidence"] = bool(a["detail"].pop("evidence", None))
                a["report_summary"] = (a.get("report") or "").split("\n")[0][:200] or None
                a.pop("report", None)
            return alerts
        if op == "investigate_host":
            kind, value = str(p.get("kind") or ""), p.get("value")
            fx = self.detector.forensics
            fn = {"process": fx.inspect_process, "file": fx.inspect_file,
                  "ip": fx.ip_activity, "domain": fx.domain_activity}.get(kind)
            if not fn:
                raise ValidationError("kind must be process, file, ip or domain")
            return await asyncio.to_thread(fn, value)
        if op == "related_iocs":
            return await asyncio.to_thread(self.detector.forensics.related_iocs, str(p.get("indicator") or ""))
        if op == "resolve_alert":
            result = await asyncio.to_thread(self.autonomy.resolve, int(p.get("alert_id") or 0),
                                             str(p.get("decision") or ""), str(p.get("justification") or ""))
            self._wake.set()
            return result
        if op == "save_alert_report":
            alert_id, report = int(p.get("alert_id") or 0), str(p.get("report") or "").strip()
            if not self.db.get_alert(alert_id) or not report:
                raise ValidationError("unknown alert or empty report")
            self.db.save_report(alert_id, report, str(p.get("by") or "model")[:40])
            self.db.append_audit("mcp-server", "alert_report", None, alert_id=alert_id)
            return {"alert_id": alert_id, "saved": True}
        if op == "scan_files":
            return await asyncio.to_thread(self.scanner.scan_files, str(p.get("path") or ""))
        if op == "scan_auth_logs":
            return await asyncio.to_thread(self.scanner.scan_auth_logs, int(p.get("minutes", 60)))
        if op == "scan_host":
            return await asyncio.to_thread(self.scanner.scan_host, int(p.get("minutes", 60)))
        if op == "create_action":
            action = await asyncio.to_thread(
                self.manager.create, str(p.get("type")), dict(p.get("params") or {}),
                str(p.get("reason") or ""), "mcp-server",
            )
            out = summarize(action)
            if action.get("duplicate"):
                out["duplicate"] = True
            return out
        if op == "get_action":
            action = self.db.get_action(int(p.get("id", 0)))
            if not action:
                raise TransitionError(f"no action with id {p.get('id')}")
            out = summarize(action)
            if channel == "admin":
                out["audit"] = self.db.audit(action["id"])
            return out
        if op == "list_actions":
            limit = max(1, min(int(p.get("limit", 20)), 200))
            return [summarize(a) for a in self.db.list_actions(str(p.get("status") or ""), limit)]
        if op == "request_rollback":
            action = self.manager.request_rollback(int(p.get("id", 0)), str(p.get("reason") or ""), "mcp-server")
            return summarize(action)
        actor = f"analyst:{str(p.get('actor') or 'unknown')[:64]}"
        if op == "approve":
            action = await asyncio.to_thread(self.manager.approve, int(p.get("id", 0)), actor)
            self._wake.set()
            return summarize(action)
        if op == "reject":
            return summarize(self.manager.reject(int(p.get("id", 0)), actor, str(p.get("reason") or "")))
        if op == "audit":
            action_id = p.get("id")
            return self.db.audit(int(action_id) if action_id is not None else None,
                                 limit=max(1, min(int(p.get("limit", 50)), 500)))
        raise TransitionError(f"unknown operation {op!r}")

    # --- execution loop -----------------------------------------------------

    async def process_approved(self) -> None:
        for action in reversed(self.db.list_actions("approved", limit=50)):
            await self._execute(action)

    async def _execute(self, action: dict) -> None:
        if action["type"] == "rollback":
            await self._execute_rollback(action)
            return
        backend = self.backends[action["dry_run"]][action["type"]]
        try:
            _, clean = await asyncio.to_thread(self.manager.validate, action["type"], action["params"])
        except ValidationError as e:
            self.manager.transition(action["id"], "rejected", "responder",
                                    result={"error": f"re-check before execution failed: {e}"})
            return
        action = {**action, "params": clean}
        try:
            state = await asyncio.to_thread(backend.apply, action)
        except Exception as e:
            logger.error("action %s failed: %s", action["id"], e)
            self.manager.transition(action["id"], "failed", "responder", result={"error": str(e)})
            return
        self.manager.transition(
            action["id"], "executed", "responder", executed_at=now_iso(),
            expires_at=self.manager.expiry_for(action), result={"state": state},
        )
        logger.info("action %s executed%s: %s %s", action["id"],
                    " (dry-run)" if action["dry_run"] else "", action["type"], action["target"])

    async def _execute_rollback(self, action: dict) -> None:
        original = self.db.get_action(action["rollback_of"])
        backend = self.backends[original["dry_run"]][original["type"]]
        state = self._rollback_state(original)
        try:
            result = await asyncio.to_thread(backend.rollback, original, state)
        except Exception as e:
            self.manager.transition(action["id"], "failed", "responder", result={"error": str(e)})
            return
        self.manager.transition(action["id"], "executed", "responder", executed_at=now_iso(),
                                result={"state": result})
        self.manager.transition(original["id"], "rolled_back", "responder",
                                result={"state": state, "rolled_back_by": action["id"]})

    def _alert_raised(self, alert_id: int) -> None:
        """Called from worker threads: wake any notifier waiting in list_alerts."""
        if self._loop:
            self._loop.call_soon_threadsafe(self._new_alert.set)

    def _rollback_state(self, action: dict) -> dict:
        """Saved backend state, plus the IPs another executed block still needs."""
        state = dict((action.get("result") or {}).get("state") or {})
        if action["type"] in ("block_ip", "block_feed_c2"):
            keep: set[str] = set()
            for other in self.db.list_actions("executed", limit=1000):
                if other["id"] != action["id"] and other["type"] in ("block_ip", "block_feed_c2")                         and other["dry_run"] == action["dry_run"]:
                    p = other["params"]
                    keep.update(p.get("ips") or [p.get("ip")])
            state["keep_ips"] = sorted(ip for ip in keep if ip)
        return state

    def prepare_host(self) -> None:
        """Linux: make sure the nftables table exists and re-apply blocks that are
        still valid (the kernel set is empty after a reboot)."""
        firewall = self.backends[False].get("block_ip")
        if not isinstance(firewall, NftablesBackend):
            return
        try:
            firewall.ensure_table()
        except BackendError as e:
            logger.error("nftables not ready: %s", e)
            self.db.append_audit("responder", "nftables_unavailable", None, error=str(e))
            return
        now = datetime.now(timezone.utc)
        restored = 0
        for action in self.db.list_actions("executed", limit=1000):
            if action["dry_run"] or action["type"] not in ("block_ip", "block_feed_c2") or not action["expires_at"]:
                continue
            left = (datetime.fromisoformat(action["expires_at"]) - now).total_seconds()
            if left > 0:
                firewall.reapply(action, int(left))
                restored += 1
        if restored:
            self.db.append_audit("responder", "blocks_restored", None, count=restored)
            logger.info("re-applied %d active block(s) after start", restored)

    async def expire(self) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for action in self.db.due_for_expiry(now):
            if action["id"] in self._expiry_failures:
                continue
            backend = self.backends[action["dry_run"]][action["type"]]
            state = self._rollback_state(action)
            try:
                await asyncio.to_thread(backend.rollback, action, state)
            except Exception as e:
                self._expiry_failures.add(action["id"])
                self.db.append_audit("responder", "expiry_failed", action["id"], error=str(e))
                continue
            self.manager.transition(action["id"], "expired", "responder",
                                    result={"state": state, "expired_at": now})
            logger.info("action %s expired: %s", action["id"], action["target"])

    async def run(self) -> None:
        await asyncio.to_thread(self.prepare_host)
        agent_srv = await serve(self.config.agent_addr, self.handle_agent, unix_mode=0o660,
                                unix_group=self.config.agent_socket_group)
        admin_srv = await serve(self.config.admin_addr, self.handle_admin, unix_mode=0o660,
                                unix_group=self.config.admin_socket_group)
        self.db.append_audit("responder", "started", None, dry_run=self.config.dry_run,
                             agent_addr=self.config.agent_addr, admin_addr=self.config.admin_addr)
        logger.info("threatintel-responder up: agent=%s admin=%s dry_run=%s allowlist=%d entries",
                    self.config.agent_addr, self.config.admin_addr, self.config.dry_run,
                    len(self.allowlist.entries))
        self._collectors = [asyncio.create_task(self.sampler.run()), asyncio.create_task(self.dns.run())]
        self._loop = asyncio.get_running_loop()
        if self.config.auto_detect:
            self._collectors.append(asyncio.create_task(self.detector.run()))
            self._collectors.append(asyncio.create_task(self.detector.run_events()))
            self.files.start(self._loop)
            logger.info("detection: event-driven (DNS live, connections every 2 s, files: %s) "
                        "+ full scan every %ds", self.files.status, self.config.detect_interval)
        async with agent_srv, admin_srv:
            while True:
                try:
                    await self.process_approved()
                    await self.expire()
                except Exception:
                    logger.exception("execution loop error")
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
                self._wake.clear()


def load_admin_token(config: ResponderConfig) -> str:
    """Read the admin token, creating it on first start."""
    path = config.admin_token_file
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)
    path.write_text(token + "\n", encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    logger.warning("created admin token at %s (make sure only administrators can read it)", path)
    return token


def is_privileged() -> bool:
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="mcp-threatintel host agent (privileged)")
    parser.add_argument("--show-allowlist", action="store_true", help="print the effective allowlist and exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(levelname)s  %(message)s")
    config = ResponderConfig.from_env()
    if not config.agent_token:
        sys.exit("AGENT_TOKEN is not set (see .env.example / scripts/windows/setup.ps1)")
    if not config.dry_run and not is_privileged():
        sys.exit("RESPONDER_DRY_RUN=false needs an elevated terminal (Administrator / root)")
    agent = HostAgent(config)
    if args.show_allowlist:
        for e in agent.allowlist.entries:
            print(f"{e['type']:8} {e['value']:22} {e['comment']}")
        return
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("stopped")


if __name__ == "__main__":
    main()
