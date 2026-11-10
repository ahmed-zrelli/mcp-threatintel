"""threatintel-watch: the analyst PC's notifier.

Detection runs on the server, all the time, inside the host agent (AlertEngine):
it scans, records alerts and creates the pending actions even when this PC is
off. This program only:
  1. polls the server's alerts (MCP tool list_alerts) every --interval seconds;
  2. shows a Windows notification for each new one, with the approve commands
     (alerts raised while the PC was off are shown at the next start);
  3. if the local model (llama-server) is running, lets it investigate the
     alert and notifies its short analysis.

It starts by itself at Windows logon (scripts/windows/install-watch-autostart.ps1)
and then runs hidden; its log goes to %LOCALAPPDATA%\\threatintel\\watch.log.
Nothing is ever approved here: approval stays `threatintel-approve` on the server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastmcp import Client

from .llm import investigate
from .notify import notify

STATE_DIR = Path(os.getenv("LOCALAPPDATA") or Path.home()) / "threatintel"
MAX_TOASTS_PER_POLL = 3
_log_file = None


def out(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    if sys.stdout is not None:
        try:
            print(line, flush=True)
        except (OSError, ValueError):
            pass
    if _log_file:
        try:
            with open(_log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def _text(result) -> object:
    try:
        return json.loads(result.content[0].text)
    except (ValueError, IndexError, AttributeError):
        return {"error": "unreadable tool result"}


def approve_hint(actions: list[dict]) -> str:
    ids = [str(a["id"]) for a in actions if a.get("status") == "pending" and a.get("id")]
    if not ids:
        return "No action to approve."
    return "Approve on the server: " + " ; ".join(f"threatintel-approve approve {i}" for i in ids)


def describe(action: dict) -> str:
    return f"#{action.get('id')} {action.get('type')} {str(action.get('target'))[:50]}: {action.get('status')}"


class LastSeen:
    """Id of the last alert shown, so restarts do not repeat old notifications."""

    def __init__(self, path: Path):
        self.path = path

    def get(self) -> int | None:
        try:
            return int(self.path.read_text().strip())
        except (OSError, ValueError):
            return None

    def set(self, value: int) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(str(value))
        except OSError:
            pass


async def llm_available(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=3) as http:
            return (await http.get(f"{url.rstrip('/')}/health")).status_code == 200
    except httpx.HTTPError:
        return False


#: Incident events that deserve a notification. "grew" (another finding of an attack you were already
#: told about) is logged and investigated, but does not notify again: one notification per attack.
NOTIFY_EVENTS = {None, "new", "reopened", "escalated", "persisting"}
EVENT_LABEL = {"new": "NEW ATTACK", "reopened": "ATTACK BACK", "escalated": "ESCALATED",
               "persisting": "STILL ACTIVE", "grew": "same attack"}


def announce(alert: dict, toast: bool) -> None:
    """Instant part: the notification as soon as the server raised the alert."""
    actions = alert.get("actions") or []
    sev = alert.get("severity", "?").upper()
    event = alert.get("incident_event")
    inc = f"incident #{alert['incident_id']} " if alert.get("incident_id") else ""
    label = EVENT_LABEL.get(event, "")
    if toast and event in NOTIFY_EVENTS:
        ioc = (alert.get("detail") or {}).get("ioc") or ""
        notify(f"ThreatIntel {sev} {label} {inc}- {alert['title']}", [ioc, approve_hint(actions)])
    out(f"ALERT #{alert['id']} ({sev}) {inc}{label}: {alert['title']}")
    for a in actions:
        out(f"    - {describe(a)}")
    out(f"    {approve_hint(actions)}")


async def show(mcp, alert: dict, args, toast: bool) -> None:
    announce(alert, toast)
    await investigate_alert(mcp, alert, args, toast)


async def investigate_alert(mcp, alert: dict, args, toast: bool) -> None:
    """Slow part (model): evidence, report, resolution. Runs in the background."""
    actions = alert.get("actions") or []
    full = _text(await mcp.call_tool("list_alerts", {"alert_id": alert["id"]}))
    if not isinstance(full, dict) or full.get("error"):
        full = alert
    if full.get("report"):
        return  # already investigated (e.g. by another notifier)
    if args.no_ai or not await llm_available(args.llm_url):
        report, by = basic_report(full, actions), "auto"
    else:
        brief = {"alert": {k: full.get(k) for k in ("id", "ts", "kind", "severity", "title")},
                 "autonomous_mode": full.get("autonomy"),
                 "incident": full.get("incident"),
                 "detail": {k: v for k, v in (full.get("detail") or {}).items() if k != "evidence"},
                 "actions_already_created": [{k: a.get(k) for k in ("id", "type", "target", "status")}
                                             for a in actions],
                 "evidence": (full.get("detail") or {}).get("evidence")}
        text = json.dumps(brief, default=str)
        if len(text) > 7000:  # keep room in an 8k-token context
            text = text[:7000] + " ...(truncated)"
        out(f"    AI investigating alert #{alert['id']} (Qwen)...")
        try:
            report, more = await investigate(mcp, args.llm_url, text, timeout=args.llm_timeout)
            by = "qwen"
        except Exception as e:
            out(f"    AI unavailable ({e}); saving a basic report")
            report, more, by = basic_report(full, actions), [], "auto"
        new = [a for a in more if a.get("id") not in {x.get("id") for x in actions}]
        for a in new:
            out(f"    + AI added {describe(a)}")
        actions = actions + new
    try:
        await mcp.call_tool("save_alert_report", {"alert_id": alert["id"], "report": report})
    except Exception as e:
        out(f"    could not save the report on the server ({e})")
    out(f"    REPORT ({by}):\n      " + report.replace("\n", "\n      "))
    after = _text(await mcp.call_tool("list_alerts", {"alert_id": alert["id"]}))
    if isinstance(after, dict) and after.get("resolution"):
        res, acts = after["resolution"], after.get("actions") or []
        done = [a for a in acts if a.get("status") in ("approved", "executed")]
        still = [a for a in acts if a.get("status") == "pending"]
        out(f"    RESOLUTION by {after.get('resolution_by')}: {res} - {after.get('resolution_note')}")
        if toast and not res.startswith("recommended_") and alert.get("incident_event") in NOTIFY_EVENTS:
            title = {"executed": "Qwen resolved", "partially_executed": "Qwen partly resolved",
                     "dismissed": "Qwen dismissed", "escalated": "Qwen escalated to you"}.get(res, res)
            lines = [", ".join(f"{a['type']} {str(a['target'])[:30]}" for a in done)
                     or (after.get("resolution_note") or "")[:150]]
            lines.append(approve_hint(still) if still else "Undo anytime: ask Qwen to roll back the action.")
            notify(f"ThreatIntel - {title} alert #{alert['id']}", lines)
            return
    if toast and alert.get("incident_event") in NOTIFY_EVENTS:
        summary = next((line.split(":", 1)[1].strip() for line in report.splitlines()
                        if line.upper().startswith("SUMMARY")), report[:180])
        notify(f"ThreatIntel - report for alert #{alert['id']}", [summary[:200], approve_hint(actions)])


def basic_report(alert: dict, actions: list[dict]) -> str:
    """Report built from the evidence alone, when the model is not running."""
    detail = alert.get("detail") or {}
    ev = detail.get("evidence") or {}
    proc = ev.get("process") or {}
    camp = ev.get("campaign") or {}
    scope = []
    if proc.get("pid"):
        parents = " <- ".join(f"{p['name']}({p['pid']})" for p in proc.get("parent_chain", [])[:3])
        scope.append(f"process {proc.get('name')} PID {proc.get('pid')} user {proc.get('user')}"
                     + (f", started {proc.get('started')}" if proc.get("started") else "")
                     + (f", parents: {parents}" if parents else ""))
    if (ev.get("file") or {}).get("path"):
        f = ev["file"]
        scope.append(f"file {f['path']} ({f.get('type')}, owner {f.get('owner')}, modified {f.get('modified')})")
    present = camp.get("related_present_on_host") or []
    if present:
        scope.append("related IOCs also present: " + ", ".join(r["value"] for r in present[:5]))
    threat = ", ".join([p["name"] for p in camp.get("pulses", [])[:2]] + camp.get("malware_families", [])[:2])
    lines = [
        f"SUMMARY: {alert.get('title')}",
        f"SEVERITY: {alert.get('severity')} - rule-based (model not running)",
        f"WHAT HAPPENED: detected at {alert.get('ts')}; indicator listed by {detail.get('ioc') or 'threat feeds'}.",
        "SCOPE: " + ("; ".join(scope) or "see evidence on the server: threatintel-approve alert " + str(alert.get("id"))),
        "THREAT: " + (threat or detail.get("ioc") or "unknown"),
        "RECOMMENDED ACTIONS: " + approve_hint(actions),
        "CONFIDENCE: medium (automatic report)",
    ]
    return "\n".join(lines)


async def poll(mcp, last: LastSeen, args, jobs: asyncio.Queue | None = None) -> None:
    """One long poll: the server answers as soon as a new alert exists (or after wait_s)."""
    since = last.get()
    params = {"since_id": since or 0, "limit": 50}
    if since is not None:
        params["wait_s"] = getattr(args, "wait", 25)
    alerts = _text(await mcp.call_tool("list_alerts", params))
    if isinstance(alerts, dict):
        raise RuntimeError(alerts.get("error", "list_alerts failed"))
    if not alerts:
        if since is None:
            last.set(0)
        return
    if since is None:
        # First run on this PC: summarise what is already there instead of replaying it.
        worst = sorted(alerts, key=lambda a: ["critical", "high", "medium", "low"].index(a.get("severity", "low")))[0]
        notify(f"ThreatIntel - {len(alerts)} alert(s) on the server", [f"Latest: {alerts[-1]['title']}",
                                                                       f"Most severe: {worst['title']}"])
        out(f"{len(alerts)} existing alert(s) on the server; showing new ones from now on")
        last.set(alerts[-1]["id"])
        return
    for i, alert in enumerate(alerts):
        toast = i < MAX_TOASTS_PER_POLL
        announce(alert, toast)
        last.set(alert["id"])
        if jobs is not None:
            jobs.put_nowait((alert, toast))
        else:
            await investigate_alert(mcp, alert, args, toast)
    if len(alerts) > MAX_TOASTS_PER_POLL:
        notify(f"ThreatIntel - {len(alerts)} new alerts", ["More alerts than notifications shown.",
                                                          "On the server: threatintel-approve alerts"])


async def run(args) -> None:
    last = LastSeen(STATE_DIR / "watch_last_alert.txt")
    token = os.getenv("MCP_THREATINTEL_AUTH_TOKEN") or None
    out(f"threatintel-watch: server {args.mcp_url}, alerts pushed by long polling (<= {args.wait}s wait), "
        f"AI {'off' if args.no_ai else args.llm_url}")
    jobs: asyncio.Queue = asyncio.Queue()
    warned = False
    while True:
        try:
            async with Client(args.mcp_url, auth=token) as mcp:
                out("connected to the MCP server")
                warned = False

                async def investigator():
                    while True:
                        alert, toast = await jobs.get()
                        try:
                            await investigate_alert(mcp, alert, args, toast)
                        except Exception as e:
                            out(f"    investigation of alert #{alert.get('id')} failed: {e}")

                worker = asyncio.create_task(investigator())
                try:
                    while True:
                        await poll(mcp, last, args, None if args.once else jobs)
                        if args.once:
                            return
                finally:
                    worker.cancel()
        except Exception as e:
            if not warned:
                out(f"MCP server unreachable ({e}); retrying every {args.interval}s")
                warned = True
            if args.once:
                return
            await asyncio.sleep(args.interval)


def main(argv: list[str] | None = None) -> None:
    global _log_file
    load_dotenv()
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    p = argparse.ArgumentParser(prog="threatintel-watch", description="Alert notifier for mcp-threatintel")
    p.add_argument("--mcp-url", default=os.getenv("WATCH_MCP_URL", "http://127.0.0.1:3707/mcp"))
    p.add_argument("--llm-url", default=os.getenv("WATCH_LLM_URL", "http://127.0.0.1:8080"))
    p.add_argument("--interval", type=int, default=int(os.getenv("WATCH_INTERVAL", "15")),
                   help="seconds between reconnection attempts when the server is unreachable")
    p.add_argument("--wait", type=float, default=25, help="long-poll wait on the server (max 25 s)")
    p.add_argument("--llm-timeout", type=float, default=300)
    p.add_argument("--no-ai", action="store_true", help="notifications only, no model analysis")
    p.add_argument("--once", action="store_true", help="one poll, then exit")
    p.add_argument("--log-file", default=str(STATE_DIR / "watch.log"))
    args = p.parse_args(argv)
    _log_file = args.log_file
    Path(_log_file).parent.mkdir(parents=True, exist_ok=True)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        out("stopped")


if __name__ == "__main__":
    main()
