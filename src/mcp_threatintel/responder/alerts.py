"""AlertEngine: always-on detection inside the host agent.

Event-driven: the collectors call on_connection / on_dns / on_file the moment
they see something new; a match against the indicator index raises the alert
within about a second. Every ``interval_s`` seconds a full host scan (every
poller indicator, see scanner.py) also runs as a safety net (processes, SSH
logs, anything an event missed). For each NEW finding:
  * creates the suggested response actions as PENDING (requested_by
    "auto-detect"; validation, allowlist and duplicate checks apply, and
    nothing is ever approved here);
  * records an alert in responder.db.

It runs as part of the systemd service, so detection works 24/7 even when
the analyst PC is off; the PC notifier (threatintel-watch) only displays the
alerts and asks the local model for an analysis.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
from datetime import datetime, timedelta, timezone

from .actions import ActionManager
from .findings import Finding, extract_findings
from .forensics import Forensics, collect_evidence
from .scanner import HostScanner
from .store import ResponderDB
from .actions import TransitionError
from .validators import ValidationError

logger = logging.getLogger("threatintel.responder.alerts")

CORRELATE_MINUTES = 60   # findings sharing a key with an open incident this recent join it
REOPEN_HOURS = 24        # a resolved incident whose indicators come back within this time is reopened
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def finding_keys(finding: Finding) -> set[str]:
    """Correlation keys: indicators, processes and campaigns a finding touches."""
    d, keys = finding.detail, set()

    def add(prefix, value):
        if value not in (None, "", []):
            keys.add(f"{prefix}:{str(value).lower()}")

    add("ip", d.get("remote_ip") or (d.get("ip") if finding.kind.startswith("ssh_") else None))
    add("ip", d.get("src_ip"))
    add("user", d.get("user") if finding.kind.startswith(("account_", "ssh_")) else None)
    add("port", d.get("port") if finding.kind == "new_listener" else None)
    add("pid", d.get("pid"))
    add("domain", d.get("domain"))
    for ip in d.get("answers") or []:
        add("ip", ip)
    add("hash", d.get("sha256"))
    add("path", d.get("path"))
    for ind in d.get("indicators") or []:
        kind = {"url": "url"}.get(ind.get("type"), ind.get("type"))
        add(kind, ind.get("value"))
        for m in ind.get("ioc_matches") or []:
            add("family", m.get("malware_family"))
            add("pulse", m.get("pulse"))
    for m in d.get("ioc_matches") or []:
        add("family", m.get("malware_family"))
        add("pulse", m.get("pulse"))
    return keys


def _still_running(detail: dict) -> bool:
    """The connection is live now and its process (when known) still exists."""
    if not detail.get("active", True):
        return False
    pid = detail.get("pid")
    if pid:
        import psutil
        try:
            return psutil.pid_exists(int(pid))
        except (ValueError, TypeError):
            return True
    return True


#: Detections the rules handle alone: threat-intel matches and unambiguous attack behavior.
RULE_KINDS = {"c2_connection", "malicious_dns", "malicious_file", "malicious_process", "ssh_bruteforce",
              "ssh_login_from_malicious_ip", "ssh_attempt_from_malicious_ip", "port_scan", "reverse_shell"}
#: Refusals that mean "intentionally not acted on" or "already gone", not "the rules could not cope".
HANDLED_REFUSALS = ("allowlisted", "protected", "refusing to", "no process with pid", "does not exist",
                    "no longer exists", "already exited")


ACTION_PARAM = {  # MCP tool argument -> action parameter
    "block_ip": "ip", "kill_process": "pid", "quarantine_file": "path", "sinkhole_domain": "domain",
    "lock_user": "user",
}


class AlertEngine:
    def __init__(self, db: ResponderDB, manager: ActionManager, scanner: HostScanner, *,
                 interval_s: int = 30, window_min: int = 10, aggregate_minutes: int = 10,
                 rules_execute: bool = False):
        self.db = db
        self.manager = manager
        self.scanner = scanner
        self.interval_s = interval_s
        self.window_min = window_min
        self.aggregate_minutes = aggregate_minutes
        self.rules_execute = rules_execute
        # Evidence needs the real scanner (IOC index + collectors); test doubles skip it.
        self.forensics = Forensics(scanner, db) if hasattr(scanner, "iocs") else None
        self.last_run: str | None = None
        self.last_error: str | None = None
        self.events: queue.Queue = queue.Queue(maxsize=1000)
        self.on_alert = None            # callback(alert_id), e.g. wakes long-polling notifiers
        self._lock = threading.Lock()   # periodic scan and events never alert the same thing twice
        self.event_alerts = 0

    # --- event-driven detection (called from collector threads / the event loop) ---

    def _submit(self, item) -> None:
        try:
            self.events.put_nowait(item)
        except queue.Full:
            logger.warning("event queue full; the periodic scan will catch up")

    def on_connection(self, rec: dict) -> None:
        matches = self.scanner.iocs.lookup("ip", rec.get("remote_ip") or "")
        if matches:
            self._submit(("report", {"connections": {"malicious": [{**rec, "active": True, "ioc_matches": matches}]}}))

    def on_dns(self, name: str, rec: dict) -> None:
        matches = self.scanner.iocs.lookup_domain(name)
        if matches:
            self._submit(("report", {"dns": {"malicious": [{"domain": name, "lookups": rec.get("count", 1),
                                                            "answers": rec.get("answers", []),
                                                            "ioc_matches": matches}]}}))

    def on_behavior(self, section: str, rec: dict) -> None:
        self._submit(("report", {"behavior": {section: [rec]}}))

    def on_file(self, path: str) -> None:
        self._submit(("file", path))  # hashing happens in the worker, not in the event loop

    def process_event(self, item) -> list[int]:
        kind, payload = item
        if kind == "file":
            hit = self.scanner.check_file(payload)
            if not hit:
                return []
            payload = {"files": {"malicious": [hit]}}
        ids = [a for a in (self.handle(f) for f in extract_findings(payload)) if a]
        self.event_alerts += len(ids)
        return ids

    async def run_events(self) -> None:
        while True:
            item = await asyncio.to_thread(self.events.get)
            try:
                await asyncio.to_thread(self.process_event, item)
            except Exception:
                logger.exception("event handling error")

    def _create(self, tool: str, args: dict) -> dict:
        key = ACTION_PARAM[tool]
        params = {key: args[key]} | ({"behavior": True} if args.get("behavior") else {})
        try:
            return self.manager.create(tool, params, args.get("reason", ""), "auto-detect")
        except ValidationError as e:
            return {"id": None, "type": tool, "status": "rejected", "error": str(e)}

    def _apply_rules(self, finding: Finding, actions: list[dict]) -> tuple[str, list[dict]]:
        """Rules act first. Returns (route, actions): "rules" when they handled it, "ai" otherwise."""
        if not self.rules_execute or finding.kind not in RULE_KINDS:
            return "ai", actions
        unable, out = False, []
        for a in actions:
            if a.get("status") == "pending" and a.get("id") and not a.get("duplicate"):
                try:
                    a = self.manager.approve(a["id"], "rules")
                except TransitionError:
                    unable = True
            if a.get("status") == "rejected":
                err = str((a.get("result") or {}).get("error") or a.get("error") or "").lower()
                if not any(k in err for k in HANDLED_REFUSALS):
                    unable = True
            out.append(a)
        if not actions and not finding.detail.get("allowlisted"):
            unable = True
        return ("ai" if unable else "rules"), out

    def handle(self, finding: Finding) -> int | None:
        with self._lock:
            alert_id = self._handle(finding)
        if alert_id and self.on_alert:
            try:
                self.on_alert(alert_id)
            except Exception:
                logger.exception("on_alert callback failed")
        return alert_id

    def _is_open(self, alert: dict) -> bool:
        """Still being handled: not resolved, and nothing executed/expired/rolled back yet.
        (Actions refused by validation or rejected by a human leave it open: it is counted, not re-alerted.)"""
        if alert.get("resolution") and not str(alert["resolution"]).startswith("recommended_"):
            return False
        statuses = [a["status"] for a in (self.db.get_action(i) for i in alert["action_ids"]) if a]
        return not any(s in ("executed", "expired", "rolled_back") for s in statuses)

    def _incident_open(self, incident: dict) -> bool:
        return any(self._is_open(a) for a in self.db.incident_alerts(incident["id"]))

    def _correlate(self, keys: set[str]) -> dict | None:
        """Most recent incident sharing a key: open ones within CORRELATE_MINUTES, resolved ones
        within REOPEN_HOURS (so an attack that comes back reopens its own incident)."""
        now = datetime.now(timezone.utc)
        horizon = (now - timedelta(hours=REOPEN_HOURS)).isoformat(timespec="seconds")
        for inc in self.db.recent_incidents(horizon):
            if not keys & set(inc["keys"]):
                continue
            age = now - datetime.fromisoformat(inc["last_seen"])
            if age <= timedelta(minutes=CORRELATE_MINUTES) or not self._incident_open(inc):
                return inc
        return None

    def _handle(self, finding: Finding) -> int | None:
        keys = finding_keys(finding)
        prev = self.db.latest_alert(finding.key)

        # 0. An observation that is not newer than the last detection of the same finding is the same
        #    event seen again by a later scan (scans remember recent activity): ignore it entirely.
        observed = finding.detail.get("observed_at")
        if prev and observed:
            last = datetime.fromisoformat(prev.get("last_seen") or prev["ts"]).timestamp()
            if float(observed) <= last:
                return None

        # 1. Exactly the same finding, still being handled: count it, no new alert.
        if prev and self._is_open(prev):
            self.db.bump_alert(prev["id"])
            # Still happening and its actions are still pending (raised before the rules could act, or
            # left pending): the rules act now on a clear-cut attack.
            pending = [a for a in (self.db.get_action(i) for i in prev["action_ids"]) if a and a["status"] == "pending"]
            if pending and not prev.get("resolution") and self.rules_execute and finding.kind in RULE_KINDS:
                route, _ = self._apply_rules(finding, pending)
                self.db.set_alert_route(prev["id"], route)
                self.db.append_audit("rules", "acted_on_open_alert", None, alert_id=prev["id"], route=route,
                                     actions=[a["id"] for a in pending])
            if prev.get("incident_id"):
                self.db.update_incident(prev["incident_id"])
            return None

        # 2. Which attack does it belong to?
        incident = self._correlate(keys)
        recurrence_of = prev["id"] if prev else None
        if incident is None:
            event = "new"
        elif self._incident_open(incident):
            event = "grew"
            if SEVERITY_RANK[finding.severity] < SEVERITY_RANK[incident["severity"]]:
                event = "escalated"
        else:
            event = "reopened"   # the attack came back after it was handled
            finding.severity = {"low": "medium", "medium": "high"}.get(finding.severity, "critical")
            finding.title = f"RECURRING (incident #{incident['id']} reopened): {finding.title}"
            finding.detail = {**finding.detail, "recurrence_of": recurrence_of}

        actions = [self._create(tool, args) for tool, args in finding.plan]
        route, actions = self._apply_rules(finding, actions)
        ids = [a["id"] for a in actions if a.get("id")]

        # 3. Malware still hitting a C2 that is already blocked: contained, but the cause is still there.
        containing = [a for a in actions if a.get("type") != "kill_process"]
        contained = bool(containing) and all(a.get("duplicate") and a.get("status") == "executed"
                                             for a in containing)
        # Only a connection means malware is still retrying; a sinkholed name never reaches DNS again.
        # And only a LIVE connection from a process that still exists: a sampled connection seen just before
        # the kill is history, not persistence.
        if contained and finding.kind == "c2_connection" and not _still_running(finding.detail):
            if prev:
                self.db.bump_alert(prev["id"])
            return None
        if contained and incident is not None and finding.kind == "c2_connection":
            self.db.update_incident(incident["id"], blocked_attempt=True)
            if incident["persisting_notified"]:
                if prev:
                    self.db.bump_alert(prev["id"])
                return None
            event = "persisting"
            finding.title = (f"CONTAINED but persisting: {finding.title} - attempts are blocked, "
                             f"the process behind them is still running")
            self.db.update_incident(incident["id"], persisting_notified=True)
            route = "ai"   # blocked, but the cause is still running: the AI looks deeper

        detail = {**finding.detail, "route": route, "actions": [
            {k: a.get(k) for k in ("id", "type", "target", "status", "duplicate")}
            | ({"error": (a.get("result") or {}).get("error") or a.get("error")} if a.get("status") == "rejected" else {})
            for a in actions
        ]}
        if self.forensics:
            detail["evidence"] = collect_evidence(self.forensics, finding.kind, finding.detail)

        if incident is None:
            incident_id = self.db.insert_incident(severity=finding.severity, title=finding.title, keys=keys)
        else:
            incident_id = incident["id"]
        worst = min(finding.severity, incident["severity"] if incident else finding.severity,
                    key=lambda s: SEVERITY_RANK[s])
        self.db.update_incident(incident_id, keys=keys, severity=worst, add_alert=True,
                                reopened=event == "reopened")

        alert_id = self.db.insert_alert(key=finding.key, kind=finding.kind, severity=finding.severity,
                                        title=finding.title, detail=detail, action_ids=ids,
                                        recurrence_of=recurrence_of if event == "reopened" else None,
                                        incident_id=incident_id, incident_event=event)
        self.db.append_audit("auto-detect", "alert", None, alert_id=alert_id, incident_id=incident_id,
                             incident_event=event, severity=finding.severity, title=finding.title, actions=ids,
                             route=route)
        logger.warning("ALERT #%d incident #%d (%s) [%s] %s -> actions %s, handled by %s", alert_id, incident_id,
                       event, finding.severity, finding.title, ids, route)
        return alert_id

    def tick(self) -> list[int]:
        report = self.scanner.scan_host(self.window_min)
        self.last_run = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return [a for a in (self.handle(f) for f in extract_findings(report)) if a]

    async def run(self) -> None:
        await asyncio.sleep(5)  # let the collectors gather a first sample
        while True:
            try:
                await asyncio.to_thread(self.tick)
                self.last_error = None
            except Exception as e:
                self.last_error = str(e)
                logger.exception("detection loop error")
            await asyncio.sleep(self.interval_s)
