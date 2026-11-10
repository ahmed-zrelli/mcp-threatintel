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


ACTION_PARAM = {  # MCP tool argument -> action parameter
    "block_ip": "ip", "kill_process": "pid", "quarantine_file": "path", "sinkhole_domain": "domain",
}


class AlertEngine:
    def __init__(self, db: ResponderDB, manager: ActionManager, scanner: HostScanner, *,
                 interval_s: int = 30, window_min: int = 10, aggregate_minutes: int = 10):
        self.db = db
        self.manager = manager
        self.scanner = scanner
        self.interval_s = interval_s
        self.window_min = window_min
        self.aggregate_minutes = aggregate_minutes
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
        try:
            return self.manager.create(tool, {key: args[key]}, args.get("reason", ""), "auto-detect")
        except ValidationError as e:
            return {"id": None, "type": tool, "status": "rejected", "error": str(e)}

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

        # 1. Exactly the same finding, still being handled: count it, no new alert.
        prev = self.db.latest_alert(finding.key)
        if prev and self._is_open(prev):
            self.db.bump_alert(prev["id"])
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
        ids = [a["id"] for a in actions if a.get("id")]

        # 3. Malware still hitting a C2 that is already blocked: contained, but the cause is still there.
        containing = [a for a in actions if a.get("type") != "kill_process"]
        contained = bool(containing) and all(a.get("duplicate") and a.get("status") == "executed"
                                             for a in containing)
        if contained and incident is not None:
            self.db.update_incident(incident["id"], blocked_attempt=True)
            if incident["persisting_notified"]:
                if prev:
                    self.db.bump_alert(prev["id"])
                return None
            event = "persisting"
            finding.title = (f"CONTAINED but persisting: {finding.title} - attempts are blocked, "
                             f"the process behind them is still running")
            self.db.update_incident(incident["id"], persisting_notified=True)

        detail = {**finding.detail, "actions": [
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
                             incident_event=event, severity=finding.severity, title=finding.title, actions=ids)
        logger.warning("ALERT #%d incident #%d (%s) [%s] %s -> actions %s", alert_id, incident_id, event,
                       finding.severity, finding.title, ids)
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
