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
        """Still being handled: not resolved and at least one of its actions still pending/approved."""
        if alert.get("resolution") and not str(alert["resolution"]).startswith("recommended_"):
            return False
        statuses = [a["status"] for a in (self.db.get_action(i) for i in alert["action_ids"]) if a]
        return not statuses or any(s in ("pending", "approved") for s in statuses)

    def _handle(self, finding: Finding) -> int | None:
        prev = self.db.latest_alert(finding.key)
        recurrence_of = None
        if prev:
            last = datetime.fromisoformat(prev.get("last_seen") or prev["ts"])
            recent = datetime.now(timezone.utc) - last < timedelta(minutes=self.aggregate_minutes)
            if recent and self._is_open(prev):
                self.db.bump_alert(prev["id"])   # same open incident: count it, no duplicate alert
                return None
            # The threat came back after being handled (or after a quiet period): alert again, louder.
            recurrence_of = prev["id"]
            finding.severity = {"low": "medium", "medium": "high"}.get(finding.severity, "critical")
            finding.title = f"RECURRING (after alert #{prev['id']}, {prev.get('resolution') or 'open'}): {finding.title}"
            finding.detail = {**finding.detail, "recurrence_of": prev["id"],
                              "previous_resolution": prev.get("resolution"),
                              "previous_occurrences": prev.get("occurrences")}
        actions = [self._create(tool, args) for tool, args in finding.plan]
        ids = [a["id"] for a in actions if a.get("id")]
        detail = {**finding.detail, "actions": [
            {k: a.get(k) for k in ("id", "type", "target", "status", "duplicate")}
            | ({"error": (a.get("result") or {}).get("error") or a.get("error")} if a.get("status") == "rejected" else {})
            for a in actions
        ]}
        if self.forensics:
            detail["evidence"] = collect_evidence(self.forensics, finding.kind, finding.detail)
        alert_id = self.db.insert_alert(key=finding.key, kind=finding.kind, severity=finding.severity,
                                        title=finding.title, detail=detail, action_ids=ids,
                                        recurrence_of=recurrence_of)
        self.db.append_audit("auto-detect", "alert", None, alert_id=alert_id, severity=finding.severity,
                             title=finding.title, actions=ids)
        logger.warning("ALERT #%d [%s] %s -> pending actions %s", alert_id, finding.severity, finding.title, ids)
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
