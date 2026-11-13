"""ActionManager: creation, validation and the action state machine (spec §9).

    (create) --valid--> pending --approve--> approved --run ok--> executed --> rolled_back | expired
        \\--refused--> rejected    \\--reject--> rejected    \\--fail--> failed
                                  approved --re-check fails--> rejected

Only the admin channel can call approve()/reject(). The agent channel can only
create actions and request rollbacks, which themselves start as pending.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .behavior import PERSISTENCE_DIRS

from .config import ResponderConfig
from .iocs import IocIndex
from .store import ResponderDB, now_iso
from .validators import (
    Allowlist,
    ValidationError,
    validate_domain,
    validate_file,
    validate_ip,
    validate_pid,
    validate_user,
)

logger = logging.getLogger("threatintel.responder.actions")

TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected"},
    "approved": {"executed", "failed", "rejected"},
    "executed": {"rolled_back", "expired"},
    "rejected": set(),
    "failed": set(),
    "rolled_back": set(),
    "expired": set(),
}

ACTION_TYPES = {"block_ip", "sinkhole_domain", "quarantine_file", "kill_process", "block_feed_c2", "lock_user",
                "rollback"}
REVERSIBLE = {"block_ip", "sinkhole_domain", "quarantine_file", "block_feed_c2", "lock_user"}
EXPIRING = {"block_ip", "block_feed_c2"}
FEEDS_FOR_C2 = {"feodo", "threatfox"}


class TransitionError(RuntimeError):
    pass


class ActionManager:
    def __init__(self, db: ResponderDB, allowlist: Allowlist, iocs: IocIndex, config: ResponderConfig):
        self.db = db
        self.allowlist = allowlist
        self.iocs = iocs
        self.config = config

    # --- validation ---------------------------------------------------------

    def validate(self, type_: str, params: dict) -> tuple[str, dict]:
        """Return (target, normalised params) or raise ValidationError."""
        if type_ == "block_ip":
            raw = str(params.get("ip", "")).strip()
            # A LAN address may be blocked when it is a lab IOC, or when the agent itself saw it attack
            # (port scan, reverse shell): "behavior" is only kept on actions created by the detection.
            behavior = bool(params.get("behavior"))
            ip = validate_ip(raw, allow_private=behavior or self.iocs.is_local_ioc(raw))
            self._deny(self.allowlist.check_ip(ip))
            ttl = self._ttl(params.get("ttl"))
            return ip, {"ip": ip, "ttl": ttl} | ({"behavior": True} if behavior else {})
        if type_ == "sinkhole_domain":
            domain = validate_domain(params.get("domain", ""))
            self._deny(self.allowlist.check_domain(domain))
            return domain, {"domain": domain}
        if type_ == "quarantine_file":
            # New persistence files (cron, systemd units, ld.so.preload...) found by the integrity
            # monitor may be quarantined too; any other path must be inside SCAN_PATHS.
            behavior = bool(params.get("behavior"))
            roots = self.config.scan_paths + ([Path(p) for p in PERSISTENCE_DIRS] if behavior else [])
            path = validate_file(params.get("path", ""), roots)
            return str(path), {"path": str(path)} | ({"behavior": True} if behavior else {})
        if type_ == "lock_user":
            user = validate_user(params.get("user", ""), protected=self.config.protected_users)
            return user, {"user": user}
        if type_ == "kill_process":
            info = validate_pid(params.get("pid"), protected=self.allowlist.protected_processes)
            self._deny(self.allowlist.check_process(info["name"]))
            if "create_time" in params and abs(float(params["create_time"]) - info["create_time"]) > 0.01:
                raise ValidationError(f"PID {info['pid']} was reused by another process since the action was created")
            return f"{info['name']} (PID {info['pid']})", info
        if type_ == "block_feed_c2":
            feed = str(params.get("feed", "feodo")).strip().lower()
            if feed not in FEEDS_FOR_C2:
                raise ValidationError(f"feed must be one of {sorted(FEEDS_FOR_C2)}")
            ips = params.get("ips")
            if ips is None:  # snapshot the feed at creation time; re-checks reuse it
                ips = self.iocs.feed_ips(feed)
            kept = []
            for ip in ips:
                try:
                    ip = validate_ip(ip)
                except ValidationError:
                    continue
                if not self.allowlist.check_ip(ip):
                    kept.append(ip)
            if not kept:
                raise ValidationError(f"no blockable IPs in feed {feed!r} (has the poller run?)")
            return f"{feed} ({len(kept)} IPs)", {"feed": feed, "ips": kept, "ttl": self._ttl(params.get("ttl"))}
        raise ValidationError(f"unknown action type {type_!r}")

    def _ttl(self, value) -> float:
        ttl = float(value) if value not in (None, "") else self.config.block_ttl
        if ttl <= 0 or ttl > 24 * 30:
            raise ValidationError("ttl must be > 0 and at most 720")
        return ttl

    @staticmethod
    def _deny(reason: str | None) -> None:
        if reason:
            raise ValidationError(reason)

    # --- lifecycle ----------------------------------------------------------

    def create(self, type_: str, params: dict, reason: str, requested_by: str) -> dict:
        if type_ not in ACTION_TYPES - {"rollback"}:
            raise ValidationError(f"unknown action type {type_!r}")
        if requested_by != "auto-detect":
            params = {k: v for k, v in params.items() if k != "behavior"}
        try:
            target, clean = self.validate(type_, params)
            status, result = "pending", None
            existing = self._find_active(type_, target)
            if existing:
                # Same request again (watcher + model, or a repeated alert): reuse it.
                self.db.append_audit(requested_by, "duplicate_request", existing["id"], type=type_, target=target)
                return {**existing, "duplicate": True}
        except ValidationError as e:
            target = str(params.get("ip") or params.get("domain") or params.get("path")
                         or params.get("pid") or params.get("feed") or params.get("user") or "?")
            clean, status, result = params, "rejected", {"error": str(e)}
        action_id = self.db.insert_action(
            type=type_, target=target, params=clean, reason=reason[:500], requested_by=requested_by,
            status=status, dry_run=self.config.dry_run, result=result,
        )
        self.db.append_audit(requested_by, "created" if status == "pending" else "refused_at_creation",
                             action_id, type=type_, target=target, **(result or {}))
        return self.db.get_action(action_id)

    def _find_active(self, type_: str, target: str) -> dict | None:
        """A pending, approved or still-executed action of the same type on the same target."""
        # An executed block or sinkhole is still in force, so it is reused. An executed quarantine
        # or kill concerned a file/process that no longer exists: a re-dropped file needs a new action.
        statuses = ("pending", "approved") if type_ in ("quarantine_file", "kill_process") \
            else ("pending", "approved", "executed")
        for status in statuses:
            for a in self.db.list_actions(status, limit=500):
                if a["type"] == type_ and a["target"] == target and a["dry_run"] == self.config.dry_run:
                    return a
        return None

    def request_rollback(self, action_id: int, reason: str, requested_by: str) -> dict:
        original = self._get(action_id)
        if original["type"] not in REVERSIBLE:
            raise TransitionError(f"action {action_id} ({original['type']}) is irreversible")
        if original["status"] != "executed":
            raise TransitionError(f"only executed actions can be rolled back (status: {original['status']})")
        for a in self.db.list_actions("pending", limit=500):
            if a["type"] == "rollback" and a["rollback_of"] == action_id:
                return a
        new_id = self.db.insert_action(
            type="rollback", target=f"action {action_id}: {original['target']}", params={},
            reason=reason[:500], requested_by=requested_by, status="pending",
            dry_run=self.config.dry_run, rollback_of=action_id,
        )
        self.db.append_audit(requested_by, "rollback_requested", new_id, rollback_of=action_id)
        return self.db.get_action(new_id)

    def transition(self, action_id: int, new_status: str, actor: str, **fields) -> dict:
        action = self._get(action_id)
        if new_status not in TRANSITIONS[action["status"]]:
            raise TransitionError(f"action {action_id}: {action['status']} -> {new_status} is not allowed")
        self.db.update_action(action_id, status=new_status, **fields)
        self.db.append_audit(actor, new_status, action_id, **{k: v for k, v in fields.items() if k != "params"})
        return self.db.get_action(action_id)

    def approve(self, action_id: int, actor: str) -> dict:
        action = self._get(action_id)
        if action["status"] != "pending":
            raise TransitionError(f"action {action_id} is {action['status']}, not pending")
        if action["type"] == "rollback":
            original = self._get(action["rollback_of"])
            if original["status"] != "executed":
                return self.transition(action_id, "rejected", actor,
                                       result={"error": f"original action is now {original['status']}"})
            return self.transition(action_id, "approved", actor, approved_by=actor, approved_at=now_iso())
        try:
            _, clean = self.validate(action["type"], action["params"])
        except ValidationError as e:
            self.transition(action_id, "approved", actor, approved_by=actor, approved_at=now_iso())
            return self.transition(action_id, "rejected", "responder", result={"error": f"re-check failed: {e}"})
        return self.transition(action_id, "approved", actor, approved_by=actor, approved_at=now_iso(),
                               params=clean)

    def reject(self, action_id: int, actor: str, reason: str = "") -> dict:
        return self.transition(action_id, "rejected", actor, result={"error": reason or "rejected by analyst"})

    def expiry_for(self, action: dict) -> str | None:
        if action["type"] not in EXPIRING:
            return None
        ttl = float(action["params"].get("ttl", self.config.block_ttl))
        delta = timedelta(seconds=ttl * self.config.ttl_seconds_per_unit)
        return (datetime.now(timezone.utc) + delta).isoformat(timespec="seconds")

    def _get(self, action_id: int) -> dict:
        action = self.db.get_action(int(action_id))
        if not action:
            raise TransitionError(f"no action with id {action_id}")
        return action
