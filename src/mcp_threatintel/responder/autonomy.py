"""AI mode: the local model decides, inside server-side guardrails.

The agent runs in AI mode only. Every action the model requests (MCP response tools, rollbacks) is
approved at once by approve_request(), and resolve_alert lets it execute or dismiss the actions the
detection rules proposed for an alert. The analyst can still cancel a pending action or roll back an
executed one from the dashboard.

    resolve(alert_id, decision, justification)
        execute   approve the alert's pending actions
        dismiss   reject them (false positive)
        escalate  leave them to a human

Guardrails enforced HERE, on the server, whatever the model says:
  * AUTONOMY=off (default): nothing is executed; the decision is only stored
    as a recommendation and a human approves as before.
  * Only the actions created by the detection engine for THAT alert can be
    approved (targets come from deterministic feed matches, never from the
    model, so text injected in feeds cannot point it at an arbitrary target).
  * Only the action types in AUTONOMY_ACTIONS (default: reversible ones -
    block_ip, sinkhole_domain, quarantine_file). Others stay pending for a human.
  * At most AUTONOMY_MAX_PER_HOUR autonomous approvals per hour.
  * Approval re-runs validation and the allowlist (ActionManager.approve).
  * Everything is audited as "qwen-autonomous" with the justification, and any
    executed action can be rolled back by the analyst.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .actions import ActionManager, TransitionError
from .config import ResponderConfig
from .store import ResponderDB
from .validators import ValidationError

ACTOR = "qwen-autonomous"
DECISIONS = {"execute", "dismiss", "escalate"}


class Autonomy:
    def __init__(self, db: ResponderDB, manager: ActionManager, config: ResponderConfig):
        self.db = db
        self.manager = manager
        self.config = config

    def status(self) -> dict:
        return {"enabled": self.config.autonomy, "mode": "ai" if self.config.autonomy else "approval",
                "allowed_actions": list(self.config.autonomy_actions),
                "max_per_hour": self.config.autonomy_max_per_hour,
                "used_last_hour": self._used_last_hour()}

    def _used_last_hour(self) -> int:
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
        return self.db.count_audit_since(ACTOR, "approved", since)

    def approve_request(self, action: dict) -> dict:
        """An action the model asked for: executed now (validation, allowlist and the hourly limit apply)."""
        if not self.config.autonomy or action.get("status") != "pending" or action.get("duplicate"):
            return action
        if action["type"] != "rollback" and action["type"] not in self.config.autonomy_actions:
            return {**action, "left_pending": f"{action['type']} is not in AUTONOMY_ACTIONS"}
        if self._used_last_hour() >= self.config.autonomy_max_per_hour:
            return {**action, "left_pending": "hourly AI limit reached (AUTONOMY_MAX_PER_HOUR)"}
        try:
            return self.manager.approve(action["id"], ACTOR)
        except TransitionError as e:
            return {**action, "left_pending": str(e)}

    def resolve(self, alert_id: int, decision: str, justification: str) -> dict:
        decision = (decision or "").strip().lower()
        justification = (justification or "").strip()
        if decision not in DECISIONS:
            raise ValidationError(f"decision must be one of {sorted(DECISIONS)}")
        if len(justification) < 10:
            raise ValidationError("a justification (at least one sentence) is required")
        alert = self.db.get_alert(int(alert_id))
        if not alert:
            raise ValidationError(f"no alert with id {alert_id}")
        if alert.get("resolution"):
            return {"alert_id": alert["id"], "already_resolved": alert["resolution"],
                    "by": alert.get("resolution_by")}

        pending = [a for a in (self.db.get_action(i) for i in alert["action_ids"]) if a and a["status"] == "pending"]

        if not self.config.autonomy:
            self.db.save_resolution(alert["id"], f"recommended_{decision}", "qwen", justification)
            self.db.append_audit("qwen", "autonomy_recommendation", None, alert_id=alert["id"], decision=decision)
            return {"alert_id": alert["id"], "autonomy": False, "recorded_as": f"recommended_{decision}",
                    "note": "Autonomous mode is OFF: nothing was executed, a human must approve the pending actions.",
                    "pending_action_ids": [a["id"] for a in pending]}

        executed, left = [], []
        if decision == "execute":
            used = self._used_last_hour()
            for a in pending:
                if a["type"] not in self.config.autonomy_actions:
                    left.append({"id": a["id"], "type": a["type"],
                                 "reason": "not allowed in autonomous mode: needs a human"})
                    continue
                if used >= self.config.autonomy_max_per_hour:
                    left.append({"id": a["id"], "type": a["type"], "reason": "hourly autonomous limit reached"})
                    continue
                try:
                    res = self.manager.approve(a["id"], ACTOR)
                except TransitionError as e:
                    left.append({"id": a["id"], "type": a["type"], "reason": str(e)})
                    continue
                used += 1
                entry = {"id": a["id"], "type": a["type"], "target": a["target"], "status": res["status"]}
                if res["status"] == "rejected":
                    entry["reason"] = (res.get("result") or {}).get("error")
                executed.append(entry)
            approved = [e for e in executed if e["status"] == "approved"]
            resolution = ("executed" if approved and not left else
                          "partially_executed" if approved else "escalated")
        elif decision == "dismiss":
            for a in pending:
                try:
                    self.manager.reject(a["id"], ACTOR, f"dismissed as false positive: {justification[:200]}")
                    executed.append({"id": a["id"], "type": a["type"], "target": a["target"], "status": "rejected"})
                except TransitionError as e:
                    left.append({"id": a["id"], "type": a["type"], "reason": str(e)})
            resolution = "dismissed"
        else:
            left = [{"id": a["id"], "type": a["type"], "reason": "left pending (AI unsure); the analyst "
                     "can cancel it on the dashboard"} for a in pending]
            resolution = "escalated"

        self.db.save_resolution(alert["id"], resolution, ACTOR, justification)
        self.db.append_audit(ACTOR, "alert_resolved", None, alert_id=alert["id"], decision=decision,
                             resolution=resolution, handled=[e["id"] for e in executed],
                             left_for_human=[e["id"] for e in left])
        return {"alert_id": alert["id"], "autonomy": True, "decision": decision, "resolution": resolution,
                "handled": executed, "left_for_human": left,
                "note": "Approved actions run within a second; the analyst can roll any of them back."}
