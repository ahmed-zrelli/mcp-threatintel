"""ResponderDB: actions, append-only audit log and allowlist (responder.db).

Owned by the host agent. The MCP server never opens this file; it only talks
to the agent over the agent channel.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    params_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    executed_at TEXT,
    result TEXT,
    rollback_of INTEGER REFERENCES actions(id),
    expires_at TEXT,
    dry_run INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    action_id INTEGER,
    details_json TEXT NOT NULL DEFAULT '{}'
);

-- Append-only: the database itself refuses to rewrite history.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- Alerts raised by the always-on detection loop (AlertEngine).
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    key TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    action_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_alerts_key ON alerts(key, ts);

-- One incident = one attack: every alert (finding) that shares an indicator,
-- process or campaign with it inside the correlation window joins it.
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    opened_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    keys_json TEXT NOT NULL DEFAULT '[]',
    alert_count INTEGER NOT NULL DEFAULT 0,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    blocked_attempts INTEGER NOT NULL DEFAULT 0,
    persisting_notified INTEGER NOT NULL DEFAULT 0
);

-- Runtime settings and baselines (decision mode, normal accounts/files/ports), kept across restarts.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    changed_by TEXT,
    changed_at TEXT
);

CREATE TABLE IF NOT EXISTS allowlist (
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    comment TEXT,
    UNIQUE(value, type)
);
"""


_UPDATABLE = {
    "status", "params_json", "approved_by", "approved_at", "executed_at", "result", "expires_at",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ResponderDB:
    """Thin, thread-safe wrapper around one sqlite3 connection."""

    def __init__(self, path: str | Path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._lock = threading.Lock()

    def _migrate(self) -> None:
        """Columns added after the first release (existing databases on deployed servers)."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(alerts)")}
        for col, ddl in (("report", "TEXT"), ("report_by", "TEXT"), ("report_at", "TEXT"),
                         ("resolution", "TEXT"), ("resolution_by", "TEXT"), ("resolution_at", "TEXT"),
                         ("resolution_note", "TEXT"), ("occurrences", "INTEGER NOT NULL DEFAULT 1"),
                         ("last_seen", "TEXT"), ("recurrence_of", "INTEGER"),
                         ("incident_id", "INTEGER"), ("incident_event", "TEXT")):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {ddl}")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- actions ---

    def insert_action(self, *, type: str, target: str, params: dict, reason: str,
                      requested_by: str, status: str, dry_run: bool,
                      rollback_of: int | None = None, result: dict | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO actions (type, target, params_json, reason, requested_by,
                   status, created_at, rollback_of, dry_run, result)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (type, target, json.dumps(params), reason, requested_by, status,
                 now_iso(), rollback_of, int(dry_run),
                 json.dumps(result) if result is not None else None),
            )
            self._conn.commit()
            return cur.lastrowid

    def update_action(self, action_id: int, **fields) -> None:
        if not fields:
            return
        if "result" in fields and not isinstance(fields["result"], (str, type(None))):
            fields["result"] = json.dumps(fields["result"])
        if "params" in fields:
            fields["params_json"] = json.dumps(fields.pop("params"))
        bad = set(fields) - _UPDATABLE
        if bad:
            raise ValueError(f"not updatable: {sorted(bad)}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self._conn.execute(f"UPDATE actions SET {cols} WHERE id = ?", (*fields.values(), action_id))
            self._conn.commit()

    def get_action(self, action_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
        return _action(row) if row else None

    def list_actions(self, status: str = "", limit: int = 50) -> list[dict]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM actions WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [_action(r) for r in rows]

    def due_for_expiry(self, now: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM actions WHERE status = 'executed' AND expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            ).fetchall()
        return [_action(r) for r in rows]

    # --- audit ---

    def append_audit(self, actor: str, event: str, action_id: int | None = None, **details) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log (ts, actor, event, action_id, details_json) VALUES (?, ?, ?, ?, ?)",
                (now_iso(), actor, event, action_id, json.dumps(details, default=str)),
            )
            self._conn.commit()

    def audit(self, action_id: int | None = None, limit: int = 100) -> list[dict]:
        with self._lock:
            if action_id is not None:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log WHERE action_id = ? ORDER BY id", (action_id,)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json") or "{}")
            out.append(d)
        return out

    # --- alerts ---

    def insert_alert(self, *, key: str, kind: str, severity: str, title: str, detail: dict,
                     action_ids: list[int], recurrence_of: int | None = None,
                     incident_id: int | None = None, incident_event: str | None = None) -> int:
        now = now_iso()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (ts, key, kind, severity, title, detail_json, action_ids, last_seen, "
                "recurrence_of, incident_id, incident_event) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, key, kind, severity, title, json.dumps(detail, default=str), json.dumps(action_ids),
                 now, recurrence_of, incident_id, incident_event),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_alert(self, alert_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["detail"] = json.loads(d.pop("detail_json") or "{}")
        d["action_ids"] = json.loads(d["action_ids"] or "[]")
        return d

    def save_report(self, alert_id: int, report: str, by: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE alerts SET report = ?, report_by = ?, report_at = ? WHERE id = ?",
                               (report[:8000], by, now_iso(), alert_id))
            self._conn.commit()

    def save_resolution(self, alert_id: int, resolution: str, by: str, note: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET resolution = ?, resolution_by = ?, resolution_at = ?, resolution_note = ? "
                "WHERE id = ?", (resolution, by, now_iso(), note[:2000], alert_id))
            self._conn.commit()

    def count_audit_since(self, actor: str, event: str, since_iso: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE actor = ? AND event = ? AND ts >= ?",
                (actor, event, since_iso)).fetchone()[0]

    def latest_alert(self, key: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT id FROM alerts WHERE key = ? ORDER BY id DESC LIMIT 1",
                                     (key,)).fetchone()
        return self.get_alert(row["id"]) if row else None

    # --- incidents ---

    def insert_incident(self, *, severity: str, title: str, keys: set[str]) -> int:
        now = now_iso()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incidents (opened_at, last_seen, severity, title, keys_json) VALUES (?, ?, ?, ?, ?)",
                (now, now, severity, title, json.dumps(sorted(keys))))
            self._conn.commit()
            return cur.lastrowid

    def get_incident(self, incident_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["keys"] = json.loads(d.pop("keys_json") or "[]")
        return d

    def recent_incidents(self, since_iso: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT id FROM incidents WHERE last_seen >= ? ORDER BY id DESC",
                                      (since_iso,)).fetchall()
        return [self.get_incident(r["id"]) for r in rows]

    def list_incidents(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT id FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self.get_incident(r["id"]) for r in rows]

    def update_incident(self, incident_id: int, *, keys: set[str] | None = None, severity: str | None = None,
                        add_alert: bool = False, reopened: bool = False, blocked_attempt: bool = False,
                        persisting_notified: bool = False) -> None:
        inc = self.get_incident(incident_id)
        if not inc:
            return
        fields = {"last_seen": now_iso()}
        if keys:
            fields["keys_json"] = json.dumps(sorted(set(inc["keys"]) | set(keys))[:500])
        if severity:
            fields["severity"] = severity
        sets = ", ".join(f"{k} = ?" for k in fields)
        extra = []
        if add_alert:
            extra.append("alert_count = alert_count + 1")
        if reopened:
            extra.append("reopen_count = reopen_count + 1")
        if blocked_attempt:
            extra.append("blocked_attempts = blocked_attempts + 1")
        if persisting_notified:
            extra.append("persisting_notified = 1")
        sql = "UPDATE incidents SET " + ", ".join([sets] + extra) + " WHERE id = ?"
        with self._lock:
            self._conn.execute(sql, (*fields.values(), incident_id))
            self._conn.commit()

    def incident_alerts(self, incident_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT id FROM alerts WHERE incident_id = ? ORDER BY id",
                                      (incident_id,)).fetchall()
        return [self.get_alert(r["id"]) for r in rows]

    def bump_alert(self, alert_id: int) -> None:
        """The same open incident was detected again: count it instead of re-alerting."""
        with self._lock:
            self._conn.execute("UPDATE alerts SET occurrences = occurrences + 1, last_seen = ? WHERE id = ?",
                               (now_iso(), alert_id))
            self._conn.commit()

    def alerted_since(self, key: str, since_iso: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM alerts WHERE key = ? AND ts >= ? LIMIT 1", (key, since_iso)
            ).fetchone()
        return row is not None

    def list_alerts(self, since_id: int = 0, limit: int = 50) -> list[dict]:
        with self._lock:
            if since_id:
                rows = self._conn.execute(
                    "SELECT * FROM alerts WHERE id > ? ORDER BY id LIMIT ?", (since_id, limit)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM (SELECT * FROM alerts ORDER BY id DESC LIMIT ?) ORDER BY id", (limit,)
                ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d.pop("detail_json") or "{}")
            d["action_ids"] = json.loads(d["action_ids"] or "[]")
            out.append(d)
        return out

    # --- settings ---

    def get_setting(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str, by: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings (key, value, changed_by, changed_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, changed_by = excluded.changed_by, "
                "changed_at = excluded.changed_at", (key, value, by, now_iso()))
            self._conn.commit()

    # --- allowlist ---

    def replace_allowlist(self, entries: list[tuple[str, str, str]]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM allowlist")
            self._conn.executemany(
                "INSERT OR IGNORE INTO allowlist (value, type, comment) VALUES (?, ?, ?)", entries
            )
            self._conn.commit()

    def load_allowlist(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT value, type, comment FROM allowlist").fetchall()
        return [dict(r) for r in rows]


def _action(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["params"] = json.loads(d.pop("params_json") or "{}")
    d["result"] = json.loads(d["result"]) if d.get("result") else None
    d["dry_run"] = bool(d["dry_run"])
    return d
