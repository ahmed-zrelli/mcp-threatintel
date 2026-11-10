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
                         ("resolution_note", "TEXT")):
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
                     action_ids: list[int]) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (ts, key, kind, severity, title, detail_json, action_ids) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now_iso(), key, kind, severity, title, json.dumps(detail, default=str), json.dumps(action_ids)),
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
