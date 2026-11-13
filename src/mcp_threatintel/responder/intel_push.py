"""Threat-intel push: the console (analyst PC) sends its indicator database to the agent.

In the split architecture the poller runs on the analyst PC, not on the
protected server. After each poll the console sends a consistent snapshot of
threatintel.db (``VACUUM INTO``, gzip) in chunks over the agent channel; the
agent checks the SHA-256 and SQLite integrity, then swaps it in atomically.
The IocIndex notices the new file and rebuilds itself within seconds.
A snapshot identical to the last one pushed is not sent again.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import logging
import os
import sqlite3
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("threatintel.intel_push")

CHUNK = 512 * 1024
MAX_TOTAL = 300 * 1024 * 1024


def snapshot(db_path: str | Path) -> bytes:
    """gzip of a compact, rollback-journal copy of the database (deterministic for identical data)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "snapshot.db")
        src = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
        try:
            src.execute("VACUUM INTO ?", (out,))
        finally:
            src.close()
        c = sqlite3.connect(out)
        c.execute("PRAGMA journal_mode=DELETE")
        c.close()
        raw = Path(out).read_bytes()
    return gzip.compress(raw, compresslevel=6, mtime=0)


def push(send, db_path: str | Path, *, force: bool = False) -> dict:
    """Send the snapshot with ``send(op, params) -> data`` (an agent-channel call)."""
    blob = snapshot(db_path)
    digest = hashlib.sha256(blob).hexdigest()
    if not force:
        status = send("intel_status", {})
        if status.get("sha256") == digest:
            return {"pushed": False, "reason": "agent already has this snapshot", "sha256": digest}
    transfer = f"{int(time.time())}-{digest[:12]}"
    chunks = [blob[i:i + CHUNK] for i in range(0, len(blob), CHUNK)] or [b""]
    result = {}
    for seq, chunk in enumerate(chunks):
        last = seq == len(chunks) - 1
        result = send("push_intel", {"transfer": transfer, "seq": seq, "last": last,
                                     "sha256": digest if last else None,
                                     "data": base64.b64encode(chunk).decode()})
    return {"pushed": True, "bytes": len(blob), "chunks": len(chunks), "sha256": digest, **(result or {})}


class IntelReceiver:
    """Agent side: assembles chunks, verifies, swaps the IOC database in."""

    def __init__(self, ioc_db: Path, db=None):
        self.ioc_db = Path(ioc_db)
        self.db = db              # ResponderDB (records the last snapshot hash)
        self._transfer: str | None = None
        self._next = 0
        self._size = 0

    def _part(self) -> Path:
        return self.ioc_db.with_name(self.ioc_db.name + ".incoming.gz")

    def status(self) -> dict:
        sha = self.db.get_setting("intel_sha256") if self.db else None
        exists = self.ioc_db.exists()
        return {"sha256": sha, "received_at": self.db.get_setting("intel_received_at") if self.db else None,
                "db_exists": exists, "db_bytes": self.ioc_db.stat().st_size if exists else 0}

    def receive(self, p: dict) -> dict:
        transfer, seq = str(p.get("transfer") or ""), int(p.get("seq", -1))
        if not transfer:
            raise ValueError("missing transfer id")
        if seq == 0:
            self._transfer, self._next, self._size = transfer, 0, 0
            self.ioc_db.parent.mkdir(parents=True, exist_ok=True)
            self._part().write_bytes(b"")
        if transfer != self._transfer or seq != self._next:
            raise ValueError(f"out-of-order chunk {seq} for {transfer} (expected {self._next} of {self._transfer})")
        data = base64.b64decode(str(p.get("data") or ""), validate=True)
        self._size += len(data)
        if self._size > MAX_TOTAL:
            self._transfer = None
            raise ValueError("intel snapshot too large")
        with open(self._part(), "ab") as f:
            f.write(data)
        self._next += 1
        if not p.get("last"):
            return {"received": seq}
        self._transfer = None
        return self._install(str(p.get("sha256") or ""))

    def _install(self, sha: str) -> dict:
        part = self._part()
        blob = part.read_bytes()
        part.unlink(missing_ok=True)
        if hashlib.sha256(blob).hexdigest() != sha:
            raise ValueError("intel snapshot checksum mismatch; not installed")
        tmp = self.ioc_db.with_name(self.ioc_db.name + ".new")
        tmp.write_bytes(gzip.decompress(blob))
        try:
            c = sqlite3.connect(tmp)
            try:
                if c.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("intel snapshot failed the SQLite integrity check")
                counts = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608 (fixed names)
                          for t in ("iocs", "pulse_indicators", "local_iocs")
                          if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()}
                if "iocs" not in counts:
                    raise ValueError("intel snapshot has no iocs table")
            finally:
                c.close()
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        # A WAL left by an earlier writer must not be replayed onto the new file.
        for suffix in ("-wal", "-shm"):
            Path(str(self.ioc_db) + suffix).unlink(missing_ok=True)
        os.replace(tmp, self.ioc_db)
        if self.db:
            self.db.set_setting("intel_sha256", sha, "console")
            self.db.set_setting("intel_received_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "console")
            self.db.append_audit("console", "intel_received", None, sha256=sha[:16], bytes=len(blob), **counts)
        logger.info("intel snapshot installed: %s", counts)
        return {"installed": True, "counts": counts}
