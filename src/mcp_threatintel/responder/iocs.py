"""Read-only view of the intelligence cache (threatintel.db) for the host agent.

The agent never writes the cache: it is opened with ``mode=ro``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


class IocIndex:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        uri = self.db_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @property
    def available(self) -> bool:
        return self.db_path.exists()

    def match(self, values: list[str]) -> dict[str, list[dict]]:
        """Return {value: [match, ...]} for every value found in iocs or local_iocs."""
        values = sorted({v for v in values if v})
        if not values or not self.available:
            return {}
        out: dict[str, list[dict]] = {}
        conn = self._connect()
        try:
            for i in range(0, len(values), 500):
                chunk = values[i:i + 500]
                marks = ",".join("?" * len(chunk))
                for r in conn.execute(
                    f"SELECT indicator, type, source, malware_family, threat_type FROM iocs "
                    f"WHERE indicator IN ({marks})", chunk,
                ):
                    out.setdefault(r["indicator"], []).append({
                        "source": r["source"], "type": r["type"],
                        "malware_family": r["malware_family"], "threat_type": r["threat_type"],
                    })
                lowered = [c.lower() for c in chunk]
                by_lower = {c.lower(): c for c in chunk}
                for r in conn.execute(
                    f"SELECT value, type, comment FROM local_iocs WHERE lower(value) IN ({marks})", lowered,
                ):
                    original = by_lower.get(r["value"].lower(), r["value"])
                    out.setdefault(original, []).append({
                        "source": "local", "type": r["type"], "comment": r["comment"],
                    })
        except sqlite3.OperationalError:
            # Cache not initialised yet (poller never ran): nothing matches.
            return {}
        finally:
            conn.close()
        return out

    def is_local_ioc(self, value: str) -> bool:
        return any(m["source"] == "local" for m in self.match([value]).get(value, []))

    def feed_ips(self, source: str, limit: int = 5000) -> list[str]:
        """IP indicators of one feed (for block_feed_c2)."""
        if not self.available:
            return []
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT DISTINCT indicator FROM iocs WHERE source = ? AND type = 'ip' LIMIT ?",
                (source, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()
        return [r["indicator"] for r in rows]
