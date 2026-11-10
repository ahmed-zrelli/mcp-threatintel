"""Read-only view of the intelligence cache (threatintel.db) for the host agent.

Every indicator the poller stored is turned into an in-memory index (rebuilt
when the database changes, at most every ``refresh_s`` seconds):

    ips      - Feodo / ThreatFox / OTX IPs, plus IP hosts of URLhaus URLs
    domains  - ThreatFox / OTX domains and hostnames (explicit domain IOCs only:
               URLhaus hosts are often shared services and are NOT used, to
               avoid flagging e.g. github.com)
    urls     - URLhaus / ThreatFox / OTX URLs
    hashes   - MD5, SHA-1 and SHA-256 from MalwareBazaar / ThreatFox / OTX

plus the lab IOCs (local_iocs). The agent never writes the cache: it is
opened with ``mode=ro``.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .benign import is_benign_domain, is_benign_ip

_TYPE = {  # normalise the many spellings of indicator types across feeds
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip:port": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url",
    "hash_md5": "hash", "md5_hash": "hash", "filehash-md5": "hash",
    "hash_sha1": "hash", "sha1_hash": "hash", "filehash-sha1": "hash",
    "hash_sha256": "hash", "sha256_hash": "hash", "filehash-sha256": "hash",
}


def _norm_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class IocIndex:
    def __init__(self, db_path: str | Path, refresh_s: float = 300):
        self.db_path = Path(db_path)
        self.refresh_s = refresh_s
        self._lock = threading.Lock()
        self._built_at = 0.0
        self._mtime = None
        self._idx: dict[str, dict[str, list[dict]]] = {"ip": {}, "domain": {}, "url": {}, "hash": {}}
        self.counts: dict[str, int] = {}

    def _connect(self) -> sqlite3.Connection:
        uri = self.db_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @property
    def available(self) -> bool:
        return self.db_path.exists()

    # --- index -------------------------------------------------------------

    def _db_mtime(self):
        try:
            wal = self.db_path.with_name(self.db_path.name + "-wal")
            return (self.db_path.stat().st_mtime, wal.stat().st_mtime if wal.exists() else 0)
        except OSError:
            return None

    def _ensure(self) -> None:
        now = time.time()
        if self._built_at and now - self._built_at < self.refresh_s:
            return
        mtime = self._db_mtime()
        if self._built_at and mtime == self._mtime:
            self._built_at = now
            return
        with self._lock:
            self._idx = self._build()
            self._mtime = mtime
            self._built_at = now
            self.counts = {k: len(v) for k, v in self._idx.items()}

    def _build(self) -> dict[str, dict[str, list[dict]]]:
        idx: dict[str, dict[str, list[dict]]] = {"ip": {}, "domain": {}, "url": {}, "hash": {}}
        if not self.available:
            return idx

        def add(kind: str, value: str, match: dict) -> None:
            if not value:
                return
            value = value.strip()
            if kind in ("domain", "hash"):
                value = _norm_domain(value)
            elif kind == "ip":
                value = value.split(":")[0] if value.count(":") == 1 else value
            lst = idx[kind].setdefault(value, [])
            if len(lst) < 5:
                lst.append(match)

        conn = self._connect()
        try:
            for r in conn.execute(
                "SELECT indicator, type, source, malware_family, threat_type FROM iocs"
            ):
                kind = _TYPE.get((r["type"] or "").lower())
                m = {"source": r["source"], "malware_family": r["malware_family"], "threat_type": r["threat_type"]}
                if kind == "url":
                    add("url", r["indicator"], m)
                    host = (urlsplit(r["indicator"]).hostname or "")
                    if _is_ip(host):  # an IP serving malware is specific enough to flag
                        add("ip", host, {**m, "threat_type": "malware_distribution"})
                elif kind:
                    add(kind, r["indicator"], m)
            try:
                for r in conn.execute(
                    "SELECT pi.indicator, pi.type, p.name FROM pulse_indicators pi "
                    "JOIN pulses p ON p.pulse_id = pi.pulse_id"
                ):
                    kind = _TYPE.get((r["type"] or "").lower())
                    if kind:
                        add(kind, r["indicator"], {"source": "otx", "pulse": (r["name"] or "")[:80]})
            except sqlite3.OperationalError:
                pass
            for r in conn.execute("SELECT value, type, comment FROM local_iocs"):
                kind = _TYPE.get((r["type"] or "").lower())
                if kind:
                    add(kind, r["value"], {"source": "local", "comment": r["comment"]})
        except sqlite3.OperationalError:
            return idx  # cache not initialised yet (poller never ran)
        finally:
            conn.close()
        return idx

    # --- lookups -----------------------------------------------------------

    def lookup(self, kind: str, value: str) -> list[dict]:
        """Matches for one observable; feed matches on well-known services are ignored,
        lab IOCs (source 'local') always count."""
        self._ensure()
        key = _norm_domain(value) if kind in ("domain", "hash") else value.strip()
        matches = self._idx.get(kind, {}).get(key, [])
        if not matches:
            return []
        local = [m for m in matches if m.get("source") == "local"]
        if local:
            return matches
        if kind == "ip" and is_benign_ip(key):
            return []
        if kind == "domain" and is_benign_domain(key):
            return []
        return matches

    def lookup_domain(self, domain: str) -> list[dict]:
        """Exact domain, then its parents (a.b.evil.example -> evil.example)."""
        d = _norm_domain(domain)
        parts = d.split(".")
        for i in range(len(parts) - 1):
            found = self.lookup("domain", ".".join(parts[i:]))
            if found:
                return found
        return []

    def match(self, values: list[str]) -> dict[str, list[dict]]:
        """{value: matches} for IPs or hashes (kept for the existing scanners)."""
        out: dict[str, list[dict]] = {}
        for v in {v for v in values if v}:
            found = self.lookup("ip", v) if _is_ip(v) else self.lookup("hash", v)
            if found:
                out[v] = found
        return out

    def is_local_ioc(self, value: str) -> bool:
        kind = "ip" if _is_ip(value) else ("hash" if len(value) in (32, 40, 64) else "domain")
        return any(m.get("source") == "local" for m in self.lookup(kind, value))

    def related(self, indicator: str, limit: int = 300) -> dict:
        """Campaign pivot: OTX pulses and malware families that contain ``indicator``,
        and the other indicators they list (normalised types, shared services removed)."""
        out = {"pulses": [], "families": [], "related": []}
        if not self.available or not indicator:
            return out
        value = indicator.strip()
        conn = self._connect()
        try:
            pulses = conn.execute(
                "SELECT DISTINCT p.pulse_id, p.name, p.adversary, p.malware_families FROM pulse_indicators pi "
                "JOIN pulses p ON p.pulse_id = pi.pulse_id WHERE lower(pi.indicator) = lower(?) LIMIT 10",
                (value,),
            ).fetchall()
            out["pulses"] = [{"id": r["pulse_id"], "name": (r["name"] or "")[:100], "adversary": r["adversary"]}
                             for r in pulses]
            fams = [r["malware_family"] for r in conn.execute(
                "SELECT DISTINCT malware_family FROM iocs WHERE lower(indicator) = lower(?) "
                "AND malware_family IS NOT NULL AND malware_family != ''", (value,))]
            out["families"] = fams
            seen: set[tuple[str, str]] = set()

            def keep(v: str, t: str, src: str) -> None:
                kind = _TYPE.get((t or "").lower())
                if not kind or kind == "url" or not v or v.lower() == value.lower():
                    return
                v = v.strip().lower() if kind in ("domain", "hash") else v.strip()
                if (kind == "ip" and is_benign_ip(v)) or (kind == "domain" and is_benign_domain(v)):
                    return
                if (v, kind) not in seen and len(seen) < limit:
                    seen.add((v, kind))
                    out["related"].append({"value": v, "type": kind, "via": src})

            for p in out["pulses"]:
                for r in conn.execute("SELECT indicator, type FROM pulse_indicators WHERE pulse_id = ?", (p["id"],)):
                    keep(r["indicator"], r["type"], f"OTX pulse: {p['name'][:50]}")
            for fam in fams[:3]:
                for r in conn.execute(
                    "SELECT indicator, type, source FROM iocs WHERE malware_family = ? LIMIT ?", (fam, limit)
                ):
                    keep(r["indicator"], r["type"], f"{r['source']} family: {fam}")
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
        return out

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
