"""HostScanner: read-only inspection of the host, cross-checked with every
indicator the poller collected (IocIndex: IPs, domains, URLs, MD5/SHA-1/SHA-256,
from abuse.ch, OTX and the lab list).

Detectors:
  connections  - live + recently sampled remote endpoints   vs IPs
  dns          - names the server resolved (systemd-resolved) vs domains
  files        - SCAN_PATHS + temp dirs, all three hashes   vs hashes
  processes    - URLs / domains / IPs in command lines      vs URLs, domains, IPs
  auth_logs    - SSH failures (brute force) and logins (even successful) from malicious IPs

Nothing here modifies the machine. Results are capped (config.max_results).
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import psutil

from .config import ResponderConfig
from .iocs import IocIndex
from .monitor import ConnectionSampler, DnsMonitor
from .validators import ValidationError, validate_path

logger = logging.getLogger("threatintel.responder.scanner")

MAX_FILES = 2000
MAX_FILE_BYTES = 100 * 1024 * 1024

# OpenSSH writes the same messages on Linux (auth.log/journald) and Windows
# (OpenSSH/Operational event log), so one parser serves both.
_FAILED = re.compile(
    r"(?:Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+)"
    r"|Invalid user (?P<user2>\S+)) from (?P<ip>[0-9a-fA-F:.]+)"
)
_ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")

_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>|;`]+", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b", re.I)
_NOT_DOMAIN_SUFFIX = {"py", "sh", "so", "conf", "json", "txt", "log", "service", "socket", "db", "csv", "pid", "lock"}


def parse_auth_lines(lines) -> dict[str, dict]:
    """Count failed and successful SSH authentications per source IP."""
    per_ip: dict[str, dict] = defaultdict(lambda: {"failures": 0, "accepted": 0, "users": set()})
    for line in lines:
        m = _FAILED.search(line)
        kind = "failures"
        if not m:
            m = _ACCEPTED.search(line)
            kind = "accepted"
        if not m:
            continue
        ip = m.group("ip")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        entry = per_ip[ip]
        entry[kind] += 1
        entry["users"].add(m.groupdict().get("user") or m.groupdict().get("user2"))
    return per_ip


def extract_observables(cmdline: str) -> list[tuple[str, str]]:
    """(kind, value) pairs worth checking in a process command line."""
    out: list[tuple[str, str]] = []
    for url in _URL.findall(cmdline):
        url = url.rstrip(").,")
        out.append(("url", url))
    for ip in _IPV4.findall(cmdline):
        try:
            ipaddress.IPv4Address(ip)
            out.append(("ip", ip))
        except ValueError:
            pass
    for d in _DOMAIN.findall(cmdline):
        d = d.lower()
        if d.rsplit(".", 1)[-1] not in _NOT_DOMAIN_SUFFIX and not _IPV4.fullmatch(d):
            out.append(("domain", d))
    return list(dict.fromkeys(out))


def hash_file(path: Path) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


class HostScanner:
    def __init__(self, config: ResponderConfig, iocs: IocIndex,
                 sampler: ConnectionSampler | None = None, dns: DnsMonitor | None = None):
        self.config = config
        self.iocs = iocs
        self.sampler = sampler
        self.dns = dns
        self._hash_cache: dict[str, tuple[int, float, dict]] = {}

    def _cap(self, hits: list) -> dict:
        return {"malicious_count": len(hits), "malicious": hits[: self.config.max_results],
                "truncated": len(hits) > self.config.max_results}

    # --- network ------------------------------------------------------------

    def scan_connections(self, window_minutes: int = 10) -> dict:
        now = time.time()
        seen: dict[tuple, dict] = {}
        for c in psutil.net_connections(kind="inet"):
            if c.raddr:
                seen[(c.raddr.ip, c.raddr.port, c.pid)] = {
                    "remote_ip": c.raddr.ip, "remote_port": c.raddr.port,
                    "local_port": c.laddr.port if c.laddr else None, "status": c.status,
                    "pid": c.pid, "process": _proc_name(c.pid), "active": True}
        if self.sampler:
            for key, r in self.sampler.seen.recent(window_minutes * 60, now):
                seen.setdefault(key, {**{k: r.get(k) for k in ("remote_ip", "remote_port", "local_port", "status",
                                                               "pid", "process")},
                                      "active": False, "last_seen_s_ago": int(now - r["last_seen"])})
        hits = []
        for rec in seen.values():
            matches = self.iocs.lookup("ip", rec["remote_ip"])
            if matches:
                hits.append({**rec, "ioc_matches": matches})
        hits.sort(key=lambda h: not h["active"])
        return {"connections_checked": len(seen), "sampled_history": bool(self.sampler),
                "ioc_cache_available": self.iocs.available, **self._cap(hits)}

    # --- DNS ----------------------------------------------------------------

    def scan_dns(self, window_minutes: int = 10) -> dict:
        if not self.dns or not self.dns.available:
            return {"available": False, "note": "DNS monitoring needs systemd-resolved (Linux)",
                    "malicious_count": 0, "malicious": []}
        now = time.time()
        recent = self.dns.seen.recent(window_minutes * 60, now)
        hits = []
        for name, r in recent:
            matches = self.iocs.lookup_domain(name)
            if matches:
                hits.append({"domain": name, "lookups": r["count"], "answers": r.get("answers", []),
                             "last_seen_s_ago": int(now - r["last_seen"]), "ioc_matches": matches})
        return {"available": True, "monitor": self.dns.status, "domains_seen": len(recent), **self._cap(hits)}

    # --- files --------------------------------------------------------------

    def _roots(self, path: str) -> list[Path]:
        if path:
            return [validate_path(path, self.config.scan_paths)]
        return [p for p in self.config.scan_paths if p.exists()]

    def scan_files(self, path: str = "") -> dict:
        roots = self._roots(path)
        if not roots:
            raise ValidationError("no directory to scan: set SCAN_PATHS")
        scanned = skipped = 0
        hits = []
        for root in roots:
            for file in _walk(root):
                if scanned >= MAX_FILES:
                    break
                try:
                    st = file.stat()
                    if st.st_size > MAX_FILE_BYTES:
                        skipped += 1
                        continue
                    cached = self._hash_cache.get(str(file))
                    if cached and cached[0] == st.st_size and cached[1] == st.st_mtime:
                        hashes = cached[2]
                    else:
                        hashes = hash_file(file)
                        self._hash_cache[str(file)] = (st.st_size, st.st_mtime, hashes)
                except OSError:
                    skipped += 1
                    continue
                scanned += 1
                for algo, digest in hashes.items():
                    matches = self.iocs.lookup("hash", digest)
                    if matches:
                        hits.append({"path": str(file), "size": st.st_size, "sha256": hashes["sha256"],
                                     "matched_hash": algo, "ioc_matches": matches})
                        break
        if len(self._hash_cache) > 20000:
            self._hash_cache.clear()
        return {"scanned_paths": [str(r) for r in roots], "files_scanned": scanned, "files_skipped": skipped,
                "limit_reached": scanned >= MAX_FILES, **self._cap(hits)}

    # --- processes ----------------------------------------------------------

    def scan_processes(self) -> dict:
        own = {os.getpid()}
        checked = 0
        hits = []
        for p in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            if p.info["pid"] in own or not p.info.get("cmdline"):
                continue
            checked += 1
            cmd = " ".join(p.info["cmdline"])[:2000]
            found = []
            for kind, value in extract_observables(cmd):
                matches = self.iocs.lookup_domain(value) if kind == "domain" else self.iocs.lookup(kind, value)
                if matches:
                    found.append({"type": kind, "value": value, "ioc_matches": matches})
            if found:
                hits.append({"pid": p.info["pid"], "process": p.info["name"], "user": p.info.get("username"),
                             "cmdline": cmd[:300], "indicators": found})
        return {"processes_checked": checked, **self._cap(hits)}

    # --- authentication logs ------------------------------------------------

    def scan_auth_logs(self, minutes: int = 60) -> dict:
        minutes = max(1, min(int(minutes), 7 * 24 * 60))
        source, lines, note = _read_auth_logs(minutes)
        per_ip = parse_auth_lines(lines)
        threshold = self.config.auth_fail_threshold
        details = []
        for ip, d in per_ip.items():
            matches = self.iocs.lookup("ip", ip)
            details.append({
                "ip": ip, "failures": d["failures"], "accepted": d["accepted"],
                "users_tried": sorted(u for u in d["users"] if u)[:10],
                "brute_force": d["failures"] >= threshold,
                "known_malicious": bool(matches),
                "ioc_matches": matches,
            })
        details.sort(key=lambda d: (not d["known_malicious"], -d["failures"]))
        return {
            "log_source": source, "note": note, "minutes": minutes, "threshold": threshold,
            "lines_read": len(lines), "sources_with_failures": sum(1 for d in details if d["failures"]),
            "brute_force_ips": [d["ip"] for d in details if d["brute_force"]],
            "malicious_sources": [d["ip"] for d in details if d["known_malicious"]],
            "successful_logins_from_malicious_ips": [d["ip"] for d in details if d["known_malicious"] and d["accepted"]],
            "details": details[: self.config.max_results],
        }

    # --- aggregate ----------------------------------------------------------

    def scan_host(self, minutes: int = 60) -> dict:
        report: dict = {}
        suggestions: list[str] = []
        for name, fn in (("connections", lambda: self.scan_connections(min(minutes, 60))),
                         ("dns", lambda: self.scan_dns(min(minutes, 60))),
                         ("files", self.scan_files),
                         ("processes", self.scan_processes),
                         ("auth_logs", lambda: self.scan_auth_logs(minutes))):
            try:
                report[name] = fn()
            except Exception as e:  # one failing scan must not hide the others
                report[name] = {"error": str(e)}
        for c in report["connections"].get("malicious", []):
            suggestions.append(f"block_ip ip={c['remote_ip']} (connection from {c['process']} PID {c['pid']})")
            if c.get("pid") and c.get("active"):
                suggestions.append(f"kill_process pid={c['pid']} ({c['process']})")
        for d in report["dns"].get("malicious", []):
            suggestions.append(f"sinkhole_domain domain={d['domain']} (resolved {d['lookups']}x)")
        for f in report["files"].get("malicious", []):
            suggestions.append(f"quarantine_file path={f['path']}")
        for p in report["processes"].get("malicious", []):
            suggestions.append(f"kill_process pid={p['pid']} ({p['process']}: {p['indicators'][0]['value']})")
        for ip in report["auth_logs"].get("brute_force_ips", []) + report["auth_logs"].get("malicious_sources", []):
            suggestions.append(f"block_ip ip={ip} (SSH)")
        report["suggested_actions"] = list(dict.fromkeys(suggestions))[: self.config.max_results]
        report["findings"] = len(set(suggestions))
        report["indicators_indexed"] = self.iocs.counts
        return report


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            if p.is_file() and not p.is_symlink():
                yield p


def _proc_name(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _read_auth_logs(minutes: int) -> tuple[str, list[str], str]:
    """Return (source name, lines, note). Never raises."""
    try:
        if sys.platform == "win32":
            ms = minutes * 60 * 1000
            query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
            proc = subprocess.run(
                ["wevtutil", "qe", "OpenSSH/Operational", f"/q:{query}", "/f:text", "/c:5000", "/rd:true"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return ("OpenSSH/Operational", [],
                        "OpenSSH Server event log not available (install the 'OpenSSH Server' optional feature)")
            return "OpenSSH/Operational", proc.stdout.splitlines(), ""
        proc = subprocess.run(
            ["journalctl", "-u", "ssh", "-u", "sshd", "--since", f"-{minutes}min", "-o", "cat", "--no-pager"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return "journald (ssh)", proc.stdout.splitlines(), ""
        if os.path.exists("/var/log/auth.log"):
            with open("/var/log/auth.log", errors="replace") as f:
                lines = f.readlines()[-5000:]
            return "/var/log/auth.log", lines, "auth.log is not time-filtered: last 5000 lines"
        return "none", [], "no SSH log source found"
    except Exception as e:
        return "error", [], f"could not read auth logs: {e}"
