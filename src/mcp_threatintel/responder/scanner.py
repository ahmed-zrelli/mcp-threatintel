"""HostScanner: read-only inspection of the host, cross-checked with the IOC cache.

Nothing here modifies the machine. Results are capped (config.max_results) so
a scan never floods the model's context window.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import psutil

from .backends.quarantine import sha256_file
from .config import ResponderConfig
from .iocs import IocIndex
from .validators import ValidationError, validate_path

logger = logging.getLogger("threatintel.responder.scanner")

MAX_FILES = 500
MAX_FILE_BYTES = 100 * 1024 * 1024

# OpenSSH writes the same messages on Linux (auth.log/journald) and Windows
# (OpenSSH/Operational event log), so one parser serves both.
_FAILED = re.compile(
    r"(?:Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+)"
    r"|Invalid user (?P<user2>\S+)) from (?P<ip>[0-9a-fA-F:.]+)"
)


def parse_auth_lines(lines) -> dict[str, dict]:
    """Count failed SSH authentications per source IP."""
    per_ip: dict[str, dict] = defaultdict(lambda: {"failures": 0, "users": set()})
    for line in lines:
        m = _FAILED.search(line)
        if not m:
            continue
        ip = m.group("ip")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        entry = per_ip[ip]
        entry["failures"] += 1
        entry["users"].add(m.group("user") or m.group("user2"))
    return per_ip


class HostScanner:
    def __init__(self, config: ResponderConfig, iocs: IocIndex):
        self.config = config
        self.iocs = iocs

    # --- network ------------------------------------------------------------

    def scan_connections(self) -> dict:
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            conns.append(c)
        remote_ips = [c.raddr.ip for c in conns]
        matches = self.iocs.match(remote_ips)
        hits = []
        for c in conns:
            if c.raddr.ip not in matches:
                continue
            hits.append({
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
                "local_port": c.laddr.port if c.laddr else None,
                "status": c.status,
                "pid": c.pid,
                "process": _proc_name(c.pid),
                "ioc_matches": matches[c.raddr.ip],
            })
        return {
            "connections_checked": len(conns),
            "unique_remote_ips": len(set(remote_ips)),
            "malicious_count": len(hits),
            "malicious": hits[: self.config.max_results],
            "truncated": len(hits) > self.config.max_results,
            "ioc_cache_available": self.iocs.available,
        }

    # --- files --------------------------------------------------------------

    def scan_files(self, path: str = "") -> dict:
        roots = [validate_path(path, self.config.scan_paths)] if path else [
            p for p in self.config.scan_paths if p.exists()
        ]
        if not roots:
            raise ValidationError("no directory to scan: set SCAN_PATHS")
        hashes: dict[str, list[dict]] = defaultdict(list)
        scanned = skipped = 0
        for root in roots:
            for file in _walk(root):
                if scanned >= MAX_FILES:
                    break
                try:
                    size = file.stat().st_size
                    if size > MAX_FILE_BYTES:
                        skipped += 1
                        continue
                    digest = sha256_file(file)
                except OSError:
                    skipped += 1
                    continue
                scanned += 1
                hashes[digest].append({"path": str(file), "size": size})
        matches = self.iocs.match(list(hashes))
        hits = [
            {**f, "sha256": digest, "ioc_matches": matches[digest]}
            for digest in matches for f in hashes[digest]
        ]
        return {
            "scanned_paths": [str(r) for r in roots],
            "files_scanned": scanned,
            "files_skipped": skipped,
            "limit_reached": scanned >= MAX_FILES,
            "malicious_count": len(hits),
            "malicious": hits[: self.config.max_results],
            "truncated": len(hits) > self.config.max_results,
        }

    # --- authentication logs ------------------------------------------------

    def scan_auth_logs(self, minutes: int = 60) -> dict:
        minutes = max(1, min(int(minutes), 7 * 24 * 60))
        source, lines, note = _read_auth_logs(minutes)
        per_ip = parse_auth_lines(lines)
        threshold = self.config.auth_fail_threshold
        ranked = sorted(per_ip.items(), key=lambda kv: kv[1]["failures"], reverse=True)
        matches = self.iocs.match([ip for ip, _ in ranked])
        suspects = [
            {
                "ip": ip,
                "failures": d["failures"],
                "users_tried": sorted(d["users"])[:10],
                "brute_force": d["failures"] >= threshold,
                "ioc_matches": matches.get(ip, []),
            }
            for ip, d in ranked
        ]
        return {
            "log_source": source,
            "note": note,
            "minutes": minutes,
            "threshold": threshold,
            "lines_read": len(lines),
            "sources_with_failures": len(suspects),
            "brute_force_ips": [s["ip"] for s in suspects if s["brute_force"]],
            "details": suspects[: self.config.max_results],
        }

    # --- aggregate ----------------------------------------------------------

    def scan_host(self, minutes: int = 60) -> dict:
        report: dict = {}
        suggestions: list[str] = []
        for name, fn in (("connections", self.scan_connections),
                         ("files", self.scan_files),
                         ("auth_logs", lambda: self.scan_auth_logs(minutes))):
            try:
                report[name] = fn()
            except Exception as e:  # one failing scan must not hide the others
                report[name] = {"error": str(e)}
        for c in report["connections"].get("malicious", []):
            suggestions.append(f"block_ip ip={c['remote_ip']} (connection from {c['process']} PID {c['pid']})")
            if c.get("pid"):
                suggestions.append(f"kill_process pid={c['pid']} ({c['process']})")
        for f in report["files"].get("malicious", []):
            suggestions.append(f"quarantine_file path={f['path']}")
        for ip in report["auth_logs"].get("brute_force_ips", []):
            suggestions.append(f"block_ip ip={ip} (SSH brute force)")
        report["suggested_actions"] = suggestions[: self.config.max_results]
        report["findings"] = len(suggestions)
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
