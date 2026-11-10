"""Turn a scan_host report into findings, and remember which ones were already alerted."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    kind: str                      # c2_connection | malicious_file | ssh_bruteforce
    key: str                       # stable identity, used to alert only once
    title: str
    detail: dict
    plan: list[tuple[str, dict]] = field(default_factory=list)  # (MCP tool, arguments)


def _source(matches: list[dict]) -> str:
    parts = []
    for m in matches or []:
        bits = [m.get("source") or "?"]
        for k in ("malware_family", "threat_type", "comment"):
            if m.get(k):
                bits.append(str(m[k]))
                break
        parts.append(" ".join(bits))
    return ", ".join(dict.fromkeys(parts)) or "known IOC"


def extract_findings(report: dict) -> list[Finding]:
    """Findings from a scan_host result, each with the rule-based actions to propose."""
    out: list[Finding] = []
    for c in (report.get("connections") or {}).get("malicious") or []:
        ip, pid, proc = c.get("remote_ip"), c.get("pid"), c.get("process") or "unknown process"
        src = _source(c.get("ioc_matches"))
        f = Finding(
            kind="c2_connection",
            key=f"conn:{ip}:{pid}",
            title=f"C2 connection: {proc} (PID {pid}) -> {ip}:{c.get('remote_port')}",
            detail={**c, "ioc": src},
        )
        reason = f"Active connection from {proc} (PID {pid}) to {ip}:{c.get('remote_port')}, IOC: {src}"
        if pid:
            f.plan.append(("kill_process", {"pid": int(pid), "reason": reason}))
        f.plan.append(("block_ip", {"ip": ip, "reason": reason}))
        out.append(f)
    for m in (report.get("files") or {}).get("malicious") or []:
        path, digest = m.get("path"), m.get("sha256", "")
        src = _source(m.get("ioc_matches"))
        name = os.path.basename(path or "?")
        out.append(Finding(
            kind="malicious_file",
            key=f"file:{digest}:{path}",
            title=f"Malicious file: {name}",
            detail={**m, "ioc": src},
            plan=[("quarantine_file", {"path": path, "reason": f"SHA-256 {digest[:16]}... matches {src}"})],
        ))
    for d in (report.get("auth_logs") or {}).get("details") or []:
        if not d.get("brute_force"):
            continue
        ip = d.get("ip")
        users = ", ".join(d.get("users_tried") or [])
        out.append(Finding(
            kind="ssh_bruteforce",
            key=f"brute:{ip}",
            title=f"SSH brute force from {ip} ({d.get('failures')} failures)",
            detail=d,
            plan=[("block_ip", {"ip": ip, "reason": f"{d.get('failures')} failed SSH logins from {ip} (users: {users})"})],
        ))
    return out


class SeenStore:
    """Keys already alerted, forgotten after ``ttl_s`` so a later attack alerts again."""

    def __init__(self, path: Path | None, ttl_s: float = 6 * 3600, clock=time.time):
        self.path = path
        self.ttl_s = ttl_s
        self.clock = clock
        self._seen: dict[str, float] = {}
        if path and path.exists():
            try:
                self._seen = {k: float(v) for k, v in json.loads(path.read_text()).items()}
            except (ValueError, OSError):
                self._seen = {}

    def new_only(self, findings: list[Finding]) -> list[Finding]:
        now = self.clock()
        self._seen = {k: t for k, t in self._seen.items() if now - t < self.ttl_s}
        fresh = [f for f in findings if f.key not in self._seen]
        for f in fresh:
            self._seen[f.key] = now
        if fresh:
            self._save()
        return fresh

    def _save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._seen))
        except OSError:
            pass
