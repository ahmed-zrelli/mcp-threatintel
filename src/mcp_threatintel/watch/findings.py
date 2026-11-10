"""Turn a scan_host report into findings, and remember which ones were already alerted."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    kind: str                      # c2_connection | malicious_dns | malicious_file | malicious_process | ssh_*
    key: str                       # stable identity, used to alert only once
    title: str
    detail: dict
    severity: str = "high"
    plan: list[tuple[str, dict]] = field(default_factory=list)  # (MCP tool, arguments)


def _source(matches: list[dict]) -> str:
    parts = []
    for m in matches or []:
        bits = [m.get("source") or "?"]
        for k in ("malware_family", "pulse", "threat_type", "comment"):
            if m.get(k):
                bits.append(str(m[k])[:50])
                break
        parts.append(" ".join(bits))
    return ", ".join(dict.fromkeys(parts)) or "known IOC"


def _is_ip(value: str) -> bool:
    return value.count(".") == 3 and all(p.isdigit() for p in value.split("."))


def extract_findings(report: dict) -> list[Finding]:
    """Findings from a scan_host result, each with the rule-based actions to propose."""
    out: list[Finding] = []

    for c in (report.get("connections") or {}).get("malicious") or []:
        ip, pid, proc = c.get("remote_ip"), c.get("pid"), c.get("process") or "unknown process"
        src = _source(c.get("ioc_matches"))
        when = "" if c.get("active", True) else f" ({c.get('last_seen_s_ago', '?')} s ago)"
        reason = f"Connection from {proc} (PID {pid}) to {ip}:{c.get('remote_port')}{when}, IOC: {src}"
        f = Finding("c2_connection", f"conn:{ip}:{pid}",
                    f"C2 connection: {proc} (PID {pid}) -> {ip}:{c.get('remote_port')}{when}",
                    {**c, "ioc": src}, "critical")
        if pid and c.get("active", True):
            f.plan.append(("kill_process", {"pid": int(pid), "reason": reason}))
        f.plan.append(("block_ip", {"ip": ip, "reason": reason}))
        out.append(f)

    for d in (report.get("dns") or {}).get("malicious") or []:
        dom = d.get("domain")
        src = _source(d.get("ioc_matches"))
        out.append(Finding(
            "malicious_dns", f"dns:{dom}",
            f"Malicious domain resolved: {dom} ({d.get('lookups')}x)",
            {**d, "ioc": src}, "high",
            [("sinkhole_domain", {"domain": dom, "reason": f"The server resolved {dom} "
                                  f"{d.get('lookups')} time(s); listed by {src}"})],
        ))

    for m in (report.get("files") or {}).get("malicious") or []:
        path, digest = m.get("path"), m.get("sha256", "")
        src = _source(m.get("ioc_matches"))
        out.append(Finding(
            "malicious_file", f"file:{digest}:{path}",
            f"Malicious file: {os.path.basename(path or '?')}",
            {**m, "ioc": src}, "high",
            [("quarantine_file", {"path": path, "reason": f"{m.get('matched_hash', 'sha256').upper()} "
                                  f"of the file matches {src}"})],
        ))

    for p in (report.get("processes") or {}).get("malicious") or []:
        pid, name = p.get("pid"), p.get("process") or "process"
        inds = p.get("indicators") or []
        what = ", ".join(i["value"] for i in inds[:2])
        src = _source([m for i in inds for m in i.get("ioc_matches", [])])
        reason = f"{name} (PID {pid}) command line references {what} ({src})"
        f = Finding("malicious_process", f"proc:{pid}:{what}",
                    f"Malicious command line: {name} (PID {pid}) -> {what}",
                    {**p, "ioc": src}, "critical", [("kill_process", {"pid": int(pid), "reason": reason})])
        for i in inds:
            value = i["value"]
            if i["type"] == "url":
                value = urlsplit(value).hostname or ""
            if _is_ip(value):
                f.plan.append(("block_ip", {"ip": value, "reason": reason}))
            elif value:
                f.plan.append(("sinkhole_domain", {"domain": value, "reason": reason}))
        out.append(f)

    auth = report.get("auth_logs") or {}
    for d in auth.get("details") or []:
        ip = d.get("ip")
        users = ", ".join(d.get("users_tried") or [])
        if d.get("known_malicious") and d.get("accepted"):
            kind, sev = "ssh_login_from_malicious_ip", "critical"
            title = f"SUCCESSFUL SSH login from known-malicious IP {ip} (users: {users})"
        elif d.get("brute_force"):
            kind, sev = "ssh_bruteforce", "high"
            title = f"SSH brute force from {ip} ({d.get('failures')} failures)"
        elif d.get("known_malicious") and d.get("failures"):
            kind, sev = "ssh_attempt_from_malicious_ip", "medium"
            title = f"SSH login attempts from known-malicious IP {ip} ({d.get('failures')} failures)"
        else:
            continue
        reason = (f"{d.get('failures')} failed / {d.get('accepted')} successful SSH logins from {ip} "
                  f"(users: {users})" + (f", IOC: {_source(d.get('ioc_matches'))}" if d.get("known_malicious") else ""))
        out.append(Finding(kind, f"{kind}:{ip}", title, d, sev, [("block_ip", {"ip": ip, "reason": reason})]))

    out.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
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
