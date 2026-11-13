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
        # Many failed logins are evidence by themselves: a LAN attacker may be blocked too (not the allowlist).
        plan = {"ip": ip, "reason": reason} | ({"behavior": True} if kind == "ssh_bruteforce" else {})
        out.append(Finding(kind, f"{kind}:{ip}", title, d, sev, [("block_ip", plan)]))

    out += behavior_findings(report.get("behavior") or {})
    out.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return out


ACCOUNT_TITLES = {
    "user_added": "New account created: {user} (uid {uid}, shell {shell})",
    "uid_set_to_0": "Account {user} now has uid 0 (root privileges)",
    "login_shell_enabled": "Login shell enabled for system account {user} ({shell})",
    "user_removed": "Account removed: {user}",
    "privileged_group_member_added": "{user} added to privileged group {group}",
    "password_changed": "Password changed for {user}",
    "sudoers_added": "New sudoers file: {path}",
    "sudoers_modified": "sudoers changed: {path}",
    "ssh_key_added": "SSH key added to {user}'s authorized_keys ({key})",
}
LOCK_ON = {"user_added", "uid_set_to_0", "login_shell_enabled", "privileged_group_member_added", "ssh_key_added"}


def behavior_findings(b: dict) -> list[Finding]:
    """Attacks found by behavior rather than by a feed (see responder/behavior.py)."""
    out: list[Finding] = []
    for s in b.get("port_scans") or []:
        ip = s["src_ip"]
        reason = f"{ip} probed {s['distinct_ports']} different ports in {s['window_s']:.0f} s"
        allow = s.get("allowlisted")
        f = Finding("port_scan", f"portscan:{ip}",
                    f"Port scan from {ip}: {s['distinct_ports']} ports in {s['window_s']:.0f} s"
                    + (" (allowlisted source, not blocked)" if allow else ""), s, "medium" if allow else "high")
        if not allow:
            f.plan.append(("block_ip", {"ip": ip, "behavior": True, "reason": reason}))
        out.append(f)

    for r in b.get("reverse_shells") or []:
        pid, name, ip = r["pid"], r.get("process") or "?", r["remote_ip"]
        reason = f"{name} (PID {pid}) has its input/output connected to {ip}:{r['remote_port']} (reverse shell)"
        out.append(Finding("reverse_shell", f"revshell:{pid}",
                           f"REVERSE SHELL: {name} (PID {pid}, user {r.get('user')}) -> {ip}:{r['remote_port']}",
                           r, "critical", [("kill_process", {"pid": int(pid), "reason": reason}),
                                           ("block_ip", {"ip": ip, "behavior": True, "reason": reason})]))

    for p in b.get("suspicious_processes") or []:
        pid, name = p["pid"], p.get("process") or "?"
        why = "; ".join(p.get("reasons") or [])
        out.append(Finding("suspicious_process", f"susproc:{pid}",
                           f"Suspicious process: {name} (PID {pid}, user {p.get('user')}): {why}",
                           p, "high", [("kill_process", {"pid": int(pid), "reason": f"{name} (PID {pid}): {why}; "
                                                         f"command: {p.get('cmdline', '')[:150]}"})]))

    for n in b.get("new_listeners") or []:
        title = (f"New listening port {n['address']}:{n['port']} opened by {n['process']} (PID {n['pid']})"
                 + (" during a package installation" if n.get("during_package_install") else ""))
        f = Finding("new_listener", f"listen:{n['key']}", title, n, n.get("severity", "high"))
        if n.get("pid") and not n.get("during_package_install") and n["severity"] != "medium":
            f.plan.append(("kill_process", {"pid": int(n["pid"]), "reason": f"{title}; not in the baseline of "
                                            f"known listening services (backdoor / bind shell?)"}))
        out.append(f)

    for c in b.get("account_changes") or []:
        title = ACCOUNT_TITLES.get(c["change"], c["change"]).format_map(_Default(c))
        if c.get("during_package_install"):
            title += " (during a package installation)"
        ident = c.get("fingerprint") or c.get("group") or c.get("path") or ""
        f = Finding(f"account_{c['change']}", f"account:{c['change']}:{c.get('user') or ''}:{ident}",
                    title, c, c.get("severity", "high"))
        if c["change"] in LOCK_ON and c.get("user") and not c.get("during_package_install"):
            f.plan.append(("lock_user", {"user": c["user"], "reason": title}))
        out.append(f)

    for c in b.get("integrity_changes") or []:
        what = "created" if c["change"] == "file_added" else "modified"
        title = f"System file {what}: {c['path']}" + (" (persistence location)" if c.get("persistence") else "")
        if c.get("during_package_install"):
            title += " during a package installation"
        f = Finding("integrity_" + c["change"], f"integrity:{c['path']}:{c['sha256'][:16]}", title, c,
                    c.get("severity", "medium"))
        if (c.get("persistence") and (c["change"] == "file_added" or c["path"] == "/etc/ld.so.preload")
                and not c.get("during_package_install")):
            added = "; ".join(c.get("added_lines") or [])[:200]
            f.plan.append(("quarantine_file", {"path": c["path"], "behavior": True,
                                               "reason": f"{title}; content: {added or '(binary)'}"}))
        out.append(f)
    return out


class _Default(dict):
    def __missing__(self, key):
        return "?"


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
