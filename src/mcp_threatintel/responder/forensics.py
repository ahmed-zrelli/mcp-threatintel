"""Read-only investigation of the host (used by alerts and by the model).

    inspect_process(pid)     parent chain, executable + hash, user, start time,
                             command line, connections, open files, children
    inspect_file(path)       hashes + feed matches, type, owner, mode, times,
                             processes running or holding it
    ip_activity(ip)          feed matches, live + sampled connections, DNS answers,
                             SSH activity, actions on that IP
    domain_activity(domain)  feed matches, DNS lookups + answers, processes that
                             mention it, /etc/hosts sinkhole, actions
    related_iocs(indicator)  campaign pivot: the OTX pulses / malware family of
                             the indicator, their other IOCs, and which of those
                             are ALSO present on this host

Nothing is modified. Every list is capped so results fit a small model's context.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .scanner import HostScanner, hash_file
from .store import ResponderDB
from .validators import ValidationError, validate_domain, validate_ip

CAP = 10
FORBIDDEN_PREFIXES = ("/proc", "/sys", "/dev")


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def _short(cmd: list[str] | None, n: int = 200) -> str:
    return " ".join(cmd or [])[:n]


class Forensics:
    def __init__(self, scanner: HostScanner, db: ResponderDB):
        self.scanner = scanner
        self.iocs = scanner.iocs
        self.db = db

    def change_origin(self, terms: list[str], tools: tuple = ()) -> dict:
        from .validators import Allowlist
        cfg = getattr(self.scanner, "config", None)
        return change_origin(terms, allowlist=Allowlist(self.db.load_allowlist()),
                             admins=tuple(getattr(cfg, "protected_users", ()) or ()), tools=tools)

    # --- processes ----------------------------------------------------------

    def inspect_process(self, pid) -> dict:
        try:
            pid = int(pid)
            p = psutil.Process(pid)
        except (ValueError, TypeError):
            raise ValidationError(f"not a PID: {pid!r}") from None
        except psutil.NoSuchProcess:
            return {"pid": pid, "running": False, "note": "process has exited"}
        info: dict = {"pid": pid, "running": True}
        with p.oneshot():
            for key, fn in (("name", p.name), ("exe", p.exe), ("cmdline", lambda: _short(p.cmdline(), 400)),
                            ("user", p.username), ("cwd", p.cwd), ("status", p.status)):
                try:
                    info[key] = fn()
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    info[key] = None
            info["started"] = _iso(p.create_time())
            info["running_for_s"] = int(time.time() - p.create_time())
        chain, cur = [], p
        for _ in range(6):
            try:
                cur = cur.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            if cur is None:
                break
            try:
                chain.append({"pid": cur.pid, "name": cur.name(), "cmdline": _short(cur.cmdline(), 120)})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        info["parent_chain"] = chain
        try:
            info["children"] = [{"pid": c.pid, "name": c.name()} for c in p.children(recursive=True)[:CAP]]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            info["children"] = []
        try:
            conns = p.net_connections(kind="inet")
            info["connections"] = [
                {"remote": f"{c.raddr.ip}:{c.raddr.port}", "status": c.status,
                 "ioc": bool(self.iocs.lookup("ip", c.raddr.ip))}
                for c in conns if c.raddr][:CAP]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info["connections"] = None
        try:
            info["open_files"] = [f.path for f in p.open_files()][:CAP]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info["open_files"] = None
        exe = info.get("exe")
        if exe and os.path.isfile(exe) and os.path.getsize(exe) <= 100 * 1024 * 1024:
            try:
                h = hash_file(Path(exe))
                info["exe_sha256"] = h["sha256"]
                info["exe_ioc_matches"] = next((m for m in (self.iocs.lookup("hash", v) for v in h.values()) if m), [])
            except OSError:
                pass
        info["deleted_executable"] = bool(exe and exe.endswith(" (deleted)"))
        return info

    # --- files --------------------------------------------------------------

    def inspect_file(self, path: str) -> dict:
        p = Path(str(path)).expanduser()
        if not p.is_absolute():
            raise ValidationError("give an absolute path")
        rp = str(p.resolve())
        if rp.startswith(FORBIDDEN_PREFIXES) and not rp.startswith("/dev/shm"):
            raise ValidationError("pseudo-filesystems are not inspected")
        if not p.exists():
            return {"path": str(p), "exists": False}
        st = p.stat()
        info: dict = {"path": rp, "exists": True, "size": st.st_size, "mode": stat.filemode(st.st_mode),
                      "modified": _iso(st.st_mtime), "changed": _iso(st.st_ctime), "accessed": _iso(st.st_atime)}
        try:
            import pwd
            info["owner"] = pwd.getpwuid(st.st_uid).pw_name
        except (ImportError, KeyError):
            info["owner"] = st.st_uid
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    head = f.read(64)
                info["type"] = _sniff(head)
                info["executable_bit"] = bool(st.st_mode & 0o111)
                if st.st_size <= 100 * 1024 * 1024:
                    h = hash_file(p)
                    info.update({f"{k}": v for k, v in h.items()})
                    info["ioc_matches"] = next((m for m in (self.iocs.lookup("hash", v) for v in h.values()) if m), [])
            except OSError as e:
                info["error"] = str(e)
        users = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                if proc.info.get("exe") == rp or any(f.path == rp for f in proc.open_files()):
                    users.append({"pid": proc.info["pid"], "name": proc.info["name"]})
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            if len(users) >= CAP:
                break
        info["used_by_processes"] = users
        return info

    # --- IPs and domains ----------------------------------------------------

    def ip_activity(self, ip: str, hours: int = 24) -> dict:
        try:
            ip = validate_ip(ip, allow_private=True)
        except ValidationError:
            raise
        now = time.time()
        conns = []
        if self.scanner.sampler:
            for (rip, rport, pid), r in self.scanner.sampler.seen.recent(3600, now):
                if rip == ip:
                    conns.append({"port": rport, "pid": pid, "process": r.get("process"), "count": r["count"],
                                  "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"])})
        dns = []
        if self.scanner.dns:
            dns = [{"domain": d, "lookups": r["count"], "last_seen": _iso(r["last_seen"])}
                   for d, r in self.scanner.dns.seen.recent(3600, now) if ip in (r.get("answers") or [])]
        ssh = next((d for d in self.scanner.scan_auth_logs(hours * 60).get("details", []) if d["ip"] == ip), None)
        return {"ip": ip, "ioc_matches": self.iocs.lookup("ip", ip), "connections_last_hour": conns[:CAP],
                "resolved_from_domains": dns[:CAP], "ssh_last_hours": ssh, "actions": self._actions(ip)}

    def domain_activity(self, domain: str) -> dict:
        domain = validate_domain(domain)
        now = time.time()
        lookups = []
        if self.scanner.dns:
            lookups = [{"name": d, "lookups": r["count"], "answers": r.get("answers", []),
                        "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"])}
                       for d, r in self.scanner.dns.seen.recent(3600, now)
                       if d == domain or d.endswith("." + domain)]
        procs = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            cmd = " ".join(proc.info.get("cmdline") or [])
            if domain in cmd.lower():
                procs.append({"pid": proc.info["pid"], "name": proc.info["name"], "cmdline": cmd[:200]})
            if len(procs) >= CAP:
                break
        hosts = self.scanner.config.hosts_path
        try:
            sinkholed = any(domain in line and "threatintel" in line for line in hosts.read_text().splitlines())
        except OSError:
            sinkholed = None
        return {"domain": domain, "ioc_matches": self.iocs.lookup_domain(domain), "dns_last_hour": lookups[:CAP],
                "processes_mentioning_it": procs, "sinkholed_in_hosts": sinkholed, "actions": self._actions(domain)}

    def _actions(self, target: str) -> list[dict]:
        out = []
        for status in ("pending", "approved", "executed", "rolled_back", "expired", "rejected"):
            for a in self.db.list_actions(status, limit=200):
                if target in a["target"] or target in (a["params"].get("ips") or []):
                    out.append({"id": a["id"], "type": a["type"], "status": a["status"], "created": a["created_at"]})
        return out[:CAP]

    # --- campaign pivot -----------------------------------------------------

    def related_iocs(self, indicator: str) -> dict:
        rel = self.iocs.related(indicator.strip())
        present_ips, present_domains, present_hashes = self._host_observables()
        found = []
        for r in rel["related"]:
            v, k = r["value"], r["type"]
            if (k == "ip" and v in present_ips) or (k == "domain" and v in present_domains) \
                    or (k == "hash" and v.lower() in present_hashes):
                found.append(r)
        return {"indicator": indicator, "pulses": rel["pulses"][:CAP], "malware_families": rel["families"][:CAP],
                "related_count": len(rel["related"]), "related_sample": rel["related"][:CAP],
                "related_present_on_host": found[:CAP],
                "note": "related_present_on_host lists other indicators of the same campaign/family seen here"}

    def _host_observables(self) -> tuple[set, set, set]:
        ips, domains, hashes = set(), set(), set()
        try:
            ips.update(c.raddr.ip for c in psutil.net_connections(kind="inet") if c.raddr)
        except (psutil.AccessDenied, OSError):
            pass
        if self.scanner.sampler:
            ips.update(k[0] for k, _ in self.scanner.sampler.seen.recent(3600))
        if self.scanner.dns:
            for d, r in self.scanner.dns.seen.recent(3600):
                domains.add(d)
                ips.update(r.get("answers") or [])
        for _size, _mtime, h in self.scanner._hash_cache.values():
            hashes.update(v.lower() for v in h.values())
        return ips, domains, hashes


def _sniff(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head.startswith(b"MZ"):
        return "Windows PE executable"
    if head.startswith(b"#!"):
        return "script: " + head.split(b"\n")[0][:60].decode(errors="replace")
    if head.startswith(b"PK"):
        return "ZIP/JAR/Office archive"
    if head[:4] in (b"%PDF",):
        return "PDF"
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


_SUDO = re.compile(r"sudo\[\d+\]:\s+(\S+) : (?:.*?TTY=(\S+) ; )?.*?USER=(\S+) ; COMMAND=(.+)$")
_FROM_TTY = re.compile(r"from=/dev/(\S+)")
_PROG = re.compile(r"\s([\w.-]+)\[\d+\]:")
_ADMIN_TOOLS = ("sudo", "su", "useradd", "usermod", "userdel", "groupadd", "groupmod", "gpasswd", "passwd",
                "chpasswd", "chsh", "adduser", "deluser")


def _run(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


#: For each account change, the tools that can make it (a later userdel/cleanup is not who made it).
CHANGE_TOOLS = {
    "account_user_added": ("useradd", "adduser"),
    "account_uid_set_to_0": ("usermod", "vipw"),
    "account_login_shell_enabled": ("usermod", "chsh"),
    "account_privileged_group_member_added": ("usermod", "gpasswd", "adduser"),
    "account_password_changed": ("passwd", "chpasswd", "usermod"),
}


def change_origin(terms: list[str], *, allowlist=None, admins: tuple = (), minutes: int = 30,
                  journal: str | None = None, logins: str | None = None, tools: tuple = ()) -> dict:
    """Who made an account / system-file change: the matching admin-tool and sudo log lines, the user who
    ran them, and the SSH login (IP) of that terminal. Facts only, from the system log and `last`."""
    terms = [t for t in terms if t]
    if journal is None:
        args = ["journalctl", "--since", f"-{minutes}min", "-o", "short-iso", "--no-pager"]
        for t in _ADMIN_TOOLS:
            args += ["-t", t]
        journal = _run(args)
    if logins is None:
        logins = _run(["last", "-i", "-w", "-n", "200"])
    lines = [ln for ln in journal.splitlines() if any(t in ln for t in terms)]
    if tools:   # only the tools that can make this kind of change
        lines = [ln for ln in lines if any(f" {tool}[" in ln or f"/{tool} " in ln or ln.rstrip().endswith(f"/{tool}")
                                           for tool in tools)]
    tty_ip: dict[tuple, str] = {}
    for ln in logins.splitlines():   # "ahmed pts/0 192.168.21.1 Fri Nov 13 08:30 still logged in"
        f = ln.split()
        if len(f) >= 3 and f[1].startswith(("pts/", "tty")):
            tty_ip.setdefault((f[0], f[1]), f[2])
            tty_ip.setdefault(("*", f[1]), f[2])
    made_by = []
    for ln in lines:
        m = _SUDO.search(ln)
        if m:
            user, tty, as_user, cmd = m.group(1), (m.group(2) or "").replace("/dev/", ""), m.group(3), m.group(4)
            if not any(t in cmd for t in terms):
                continue   # a sudo command about something else
            entry = {"user": user, "via": f"sudo (as {as_user})", "tty": tty or None, "command": cmd[:200]}
        else:
            t = _FROM_TTY.search(ln)
            if not t:
                continue
            prog = _PROG.search(ln)
            entry = {"user": None, "via": f"{prog.group(1) if prog else 'admin tool'} run directly as root (no sudo trace)",
                     "tty": t.group(1)}
        ip = tty_ip.get((entry["user"] or "*", entry["tty"] or "")) or tty_ip.get(("*", entry["tty"] or ""))
        entry["from_ip"] = None if ip in (None, "0.0.0.0", ":0") else ip
        if entry["from_ip"] and allowlist is not None:
            try:
                entry["from_allowlisted"] = allowlist.check_ip(entry["from_ip"])
            except ValueError:
                entry["from_allowlisted"] = None
        entry["known_admin"] = bool(entry["user"] and entry["user"] in admins and entry["user"] != "root")
        if entry not in made_by:
            made_by.append(entry)
    note = None if made_by else ("no record of who made this change in the system log (direct file edit, "
                                 "a process already running as root, or logs tampered with)")
    return {"log_lines": [ln[:220] for ln in lines[-8:]], "made_by": made_by[:5], "note": note}


def collect_evidence(fx: Forensics, kind: str, detail: dict) -> dict:
    """What an analyst would look at first for each alert type (captured at alert time)."""
    ev: dict = {}

    def safe(name, fn, *a):
        try:
            ev[name] = fn(*a)
        except Exception as e:  # evidence is best-effort, never blocks an alert
            ev[name] = {"error": str(e)}

    if kind == "c2_connection":
        if detail.get("pid"):
            safe("process", fx.inspect_process, detail["pid"])
        safe("ip", fx.ip_activity, detail.get("remote_ip"))
        safe("campaign", fx.related_iocs, detail.get("remote_ip"))
    elif kind == "malicious_dns":
        safe("domain", fx.domain_activity, detail.get("domain"))
        for i, ip in enumerate((detail.get("answers") or [])[:2]):
            safe(f"answer_ip_{i}", fx.ip_activity, ip)
        safe("campaign", fx.related_iocs, detail.get("domain"))
    elif kind == "malicious_file":
        safe("file", fx.inspect_file, detail.get("path"))
        safe("campaign", fx.related_iocs, detail.get("sha256"))
    elif kind == "malicious_process":
        safe("process", fx.inspect_process, detail.get("pid"))
        first = (detail.get("indicators") or [{}])[0]
        if first.get("value"):
            safe("campaign", fx.related_iocs, first["value"])
    elif kind.startswith("ssh_"):
        safe("ip", fx.ip_activity, detail.get("ip"))
        safe("campaign", fx.related_iocs, detail.get("ip"))
    elif kind.startswith(("account_", "integrity_")):
        # Who did it, from where: the deciding fact for a change an admin could also have made.
        term = detail.get("user") or detail.get("path")
        safe("change_origin", fx.change_origin, [term] if term else [], CHANGE_TOOLS.get(kind, ()))
    elif kind in ("new_listener", "suspicious_process", "reverse_shell"):
        if detail.get("pid"):
            safe("process", fx.inspect_process, detail["pid"])
        if detail.get("remote_ip"):
            safe("ip", fx.ip_activity, detail["remote_ip"])
    return ev
