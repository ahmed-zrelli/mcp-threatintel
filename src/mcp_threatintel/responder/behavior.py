"""Behavior detection: attacks that are in no threat feed.

  * port scan        - many distinct destination ports from one source in a few
                       seconds (kernel log of new inbound TCP SYNs, see the
                       "ti-syn" rule in deploy/threatintel.nft)
  * reverse shell    - a shell/interpreter whose stdin/stdout/stderr is a network
                       socket, or command lines typical of one (/dev/tcp, nc -e,
                       curl | sh ...), or a program executing from a temp folder
  * new listener     - a TCP port listening that was not in the baseline
  * account changes  - new user, uid 0 account, new member of a privileged group,
                       password change, sudoers change, new SSH authorized key
  * file integrity   - persistence and system files created or modified (cron,
                       systemd units, ld.so.preload, rc.local, profile, sshd/pam)

Baselines (accounts, files, listeners) are stored in responder.db, so a change
made while the agent was stopped is still reported at the next start. Changes
made while the package manager runs are reported as low severity.

Every function returns plain dicts (report fragments) consumed by
responder/findings.py. Nothing here modifies the machine.
"""

from __future__ import annotations

import glob
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

import psutil

IS_LINUX = sys.platform.startswith("linux")

# --- port scan -------------------------------------------------------------------

_SYN = re.compile(r"ti-syn .*?SRC=(?P<src>[0-9a-fA-F:.]+) .*?DPT=(?P<dpt>\d+)")


class PortScanDetector:
    """Distinct destination ports per source inside a sliding window."""

    def __init__(self, window_s: float = 10, threshold: int = 15):
        self.window_s = window_s
        self.threshold = threshold
        self.hits: dict[str, deque] = defaultdict(deque)
        self.status = "starting" if IS_LINUX else "unavailable (Linux nftables log only)"

    def feed(self, src: str, dport: int, now: float | None = None) -> dict | None:
        """Record one new inbound connection; return a scan record when the threshold is crossed."""
        now = now or time.time()
        try:
            if ipaddress.ip_address(src).is_loopback:
                return None
        except ValueError:
            return None
        q = self.hits[src]
        q.append((now, dport))
        while q and now - q[0][0] > self.window_s:
            q.popleft()
        ports = {p for _, p in q}
        if len(ports) >= self.threshold:
            record = {"src_ip": src, "distinct_ports": len(ports), "window_s": self.window_s,
                      "sample_ports": sorted(ports)[:20], "observed_at": now}
            q.clear()  # one record per burst; the next burst is a new observation
            return record
        return None

    def handle_line(self, line: str) -> dict | None:
        m = _SYN.search(line)
        if not m:
            return None
        return self.feed(m.group("src"), int(m.group("dpt")))


# --- reverse shells and suspicious processes -------------------------------------

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish", "ash", "busybox"}
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nc", "ncat", "netcat",
                "socat", "telnet", "openssl", "awk", "gawk"}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
_PATTERNS = [
    (re.compile(r"/dev/(tcp|udp)/"), "bash /dev/tcp redirection"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s"), "netcat executing a program"),
    (re.compile(r"socat\b.*exec:", re.I), "socat exec"),
    (re.compile(r"mkfifo\b.*\b(nc|ncat|netcat|telnet)\b"), "fifo-based shell"),
    (re.compile(r"\b(curl|wget)\b[^|]*\|\s*(ba|z|da)?sh\b"), "download piped to a shell"),
    (re.compile(r"base64\s+(-d|--decode)[^|]*\|\s*(ba|z|da)?sh\b"), "base64 payload piped to a shell"),
    (re.compile(r"socket\b.*\b(subprocess|pty\.spawn|os\.dup2)", re.S), "interpreter socket shell"),
]


def _base(name: str) -> str:
    return re.sub(r"\d+(\.\d+)*$", "", (name or "").lower()) or (name or "").lower()


def find_reverse_shells(conns=None, proc_lookup=None) -> list[dict]:
    """Shells/interpreters whose fd 0/1/2 is a connected inet socket (Linux exposes fd per connection)."""
    out = []
    conns = conns if conns is not None else psutil.net_connections(kind="inet")
    by_pid: dict[int, list] = defaultdict(list)
    for c in conns:
        if c.pid and c.raddr and getattr(c, "fd", -1) in (0, 1, 2):
            by_pid[c.pid].append(c)
    for pid, cs in by_pid.items():
        info = (proc_lookup or _proc_info)(pid)
        if not info or _base(info["name"]) not in SHELLS | INTERPRETERS:
            continue
        remote = cs[0].raddr
        try:
            if ipaddress.ip_address(remote.ip).is_loopback:
                continue
        except ValueError:
            continue
        out.append({**info, "remote_ip": remote.ip, "remote_port": remote.port,
                    "socket_fds": sorted({c.fd for c in cs}), "reason": "shell input/output is a network socket",
                    "observed_at": info.get("create_time") or time.time()})
    return out


def find_suspicious_processes(procs=None) -> list[dict]:
    """Command-line patterns of reverse shells / droppers, and programs executing from temp folders."""
    out = []
    for p in procs if procs is not None else psutil.process_iter(["pid", "name", "exe", "cmdline", "username",
                                                                    "create_time"]):
        i = p.info
        cmd = " ".join(i.get("cmdline") or [])
        exe = i.get("exe") or ""
        reasons = [label for rx, label in _PATTERNS if rx.search(cmd)]
        if exe.startswith(TEMP_DIRS):
            reasons.append(f"executable runs from a temp folder ({exe})")
        if reasons:
            out.append({"pid": i["pid"], "process": i.get("name"), "exe": exe, "user": i.get("username"),
                        "cmdline": cmd[:300], "reasons": reasons, "observed_at": i.get("create_time")})
    return out


def _proc_info(pid: int) -> dict | None:
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return {"pid": pid, "process": p.name(), "name": p.name(), "exe": _safe(p.exe),
                    "user": _safe(p.username), "cmdline": " ".join(_safe(p.cmdline) or [])[:300],
                    "create_time": p.create_time()}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _safe(fn):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return None


# --- listening ports --------------------------------------------------------------

def current_listeners(conns=None) -> dict[str, dict]:
    out = {}
    conns = conns if conns is not None else psutil.net_connections(kind="tcp")
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        info = _proc_info(c.pid) if c.pid else None
        name = (info or {}).get("name") or "?"
        key = f"tcp:{c.laddr.port}:{name}"
        out[key] = {"port": c.laddr.port, "address": c.laddr.ip, "pid": c.pid, "process": name,
                    "exe": (info or {}).get("exe"), "user": (info or {}).get("user")}
    return out


def new_listeners(baseline: set[str], current: dict[str, dict]) -> list[dict]:
    found = []
    for key, rec in current.items():
        if key in baseline:
            continue
        loopback = rec["address"] in ("127.0.0.1", "::1")
        sev = "critical" if (rec.get("exe") or "").startswith(TEMP_DIRS) else ("medium" if loopback else "high")
        found.append({**rec, "key": key, "severity": sev, "observed_at": time.time()})
    return found


# --- accounts ---------------------------------------------------------------------

PRIV_GROUPS = {"sudo": "critical", "admin": "critical", "wheel": "critical", "root": "critical",
               "docker": "high", "lxd": "high", "disk": "high", "shadow": "high"}
NO_LOGIN = ("nologin", "/bin/false", "/usr/bin/false", "sync", "halt", "shutdown")


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def account_snapshot(root: str = "/") -> dict:
    """users, privileged group members, password-hash fingerprints, sudoers, authorized SSH keys."""
    r = Path(root)
    users = {}
    for line in _lines(r / "etc/passwd"):
        f = line.split(":")
        if len(f) >= 7:
            users[f[0]] = {"uid": int(f[2]) if f[2].isdigit() else -1, "gid": f[3], "home": f[5], "shell": f[6]}
    groups = {}
    gid_name = {}
    for line in _lines(r / "etc/group"):
        f = line.split(":")
        if len(f) >= 4:
            gid_name[f[2]] = f[0]
            if f[0] in PRIV_GROUPS:
                groups[f[0]] = sorted(m for m in f[3].split(",") if m)
    for name, u in users.items():  # primary group membership counts too
        g = gid_name.get(u["gid"])
        if g in PRIV_GROUPS and name not in groups.setdefault(g, []) and g != "root" and name != g:
            groups[g] = sorted(groups[g] + [name])
    shadow = {}
    for line in _lines(r / "etc/shadow"):
        f = line.split(":")
        if len(f) >= 2:
            shadow[f[0]] = _h(f[1].encode())[:16]
    sudoers = {}
    for path in [r / "etc/sudoers", *sorted((r / "etc/sudoers.d").glob("*"))]:
        if path.is_file():
            try:
                sudoers[_rel(path, root)] = _h(path.read_bytes())[:16]
            except OSError:
                pass
    keys = {}
    for name, u in users.items():
        if u["uid"] != 0 and u["uid"] < 1000:
            continue
        home = Path(u["home"]) if root == "/" else r / u["home"].lstrip("/")
        ak = home / ".ssh/authorized_keys"
        entries = {}
        for line in _lines(ak):
            if line.strip() and not line.startswith("#"):
                parts = line.split()
                entries[_h(line.encode())[:16]] = parts[-1] if len(parts) >= 3 else "(no comment)"
        if entries:
            keys[name] = entries
    return {"users": users, "groups": groups, "shadow": shadow, "sudoers": sudoers, "keys": keys}


def diff_accounts(old: dict, new: dict) -> list[dict]:
    changes = []
    ou, nu = old.get("users", {}), new.get("users", {})
    for name, u in nu.items():
        if name not in ou:
            sev = "critical" if u["uid"] == 0 else ("high" if not u["shell"].endswith(NO_LOGIN) else "medium")
            changes.append({"change": "user_added", "user": name, "uid": u["uid"], "shell": u["shell"],
                            "severity": sev})
        else:
            if u["uid"] == 0 and ou[name]["uid"] != 0:
                changes.append({"change": "uid_set_to_0", "user": name, "severity": "critical"})
            if ou[name]["shell"].endswith(NO_LOGIN) and not u["shell"].endswith(NO_LOGIN):
                changes.append({"change": "login_shell_enabled", "user": name, "shell": u["shell"],
                                "severity": "high"})
    for name in ou:
        if name not in nu:
            changes.append({"change": "user_removed", "user": name, "severity": "low"})
    for g, members in new.get("groups", {}).items():
        for m in set(members) - set(old.get("groups", {}).get(g, [])):
            changes.append({"change": "privileged_group_member_added", "group": g, "user": m,
                            "severity": PRIV_GROUPS.get(g, "high")})
    for name, h in new.get("shadow", {}).items():
        before = old.get("shadow", {}).get(name)
        if before and before != h:
            sysacct = nu.get(name, {}).get("uid", 1000) < 1000
            changes.append({"change": "password_changed", "user": name,
                            "severity": "high" if sysacct else "medium"})
    for path, h in new.get("sudoers", {}).items():
        before = old.get("sudoers", {}).get(path)
        if before != h:
            changes.append({"change": "sudoers_added" if before is None else "sudoers_modified", "path": path,
                            "severity": "high"})
    for user, entries in new.get("keys", {}).items():
        for fp, comment in entries.items():
            if fp not in old.get("keys", {}).get(user, {}):
                changes.append({"change": "ssh_key_added", "user": user, "key": comment, "fingerprint": fp,
                                "severity": "critical" if nu.get(user, {}).get("uid") == 0 else "high"})
    return changes


def package_like_account_change(c: dict, snapshot: dict) -> bool:
    """What a package installation does to accounts: system accounts (uid < 1000) without a login
    shell, created, removed or re-passworded. Never a login user, a privileged group member, uid 0,
    a sudo rule or an SSH key — those stay at full severity even while apt runs."""
    if c["change"] not in ("user_added", "user_removed", "password_changed"):
        return False
    u = snapshot.get("users", {}).get(c.get("user"), {})
    if c["change"] == "user_removed":
        return True
    return 0 < u.get("uid", 1000) < 1000 and u.get("shell", "").endswith(NO_LOGIN)


def _lines(path: Path) -> list[str]:
    try:
        return path.read_text(errors="replace").splitlines()
    except OSError:
        return []


# --- file integrity ---------------------------------------------------------------

INTEGRITY_GLOBS = [
    "etc/crontab", "etc/cron.d/*", "etc/cron.hourly/*", "etc/cron.daily/*", "etc/cron.weekly/*",
    "etc/cron.monthly/*", "var/spool/cron/crontabs/*",
    "etc/systemd/system/*.service", "etc/systemd/system/*.timer", "etc/systemd/system/*/*.service",
    "etc/systemd/system/*/*.timer",
    "etc/ld.so.preload", "etc/rc.local", "etc/profile", "etc/profile.d/*", "etc/bash.bashrc",
    "root/.bashrc", "root/.profile", "etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*", "etc/pam.d/*",
    "etc/environment", "etc/ld.so.conf.d/*",
]
#: Folders a NEW file may be quarantined from (it disables the persistence; reversible).
PERSISTENCE_DIRS = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                    "/etc/cron.monthly", "/var/spool/cron/crontabs", "/etc/systemd/system", "/etc/profile.d",
                    "/etc/ld.so.preload", "/etc/rc.local"]
WATCH_DIRS = ["/etc", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
              "/etc/cron.monthly", "/var/spool/cron/crontabs", "/etc/systemd/system", "/etc/profile.d",
              "/etc/ssh", "/etc/ssh/sshd_config.d", "/etc/pam.d", "/etc/sudoers.d", "/root", "/root/.ssh"]


def _rel(path, root: str) -> str:
    """Absolute path as seen on the host ("/etc/..."), also when scanning a test root."""
    rel = os.path.relpath(str(path), root).replace("\\", "/")
    return "/" + rel.lstrip("/")


def integrity_files(root: str = "/") -> list[str]:
    files = []
    for pattern in INTEGRITY_GLOBS:
        files += [p for p in glob.glob(os.path.join(root, pattern)) if os.path.isfile(p)]
    return sorted(set(files))


def integrity_signature(root: str = "/") -> str:
    """Cheap fingerprint (names, sizes, mtimes): files are hashed again only when it changes."""
    parts = []
    for p in integrity_files(root):
        try:
            st = os.stat(p)
            parts.append(f"{p}|{st.st_size}|{st.st_mtime_ns}|{st.st_ino}")
        except OSError:
            continue
    return _h("\n".join(parts).encode())


def integrity_snapshot(root: str = "/") -> dict[str, dict]:
    out = {}
    for path in integrity_files(root):
        p = Path(path)
        try:
            if p.stat().st_size <= 5 * 1024 * 1024:
                data = p.read_bytes()
                out[_rel(p, root)] = {"sha256": _h(data), "size": len(data), "lines": _text_lines(data)}
        except OSError:
            continue
    return out


def _text_lines(data: bytes) -> list[str] | None:
    if b"\0" in data[:1024] or len(data) > 200_000:
        return None
    return data.decode(errors="replace").splitlines()[:2000]


def diff_integrity(old: dict, new: dict) -> list[dict]:
    changes = []
    for path, rec in new.items():
        before = old.get(path)
        if before and before["sha256"] == rec["sha256"]:
            continue
        added = [ln for ln in (rec.get("lines") or []) if ln not in set((before or {}).get("lines") or [])
                 and ln.strip() and not ln.lstrip().startswith("#")][:5]
        persistence = path.startswith(tuple(PERSISTENCE_DIRS)) or path in ("/etc/crontab",)
        if path == "/etc/ld.so.preload":
            sev = "critical"
        elif before is None and persistence:
            sev = "high"
        elif persistence or path.startswith(("/etc/pam.d", "/etc/ssh")):
            sev = "high"
        else:
            sev = "medium"
        changes.append({"change": "file_added" if before is None else "file_modified", "path": path,
                        "severity": sev, "persistence": persistence, "added_lines": [a[:200] for a in added],
                        "sha256": rec["sha256"]})
    return changes


def package_manager_active(procs=None) -> bool:
    """apt/dpkg is installing something right now. Ubuntu's unattended-upgrade-shutdown helper
    runs all the time (it only waits for shutdown) and does not count."""
    names = {"apt", "apt-get", "dpkg", "unattended-upgr", "unattended-upgrade", "aptitude"}
    for p in procs if procs is not None else psutil.process_iter(["name", "cmdline"]):
        if (p.info.get("name") or "") in names:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "unattended-upgrade-shutdown" in cmd:
                continue
            return True
    return False


def dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)


# --- the monitor run by the host agent ----------------------------------------------

KEEP_S = 3600
SECTIONS = ("port_scans", "reverse_shells", "suspicious_processes", "new_listeners", "account_changes",
            "integrity_changes")


class BehaviorMonitor:
    """Polls every few seconds (and follows the kernel log for port scans). Each detection is kept
    for an hour (scan_host reads it) and passed to ``on_event(section, record)`` at once."""

    def __init__(self, db, allowlist=None, *, root: str = "/", poll_s: float = 3.0,
                 enabled: bool | None = None, own_pids: set[int] | None = None):
        self.db = db
        self.allowlist = allowlist
        self.root = root
        self.poll_s = poll_s
        self.enabled = IS_LINUX if enabled is None else enabled
        self.portscan = PortScanDetector()
        self.on_event = None
        self.recent: deque = deque(maxlen=1000)   # (section, record)
        self._procs_seen: set[tuple] = set()
        self._sig: str | None = None
        self.own_pids = own_pids or {os.getpid()}
        self.status = "starting" if self.enabled else "unavailable (Linux only)"
        self.last_error: str | None = None

    # --- recording ---

    def emit(self, section: str, rec: dict) -> None:
        rec = {**rec, "observed_at": rec.get("observed_at") or time.time()}
        self.recent.append((section, rec))
        if self.on_event:
            try:
                self.on_event(section, rec)
            except Exception:  # never stop monitoring because of a callback
                pass

    def report(self, minutes: int = 60) -> dict:
        now = time.time()
        horizon = now - min(minutes * 60, KEEP_S)
        out: dict = {s: [] for s in SECTIONS}
        for section, rec in self.recent:
            if rec["observed_at"] >= horizon or section in ("suspicious_processes", "reverse_shells"):
                out[section].append(rec)
        out["monitor"] = self.status
        return out

    # --- baselines (persisted in responder.db settings) ---

    def _load(self, key: str):
        raw = self.db.get_setting(key)
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None

    def _save(self, key: str, value) -> None:
        self.db.set_setting(key, dumps(value), "behavior-monitor")

    def _pkg(self) -> bool:
        try:
            return package_manager_active()
        except Exception:
            return False

    def check_accounts(self) -> list[dict]:
        new = account_snapshot(self.root)
        old = self._load("baseline_accounts")
        self._save_if_changed("baseline_accounts", old, new)
        if old is None:
            return []
        changes = diff_accounts(old, new)
        pkg = self._pkg() if changes else False
        for c in changes:
            if pkg and package_like_account_change(c, new):
                c.update(severity="low", during_package_install=True)
            self.emit("account_changes", c)
        return changes

    def check_integrity(self, force: bool = False) -> list[dict]:
        sig = integrity_signature(self.root)
        if sig == self._sig and not force:
            return []
        self._sig = sig
        new = integrity_snapshot(self.root)
        old = self._load("baseline_integrity")
        self._save_if_changed("baseline_integrity", old, new)
        if old is None:
            return []
        changes = diff_integrity(old, new)
        pkg = self._pkg() if changes else False
        for c in changes:
            if pkg and c["path"] != "/etc/ld.so.preload":
                c.update(severity="low", during_package_install=True)
            self.emit("integrity_changes", c)
        return changes

    def check_listeners(self, current: dict | None = None) -> list[dict]:
        current = current if current is not None else current_listeners()
        known = self._load("baseline_listeners")
        if known is None:
            self._save("baseline_listeners", sorted(current))
            return []
        found = new_listeners(set(known), current)
        if found:
            self._save("baseline_listeners", sorted(set(known) | {f["key"] for f in found})[-500:])
            pkg = self._pkg()
            for f in found:
                if pkg:
                    f.update(severity="low", during_package_install=True)
                self.emit("new_listeners", f)
        return found

    def check_processes(self) -> list[dict]:
        found = []
        alive = set()
        for section, recs in (("reverse_shells", find_reverse_shells()),
                              ("suspicious_processes", find_suspicious_processes())):
            for r in recs:
                if r["pid"] in self.own_pids:
                    continue
                key = (section, r["pid"], r.get("observed_at"))
                alive.add(key)
                if key not in self._procs_seen:
                    self._procs_seen.add(key)
                    self.emit(section, r)
                    found.append(r)
        self._procs_seen &= alive  # forget processes that are gone
        # keep only processes still running in the recent list
        self.recent = deque(((s, r) for s, r in self.recent
                             if s not in ("reverse_shells", "suspicious_processes")
                             or (s, r["pid"], r.get("observed_at")) in alive), maxlen=1000)
        return found

    def on_syn_line(self, line: str) -> dict | None:
        rec = self.portscan.handle_line(line)
        if rec:
            if self.allowlist:
                try:
                    rec["allowlisted"] = self.allowlist.check_ip(rec["src_ip"])
                except ValueError:
                    rec["allowlisted"] = None
            self.emit("port_scans", rec)
        return rec

    def _save_if_changed(self, key, old, new) -> None:
        if old != new:
            self._save(key, new)

    def poll(self) -> None:
        for fn in (self.check_processes, self.check_listeners, self.check_accounts, self.check_integrity):
            try:
                fn()
                self.last_error = None
            except Exception as e:
                self.last_error = f"{fn.__name__}: {e}"

    # --- loops ---

    async def run(self) -> None:
        if not self.enabled:
            return
        import asyncio
        asyncio.get_running_loop().create_task(self._follow_kernel_log())
        self.status = "running"
        while True:
            await asyncio.to_thread(self.poll)
            await asyncio.sleep(self.poll_s)

    async def _follow_kernel_log(self) -> None:
        import asyncio
        import shutil
        if not shutil.which("journalctl"):
            self.portscan.status = "unavailable (no journalctl)"
            return
        while True:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "journalctl", "-k", "-f", "-n", "0", "-o", "cat",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                self.portscan.status = "running (kernel log, nftables ti-syn rule)"
                assert proc.stdout is not None
                async for raw in proc.stdout:
                    self.on_syn_line(raw.decode(errors="replace"))
                await proc.wait()
                self.portscan.status = f"stopped (exit {proc.returncode}), restarting"
            except Exception as e:
                self.portscan.status = f"error: {e}"
            await asyncio.sleep(10)
