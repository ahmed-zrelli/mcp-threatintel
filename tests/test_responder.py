"""Host agent tests: validation, state machine, channel isolation, backends, scans.

No test here touches the real firewall, hosts file or processes it did not
start: backends run with a recording runner or against temp files.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_threatintel.db import SCHEMA as IOC_SCHEMA
from mcp_threatintel.responder import protocol
from mcp_threatintel.responder.actions import TRANSITIONS, TransitionError
from mcp_threatintel.responder.agent import HostAgent
from mcp_threatintel.responder.backends import CommandRunner, build_backends
from mcp_threatintel.responder.backends.base import ResponseBackend
from mcp_threatintel.responder.backends.hosts_file import BEGIN, END, HostsFileBackend
from mcp_threatintel.responder.backends.quarantine import QuarantineBackend, sha256_file
from mcp_threatintel.responder.backends.windows_firewall import WindowsFirewallBackend
from mcp_threatintel.responder.config import ResponderConfig
from mcp_threatintel.responder.scanner import HostScanner, parse_auth_lines
from mcp_threatintel.responder.iocs import IocIndex
from mcp_threatintel.responder.validators import (
    Allowlist,
    ValidationError,
    validate_domain,
    validate_file,
    validate_ip,
    validate_pid,
)

AGENT_TOKEN = "agent-token-for-tests"
ADMIN_TOKEN = "admin-token-for-tests"


class RecordingRunner(CommandRunner):
    """Behaves like a real (non dry-run) runner but never executes anything."""

    def __init__(self):
        super().__init__(dry_run=False)
        self.calls: list[list[str]] = []

    def run(self, argv, log, *, check=True, timeout=60):
        self.calls.append(argv)
        log.append(" ".join(argv))
        return ""


class RecordingBackend(ResponseBackend):
    def __init__(self):
        super().__init__(RecordingRunner())
        self.applied: list[int] = []
        self.rolled_back: list[int] = []

    def apply(self, action):
        self.applied.append(action["id"])
        return {"commands": [f"apply {action['type']} {action['target']}"]}

    def rollback(self, action, state):
        self.rolled_back.append(action["id"])
        return {"commands": [f"rollback {action['id']}"]}


@pytest.fixture
def ioc_db(tmp_path):
    path = tmp_path / "threatintel.db"
    conn = sqlite3.connect(path)
    conn.executescript(IOC_SCHEMA)
    conn.executemany(
        "INSERT INTO iocs (indicator, type, source, malware_family, threat_type) VALUES (?, ?, ?, ?, ?)",
        [("45.1.2.3", "ip", "feodo", "qakbot", "botnet_cc"),
         ("45.1.2.4", "ip", "feodo", "qakbot", "botnet_cc"),
         ("a" * 64, "hash_sha256", "malwarebazaar", "agenttesla", "exe")],
    )
    conn.executemany(
        "INSERT INTO local_iocs (value, type, comment) VALUES (?, ?, ?)",
        [("192.168.56.66", "ip", "kali"), ("c2.lab.test", "domain", "lab")],
    )
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def config(tmp_path, ioc_db):
    scan = tmp_path / "scan"
    scan.mkdir()
    return ResponderConfig(
        agent_addr="tcp://127.0.0.1:1", admin_addr="tcp://127.0.0.1:2",
        agent_token=AGENT_TOKEN, data_dir=tmp_path / "data",
        admin_token_file=tmp_path / "data" / "admin.token",
        responder_db=tmp_path / "data" / "responder.db", ioc_db=ioc_db,
        quarantine_dir=tmp_path / "data" / "quarantine", hosts_path=tmp_path / "hosts",
        allowlist_file=None, scan_paths=[scan], dry_run=True, block_ttl=24, ttl_unit="hours",
    )


@pytest.fixture
def backend():
    return RecordingBackend()


@pytest.fixture
def agent(config, backend):
    types = ["block_ip", "block_feed_c2", "sinkhole_domain", "quarantine_file", "kill_process", "lock_user"]
    fake = {t: backend for t in types}
    a = HostAgent(config, admin_token=ADMIN_TOKEN, discover=False, backends={True: fake, False: fake})
    a.allowlist.add("8.8.8.8", "ip", "DNS server")
    a.allowlist.add("microsoft.com", "domain", "updates")
    yield a
    a.db.close()


def call(agent, channel, op, token=None, **params):
    handler = agent.handle_agent if channel == "agent" else agent.handle_admin
    tok = token if token is not None else (AGENT_TOKEN if channel == "agent" else ADMIN_TOKEN)
    return asyncio.run(handler({"op": op, "params": params, "token": tok}))


# --- validators ---------------------------------------------------------------


def test_validate_ip():
    assert validate_ip(" 45.1.2.3 ") == "45.1.2.3"
    for bad in ["999.1.1.1", "evil.example", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", ""]:
        with pytest.raises(ValidationError):
            validate_ip(bad)
    with pytest.raises(ValidationError, match="private"):
        validate_ip("192.168.1.10")
    assert validate_ip("192.168.1.10", allow_private=True) == "192.168.1.10"


def test_validate_domain():
    assert validate_domain("Evil.Example.") == "evil.example"
    for bad in ["-bad.com", "a..b", "evil", "1.2.3.4", "evil.com; rm -rf /", "x" * 300 + ".com"]:
        with pytest.raises(ValidationError):
            validate_domain(bad)


def test_validate_file_stays_inside_scan_paths(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "f.txt"
    inside.write_text("x")
    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    assert validate_file(str(inside), [root]) == inside.resolve()
    with pytest.raises(ValidationError, match="outside"):
        validate_file(str(outside), [root])
    with pytest.raises(ValidationError, match="outside"):
        validate_file(str(root / ".." / "secret.txt"), [root])
    with pytest.raises(ValidationError):
        validate_file(str(inside), [])


def test_validate_pid_refuses_self_and_system():
    import os
    for pid in [0, 4, os.getpid()]:
        with pytest.raises(ValidationError):
            validate_pid(pid)


def test_allowlist_cidr_and_domain_suffix():
    al = Allowlist()
    al.add("192.168.1.0/24", "cidr", "lan")
    al.add("microsoft.com", "domain")
    assert al.check_ip("192.168.1.77")
    assert al.check_ip("45.1.2.3") is None
    assert al.check_domain("update.microsoft.com")
    assert al.check_domain("notmicrosoft.com") is None


# --- channel isolation ----------------------------------------------------------


def test_agent_channel_cannot_approve(agent):
    action = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="t")["data"]
    resp = call(agent, "agent", "approve", id=action["id"])
    assert resp["ok"] is False and "not allowed" in resp["error"]
    assert agent.db.get_action(action["id"])["status"] == "pending"


def test_wrong_tokens_are_rejected(agent):
    assert call(agent, "agent", "ping", token="nope")["ok"] is False
    assert call(agent, "admin", "ping", token=AGENT_TOKEN)["ok"] is False  # agent token is not admin
    events = [e["event"] for e in agent.db.audit()]
    assert events.count("auth_failed") == 2


def test_admin_channel_cannot_scan_or_create(agent):
    assert call(agent, "admin", "create_action", type="block_ip", params={"ip": "45.1.2.3"})["ok"] is False
    assert call(agent, "admin", "scan_host")["ok"] is False


# --- lifecycle -------------------------------------------------------------------


def test_full_lifecycle_with_rollback(agent, backend):
    a = call(agent, "agent", "create_action", type="block_ip",
             params={"ip": "45.1.2.3", "ttl": 2}, reason="feodo C2")["data"]
    assert a["status"] == "pending"
    asyncio.run(agent.process_approved())
    assert backend.applied == []  # nothing runs while pending

    assert call(agent, "admin", "approve", id=a["id"], actor="alice")["data"]["status"] == "approved"
    asyncio.run(agent.process_approved())
    done = agent.db.get_action(a["id"])
    assert done["status"] == "executed" and done["expires_at"] and backend.applied == [a["id"]]

    rb = call(agent, "agent", "request_rollback", id=a["id"], reason="false positive")["data"]
    assert rb["status"] == "pending" and rb["rollback_of"] == a["id"]
    call(agent, "admin", "approve", id=rb["id"], actor="alice")
    asyncio.run(agent.process_approved())
    assert agent.db.get_action(a["id"])["status"] == "rolled_back"
    assert backend.rolled_back == [a["id"]]
    events = [e["event"] for e in agent.db.audit(a["id"])]
    assert events == ["created", "approved", "executed", "rolled_back"]


def test_allowlisted_target_is_refused_at_creation(agent, backend):
    a = call(agent, "agent", "create_action", type="block_ip", params={"ip": "8.8.8.8"}, reason="x")["data"]
    assert a["status"] == "rejected" and "allowlisted" in a["error"]
    s = call(agent, "agent", "create_action", type="sinkhole_domain",
             params={"domain": "update.microsoft.com"}, reason="x")["data"]
    assert s["status"] == "rejected"


def test_allowlist_is_rechecked_at_approval(agent, backend):
    a = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.4"}, reason="x")["data"]
    agent.allowlist.add("45.1.2.0/24", "cidr", "added after creation")
    out = call(agent, "admin", "approve", id=a["id"], actor="alice")["data"]
    assert out["status"] == "rejected" and "re-check failed" in out["error"]
    asyncio.run(agent.process_approved())
    assert backend.applied == []


def test_private_ip_needs_local_ioc(agent):
    ok = call(agent, "agent", "create_action", type="block_ip", params={"ip": "192.168.56.66"}, reason="kali")["data"]
    assert ok["status"] == "pending"
    no = call(agent, "agent", "create_action", type="block_ip", params={"ip": "192.168.56.99"}, reason="?")["data"]
    assert no["status"] == "rejected"


def test_invalid_transitions_are_refused(agent):
    a = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="x")["data"]
    call(agent, "admin", "reject", id=a["id"], actor="alice")
    assert call(agent, "admin", "approve", id=a["id"], actor="alice")["ok"] is False
    with pytest.raises(TransitionError):
        agent.manager.transition(a["id"], "executed", "test")
    assert TRANSITIONS["rejected"] == set()


def test_rollback_only_for_executed_reversible(agent):
    a = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="x")["data"]
    assert call(agent, "agent", "request_rollback", id=a["id"])["ok"] is False  # still pending


def test_block_feed_snapshots_feed_ips(agent):
    a = call(agent, "agent", "create_action", type="block_feed_c2", params={"feed": "feodo"}, reason="x")["data"]
    assert a["status"] == "pending"
    assert sorted(agent.db.get_action(a["id"])["params"]["ips"]) == ["45.1.2.3", "45.1.2.4"]


def test_ttl_expiry(agent, backend, config):
    config.ttl_unit = "minutes"
    a = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3", "ttl": 0.01},
             reason="x")["data"]
    call(agent, "admin", "approve", id=a["id"], actor="alice")
    asyncio.run(agent.process_approved())
    time.sleep(1.6)
    asyncio.run(agent.expire())
    assert agent.db.get_action(a["id"])["status"] == "expired"
    assert backend.rolled_back == [a["id"]]


def test_audit_log_is_append_only(agent):
    call(agent, "agent", "ping")
    call(agent, "agent", "ping", token="bad")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        agent.db._conn.execute("DELETE FROM audit_log")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        agent.db._conn.execute("UPDATE audit_log SET actor = 'x'")


def test_kill_process_end_to_end(config):
    """Real ProcessBackend on a process this test starts."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        config.dry_run = False
        a = HostAgent(config, admin_token=ADMIN_TOKEN, discover=False)
        act = call(a, "agent", "create_action", type="kill_process", params={"pid": proc.pid}, reason="x")["data"]
        assert act["status"] == "pending", act
        call(a, "admin", "approve", id=act["id"], actor="alice")
        asyncio.run(a.process_approved())
        assert a.db.get_action(act["id"])["status"] == "executed"
        assert proc.wait(timeout=10) is not None
        assert call(a, "agent", "request_rollback", id=act["id"])["ok"] is False  # irreversible
        a.db.close()
    finally:
        if proc.poll() is None:
            proc.kill()


# --- backends ---------------------------------------------------------------------


def test_dry_run_never_calls_subprocess(config, monkeypatch, tmp_path):
    def boom(*a, **k):
        raise AssertionError("subprocess.run called in dry-run")

    monkeypatch.setattr(subprocess, "run", boom)
    backends = build_backends(config, CommandRunner(dry_run=True))
    f = config.scan_paths[0] / "x.bin"
    f.write_bytes(b"x")
    config.hosts_path.write_text("127.0.0.1 localhost\n")
    for type_, params in [("sinkhole_domain", {"domain": "evil.example"}),
                          ("quarantine_file", {"path": str(f)})]:
        backends[type_].apply({"id": 1, "type": type_, "target": "t", "params": params})
    assert f.exists()  # not moved
    assert "evil.example" not in config.hosts_path.read_text()  # not written
    if sys.platform == "win32":
        state = backends["block_ip"].apply({"id": 1, "type": "block_ip", "target": "t",
                                            "params": {"ip": "45.1.2.3"}})
        assert state["commands"][0].startswith("netsh advfirewall firewall add rule")


def test_windows_firewall_commands():
    runner = RecordingRunner()
    fw = WindowsFirewallBackend(runner)
    state = fw.apply({"id": 7, "params": {"ip": "45.1.2.3"}})
    assert state["rules"] == ["threatintel-7-in", "threatintel-7-out"]
    assert runner.calls[0][:5] == ["netsh", "advfirewall", "firewall", "add", "rule"]
    assert "remoteip=45.1.2.3" in runner.calls[0] and "dir=out" in runner.calls[1]
    fw.rollback({"id": 7}, state)
    assert runner.calls[-1] == ["netsh", "advfirewall", "firewall", "delete", "rule", "name=threatintel-7-out"]


def test_windows_firewall_chunks_big_feeds():
    runner = RecordingRunner()
    ips = [f"45.{i // 250}.{i % 250}.1" for i in range(2500)]
    state = WindowsFirewallBackend(runner).apply({"id": 9, "params": {"ips": ips}})
    assert len(state["rules"]) == 6  # 3 chunks x (in, out)


def test_hosts_file_block_and_rollback(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("# original\n127.0.0.1 localhost\n")
    be = HostsFileBackend(RecordingRunner(), hosts, tmp_path / "backup")
    s1 = be.apply({"id": 1, "params": {"domain": "evil.example"}})
    s2 = be.apply({"id": 2, "params": {"domain": "bad.example"}})
    text = hosts.read_text()
    assert BEGIN in text and END in text and text.count(BEGIN) == 1
    assert "0.0.0.0 evil.example # threatintel:1" in text
    assert (tmp_path / "backup" / "hosts.original").read_text() == "# original\n127.0.0.1 localhost\n"
    be.rollback({"id": 1}, s1)
    text = hosts.read_text()
    assert "evil.example" not in text and "bad.example" in text
    be.rollback({"id": 2}, s2)
    assert hosts.read_text().replace("\r\n", "\n") == "# original\n127.0.0.1 localhost\n"


def test_quarantine_and_restore(tmp_path):
    src_dir = tmp_path / "downloads"
    src_dir.mkdir()
    f = src_dir / "evil.exe"
    f.write_bytes(b"malware bytes")
    digest = sha256_file(f)
    runner = RecordingRunner()
    be = QuarantineBackend(runner, tmp_path / "q")
    state = be.apply({"id": 3, "params": {"path": str(f)}})
    assert not f.exists()
    assert Path(state["quarantine_path"]).name == f"{digest}_3"
    if sys.platform == "win32":
        assert runner.calls[0][0] == "icacls" and "/inheritance:r" in runner.calls[0]
    be.rollback({"id": 3}, state)
    assert f.read_bytes() == b"malware bytes"


# --- scanner -------------------------------------------------------------------------


def test_parse_auth_lines_linux_and_windows_formats():
    lines = [
        "Failed password for root from 192.168.56.66 port 51234 ssh2",
        "Failed password for invalid user admin from 192.168.56.66 port 51235 ssh2",
        "sshd: Failed password for bob from 10.0.0.5 port 22 ssh2",
        "Invalid user oracle from 192.168.56.66 port 40000",
        "Accepted password for alice from 10.0.0.9 port 5000 ssh2",
    ]
    out = parse_auth_lines(lines)
    assert out["192.168.56.66"]["failures"] == 3
    assert out["192.168.56.66"]["users"] == {"root", "admin", "oracle"}
    assert out["10.0.0.5"]["failures"] == 1
    assert out["10.0.0.9"]["failures"] == 0 and out["10.0.0.9"]["accepted"] == 1  # successful logins are tracked


def test_scan_files_finds_local_ioc_hash(config, ioc_db):
    evil = config.scan_paths[0] / "evil.bin"
    evil.write_bytes(b"lab payload")
    (config.scan_paths[0] / "clean.txt").write_text("hello")
    conn = sqlite3.connect(ioc_db)
    conn.execute("INSERT INTO local_iocs (value, type) VALUES (?, 'hash_sha256')", (sha256_file(evil),))
    conn.commit()
    conn.close()
    out = HostScanner(config, IocIndex(ioc_db)).scan_files()
    assert out["files_scanned"] == 2 and out["malicious_count"] == 1
    assert out["malicious"][0]["path"].endswith("evil.bin")


def test_scan_files_refuses_paths_outside_scan_paths(config, ioc_db, tmp_path):
    with pytest.raises(ValidationError):
        HostScanner(config, IocIndex(ioc_db)).scan_files(str(tmp_path))


def test_ioc_index_is_read_only(ioc_db):
    idx = IocIndex(ioc_db)
    assert idx.is_local_ioc("192.168.56.66")
    conn = idx._connect()
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM iocs")
    conn.close()


# --- protocol ------------------------------------------------------------------------


def test_protocol_roundtrip_over_tcp():
    async def scenario():
        async def handler(req):
            return {"ok": True, "data": req["op"]}

        port = 38000 + (int(time.time() * 1000) % 1000)
        addr = f"tcp://127.0.0.1:{port}"
        server = await protocol.serve(addr, handler)
        async with server:
            resp = await protocol.request(addr, "ping", {}, "t")
            sync = await asyncio.to_thread(protocol.request_sync, addr, "hello", {}, "t")
        return resp, sync

    resp, sync = asyncio.run(scenario())
    assert resp == {"ok": True, "data": "ping"} and sync["data"] == "hello"


def test_protocol_refuses_non_loopback_bind():
    with pytest.raises(protocol.ProtocolError):
        asyncio.run(protocol.serve("tcp://0.0.0.0:38999", lambda r: r))


# --- Linux / nftables (phase 2) ------------------------------------------------------


def test_nftables_block_and_rollback_commands():
    from mcp_threatintel.responder.backends.nftables import NftablesBackend, TIMEOUT_MARGIN_S

    runner = RecordingRunner()
    nft = NftablesBackend(runner, None, seconds_per_unit=3600)
    nft._table_exists = lambda: True
    state = nft.apply({"id": 5, "params": {"ip": "45.1.2.3", "ttl": 2}})
    add = runner.calls[-1]
    assert add[:6] == ["nft", "add", "element", "inet", "threatintel", "blocklist"]
    assert f"45.1.2.3 timeout {2 * 3600 + TIMEOUT_MARGIN_S}s" in add[6]
    assert 'comment "threatintel-5"' in add[6]
    assert state["ips"] == ["45.1.2.3"]
    nft.rollback({"id": 5, "params": {}}, state)
    assert runner.calls[-1] == ["nft", "destroy", "element", "inet", "threatintel", "blocklist", "{ 45.1.2.3 }"]


def test_nftables_rollback_keeps_ips_still_blocked_elsewhere():
    from mcp_threatintel.responder.backends.nftables import NftablesBackend

    runner = RecordingRunner()
    nft = NftablesBackend(runner)
    out = nft.rollback({"id": 1, "params": {}}, {"ips": ["45.1.2.3", "45.1.2.4"], "keep_ips": ["45.1.2.4"]})
    assert out["removed_ips"] == ["45.1.2.3"] and out["kept_ips"] == ["45.1.2.4"]
    assert "45.1.2.4" not in runner.calls[-1][-1]


def test_nftables_missing_table_without_ruleset_fails_loudly():
    from mcp_threatintel.responder.backends.base import BackendError
    from mcp_threatintel.responder.backends.nftables import NftablesBackend

    nft = NftablesBackend(RecordingRunner(), None)
    nft._table_exists = lambda: False
    with pytest.raises(BackendError, match="missing"):
        nft.apply({"id": 1, "params": {"ip": "45.1.2.3"}})


def test_overlapping_blocks_rollback_keeps_the_other(agent, backend):
    a1 = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="x")["data"]
    a2 = call(agent, "agent", "create_action", type="block_feed_c2", params={"feed": "feodo"}, reason="x")["data"]
    for a in (a1, a2):
        call(agent, "admin", "approve", id=a["id"], actor="alice")
    asyncio.run(agent.process_approved())
    state = agent._rollback_state(agent.db.get_action(a1["id"]))
    assert "45.1.2.3" in state["keep_ips"]  # still needed by the feed block


def test_prepare_host_reapplies_active_blocks(config):
    from mcp_threatintel.responder.backends.nftables import NftablesBackend

    runner = RecordingRunner()
    nft = NftablesBackend(runner)
    nft._table_exists = lambda: True
    rec = RecordingBackend()
    real = {"block_ip": nft, "block_feed_c2": nft, "sinkhole_domain": rec, "quarantine_file": rec, "kill_process": rec}
    config.dry_run = False
    a = HostAgent(config, admin_token=ADMIN_TOKEN, discover=False, backends={True: real, False: real})
    act = call(a, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3", "ttl": 1}, reason="x")["data"]
    call(a, "admin", "approve", id=act["id"], actor="alice")
    asyncio.run(a.process_approved())
    runner.calls.clear()
    a.prepare_host()  # simulates an agent start after a reboot
    assert any(c[:3] == ["nft", "add", "element"] and "45.1.2.3" in c[-1] for c in runner.calls)
    assert any(e["event"] == "blocks_restored" for e in a.db.audit())
    a.db.close()


def test_nft_ruleset_template_is_valid_shape():
    text = (Path(__file__).resolve().parent.parent / "deploy" / "threatintel.nft").read_text()
    assert "@MCP_CLIENTS@" in text and "table inet threatintel {" in text
    assert "set blocklist" in text and "flags timeout" in text
    assert "tcp dport { 3707, 3712, 3713 } ip saddr != @mcp_clients" in text
    assert 'log prefix "ti-syn "' in text


def test_duplicate_request_reuses_the_pending_action(agent):
    a1 = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="watch")["data"]
    a2 = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="model")["data"]
    assert a2["id"] == a1["id"] and a2["duplicate"] is True
    assert len(agent.db.list_actions("pending")) == 1
    call(agent, "admin", "reject", id=a1["id"], actor="alice")
    a3 = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="again")["data"]
    assert a3["id"] != a1["id"] and not a3.get("duplicate")  # a rejected action does not block a new request


# --- always-on detection (AlertEngine) ----------------------------------------------


class FakeScanner:
    def __init__(self, report):
        self.report = report

    def scan_host(self, minutes=60):
        return self.report


def test_alert_engine_creates_alert_and_pending_actions_once(agent, backend):
    from mcp_threatintel.responder.alerts import AlertEngine

    report = {"connections": {"malicious": [{"remote_ip": "45.1.2.3", "remote_port": 443, "pid": None,
                                              "process": "curl", "active": False, "ioc_matches": [{"source": "feodo"}]}]},
              "dns": {"malicious": [{"domain": "evil.example", "lookups": 2, "ioc_matches": [{"source": "otx"}]}]}}
    eng = AlertEngine(agent.db, agent.manager, FakeScanner(report))
    first = eng.tick()
    assert len(first) == 2 and eng.tick() == []                     # second scan: nothing new
    alerts = call(agent, "agent", "list_alerts")["data"]
    assert {a["kind"] for a in alerts} == {"c2_connection", "malicious_dns"}
    pend = {(a["type"], a["target"]) for a in agent.db.list_actions("pending")}
    assert pend == {("block_ip", "45.1.2.3"), ("sinkhole_domain", "evil.example")}
    assert all(a["requested_by"] == "auto-detect" for a in agent.db.list_actions("pending"))
    assert all(x["status"] == "pending" for a in alerts for x in a["actions"])
    asyncio.run(agent.process_approved())
    assert backend.applied == []                                     # never executed without approval
    assert call(agent, "admin", "list_alerts")["ok"] is True


def test_alert_engine_records_refused_actions(agent):
    from mcp_threatintel.responder.alerts import AlertEngine

    report = {"auth_logs": {"details": [{"ip": "8.8.8.8", "failures": 50, "accepted": 0, "users_tried": ["root"],
                                         "brute_force": True, "known_malicious": False, "ioc_matches": []}]}}
    eng = AlertEngine(agent.db, agent.manager, FakeScanner(report))
    assert len(eng.tick()) == 1
    alert = agent.db.list_alerts()[0]
    assert alert["action_ids"] == [] or agent.db.get_action(alert["action_ids"][0])["status"] == "rejected"
    assert "allowlisted" in json.dumps(alert["detail"]) or alert["action_ids"]
