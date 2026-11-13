"""Investigation: forensics on the host, campaign pivot, evidence at alert time, reports."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import time

import pytest

from mcp_threatintel.db import SCHEMA
from mcp_threatintel.responder.config import ResponderConfig
from mcp_threatintel.responder.forensics import Forensics, collect_evidence
from mcp_threatintel.responder.iocs import IocIndex
from mcp_threatintel.responder.monitor import ConnectionSampler, DnsMonitor
from mcp_threatintel.responder.scanner import HostScanner
from mcp_threatintel.responder.store import ResponderDB
from test_responder import AGENT_TOKEN, agent, backend, config, ioc_db  # noqa: F401  (shared fixtures)


@pytest.fixture
def fx(tmp_path):
    dbp = tmp_path / "ti.db"
    c = sqlite3.connect(dbp)
    c.executescript(SCHEMA)
    c.execute("INSERT INTO pulses (pulse_id, name, adversary) VALUES ('p1', 'Operation Lab', 'APT-LAB')")
    c.executemany("INSERT INTO pulse_indicators (pulse_id, indicator, type) VALUES ('p1', ?, ?)", [
        ("203.0.113.66", "IPv4"), ("bad-c2.example", "domain"), ("198.51.100.20", "IPv4"), ("8.8.8.8", "IPv4")])
    c.executemany("INSERT INTO iocs (indicator, type, source, malware_family) VALUES (?,?,?,?)", [
        ("203.0.113.66", "ip", "feodo", "qakbot"), ("192.0.2.5", "ip", "threatfox", "qakbot")])
    c.commit()
    c.close()
    sampler, dns = ConnectionSampler(), DnsMonitor()
    dns.available = True
    now = time.time()
    sampler.seen.upsert(("198.51.100.20", 443, 4242), now, remote_ip="198.51.100.20", remote_port=443,
                        pid=4242, process="curl", status="ESTABLISHED")
    sampler.seen.upsert(("203.0.113.66", 8080, 4242), now, remote_ip="203.0.113.66", remote_port=8080,
                        pid=4242, process="curl", status="ESTABLISHED")
    dns.handle_line(json.dumps({"question": [{"name": "bad-c2.example"}],
                                "answer": [{"rr": {"address": [203, 0, 113, 66]}}]}))
    (tmp_path / "scan").mkdir()
    cfg = ResponderConfig(ioc_db=dbp, scan_paths=[tmp_path / "scan"], hosts_path=tmp_path / "hosts")
    scanner = HostScanner(cfg, IocIndex(dbp), sampler, dns)
    db = ResponderDB(tmp_path / "responder.db")
    yield Forensics(scanner, db)
    db.close()


def test_related_iocs_finds_other_campaign_indicators_on_host(fx):
    out = fx.related_iocs("203.0.113.66")
    assert out["pulses"][0]["name"] == "Operation Lab" and out["malware_families"] == ["qakbot"]
    values = {r["value"] for r in out["related_sample"]}
    assert {"bad-c2.example", "198.51.100.20", "192.0.2.5"} <= values and "8.8.8.8" not in values
    present = {r["value"] for r in out["related_present_on_host"]}
    assert present == {"bad-c2.example", "198.51.100.20"}       # seen in DNS / sampled connections


def test_ip_and_domain_activity(fx):
    ip = fx.ip_activity("203.0.113.66")
    assert ip["ioc_matches"] and ip["connections_last_hour"][0]["process"] == "curl"
    assert ip["resolved_from_domains"][0]["domain"] == "bad-c2.example"
    dom = fx.domain_activity("bad-c2.example")
    assert dom["dns_last_hour"][0]["answers"] == ["203.0.113.66"] and dom["ioc_matches"]


def test_inspect_process_and_file(fx, tmp_path):
    f = tmp_path / "scan" / "dropper.sh"
    f.write_text("#!/bin/sh\necho hi\n")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        info = fx.inspect_process(proc.pid)
        assert info["running"] and info["parent_chain"][0]["pid"] == os.getpid()
        assert info["exe_sha256"] and info["started"]
    finally:
        proc.kill()
        proc.wait()
    assert fx.inspect_process(proc.pid)["running"] is False
    finfo = fx.inspect_file(str(f))
    assert finfo["type"].startswith("script") and len(finfo["sha256"]) == 64
    assert fx.inspect_file(str(tmp_path / "missing"))["exists"] is False


def test_evidence_collected_per_alert_kind(fx):
    ev = collect_evidence(fx, "malicious_dns", {"domain": "bad-c2.example", "answers": ["203.0.113.66"]})
    assert {"domain", "answer_ip_0", "campaign"} <= set(ev)
    ev = collect_evidence(fx, "ssh_bruteforce", {"ip": "not-an-ip"})
    assert "error" in ev["ip"]                                   # best effort, never raises


def test_alert_reports_and_migration(tmp_path):
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)  # an alerts table from before reports existed
    c.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, key TEXT NOT NULL, "
              "kind TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, "
              "detail_json TEXT NOT NULL DEFAULT '{}', action_ids TEXT NOT NULL DEFAULT '[]')")
    c.commit()
    c.close()
    db = ResponderDB(path)
    aid = db.insert_alert(key="k", kind="c2_connection", severity="high", title="t", detail={}, action_ids=[])
    db.save_report(aid, "SUMMARY: x", "qwen")
    assert db.get_alert(aid)["report"] == "SUMMARY: x" and db.get_alert(aid)["report_by"] == "qwen"
    db.close()


def test_agent_investigation_ops(agent):  # noqa: F811
    from mcp_threatintel.responder.alerts import AlertEngine

    class S:
        def scan_host(self, minutes=60):
            return {"dns": {"malicious": [{"domain": "evil.example", "lookups": 1, "ioc_matches": [{"source": "x"}]}]}}

    agent.detector = AlertEngine(agent.db, agent.manager, agent.scanner)  # real forensics
    agent.detector.scanner = S()                                           # scripted findings
    [aid] = agent.detector.tick()

    def call(op, **params):
        return asyncio.run(agent.handle_agent({"op": op, "params": params, "token": AGENT_TOKEN}))

    full = call("list_alerts", alert_id=aid)
    assert full["ok"] and "evidence" in full["data"]["detail"]
    assert call("save_alert_report", alert_id=aid, report="SUMMARY: ok")["ok"]
    assert agent.db.get_alert(aid)["report"] == "SUMMARY: ok"
    listed = call("list_alerts")["data"][0]
    assert listed["report_summary"] == "SUMMARY: ok" and "evidence" not in listed["detail"]
    assert call("investigate_host", kind="shell", value="x")["ok"] is False
    assert call("related_iocs", indicator="evil.example")["ok"]
