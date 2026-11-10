"""threatintel-watch: findings, de-duplication, notification text, model tool loop."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx

from mcp_threatintel.responder.findings import SeenStore, extract_findings
from mcp_threatintel.watch.llm import investigate
from mcp_threatintel.watch.notify import toast_xml
from mcp_threatintel.watch.watcher import approve_hint

REPORT = {
    "connections": {"malicious": [{"remote_ip": "9.9.9.9", "remote_port": 443, "pid": 4242,
                                   "process": "python3", "ioc_matches": [{"source": "local", "comment": "lab C2"}]}]},
    "files": {"malicious": [{"path": "/home/ahmed/threatintel-lab/invoice.exe.txt", "sha256": "f8" * 32,
                             "ioc_matches": [{"source": "malwarebazaar", "malware_family": "AgentTesla"}]}]},
    "auth_logs": {"details": [
        {"ip": "192.168.56.66", "failures": 87, "users_tried": ["root", "admin"], "brute_force": True},
        {"ip": "10.0.0.9", "failures": 1, "users_tried": ["bob"], "brute_force": False},
    ]},
}


def test_extract_findings_and_plans():
    fs = {f.kind: f for f in extract_findings(REPORT)}
    assert set(fs) == {"c2_connection", "malicious_file", "ssh_bruteforce"}
    assert [t for t, _ in fs["c2_connection"].plan] == ["kill_process", "block_ip"]
    assert fs["c2_connection"].plan[0][1]["pid"] == 4242
    assert fs["malicious_file"].plan[0] == ("quarantine_file", fs["malicious_file"].plan[0][1])
    assert "AgentTesla" in fs["malicious_file"].plan[0][1]["reason"]
    assert fs["ssh_bruteforce"].plan[0][1]["ip"] == "192.168.56.66"
    assert "10.0.0.9" not in json.dumps([f.key for f in fs.values()])  # below threshold: no alert


def test_empty_or_failed_report_gives_no_findings():
    assert extract_findings({}) == []
    assert extract_findings({"connections": {"error": "x"}, "files": {"error": "y"}}) == []


def test_seen_store_alerts_once_then_again_after_ttl(tmp_path):
    now = [1000.0]
    store = SeenStore(tmp_path / "seen.json", ttl_s=60, clock=lambda: now[0])
    first = extract_findings(REPORT)
    assert len(store.new_only(first)) == 3
    assert store.new_only(extract_findings(REPORT)) == []          # same findings: silent
    assert len(SeenStore(tmp_path / "seen.json", ttl_s=60, clock=lambda: now[0]).new_only(first)) == 0  # persisted
    now[0] += 61
    assert len(store.new_only(extract_findings(REPORT))) == 3      # forgotten after the TTL


def test_toast_text_is_escaped():
    xml = toast_xml("<script>&", ['proc "x" <b>'])
    assert "<script>" not in xml and "&lt;script&gt;&amp;" in xml and "&lt;b&gt;" in xml


def test_approve_hint_lists_pending_only():
    hint = approve_hint([{"id": 3, "status": "pending"}, {"id": 4, "status": "rejected"}, {"id": 5, "status": "pending"}])
    assert hint == "Approve on the server: threatintel-approve approve 3 ; threatintel-approve approve 5"
    assert approve_hint([{"status": "rejected"}]) == "No action to approve."


class FakeMCP:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        names = ["lookup_ioc", "block_ip", "scan_host", "get_feed_status"]
        return [SimpleNamespace(name=n, description=n, inputSchema={"type": "object"}) for n in names]

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        payload = {"lookup_ioc": {"malicious": True}, "block_ip": {"id": 7, "status": "pending", "type": "block_ip"}}[name]
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(payload))])


def test_investigation_tool_loop():
    replies = iter([
        {"tool_calls": [{"id": "a", "function": {"name": "lookup_ioc", "arguments": '{"indicator": "9.9.9.9"}'}}]},
        {"tool_calls": [{"id": "b", "function": {"name": "block_ip", "arguments": '{"ip": "9.9.9.9", "reason": "C2"}'}},
                        {"id": "c", "function": {"name": "approve", "arguments": "{}"}}]},
        {"content": "High: C2 beacon. Approve: threatintel-approve approve 7"},
    ])
    sent = []

    def handler(request):
        body = json.loads(request.content)
        sent.append(body)
        msg = next(replies)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", **msg}}]})

    mcp = FakeMCP()
    text, actions = asyncio.run(investigate(mcp, "http://llm", "alert", transport=httpx.MockTransport(handler)))
    assert text.startswith("High")
    assert [a["id"] for a in actions] == [7]
    assert [c[0] for c in mcp.calls] == ["lookup_ioc", "block_ip"]        # "approve" never reached the server
    offered = {t["function"]["name"] for t in sent[0]["tools"]}
    assert offered == {"lookup_ioc", "block_ip"}                          # scan/feed tools not offered


class AlertsMCP:
    def __init__(self, alerts):
        self.alerts = alerts

    async def call_tool(self, name, args):
        since = args.get("since_id") or 0
        data = [a for a in self.alerts if a["id"] > since]
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(data))])


def test_notifier_first_run_summarises_then_shows_only_new(tmp_path, monkeypatch):
    from mcp_threatintel.watch import watcher

    shown = []
    monkeypatch.setattr(watcher, "notify", lambda title, lines: shown.append(title) or True)

    async def fake_show(mcp, alert, args, toast):
        shown.append(f"alert {alert['id']}")

    monkeypatch.setattr(watcher, "show", fake_show)
    alerts = [{"id": i, "severity": "high", "title": f"t{i}", "actions": []} for i in (1, 2)]
    last = watcher.LastSeen(tmp_path / "last.txt")
    mcp = AlertsMCP(alerts)
    asyncio.run(watcher.poll(mcp, last, SimpleNamespace(no_ai=True)))
    assert shown == ["ThreatIntel - 2 alert(s) on the server"] and last.get() == 2   # no replay of old alerts
    alerts.append({"id": 3, "severity": "critical", "title": "t3", "actions": []})
    asyncio.run(watcher.poll(mcp, last, SimpleNamespace(no_ai=True)))
    assert shown[-1] == "alert 3" and last.get() == 3
