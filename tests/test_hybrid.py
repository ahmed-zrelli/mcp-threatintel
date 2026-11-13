"""Hybrid response: rules act first, the AI automatically decides what they cannot handle."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from mcp_threatintel.watch import watcher
from mcp_threatintel.watch.llm import budgets, compact, fit
from test_responder import AGENT_TOKEN, agent, backend, call, config, ioc_db  # noqa: F401  (shared fixtures)


def _raise(agent, section, rec):  # noqa: F811
    eng = agent.detector
    eng.on_behavior(section, rec) if section else None
    ids = []
    while not eng.events.empty():
        ids += eng.process_event(eng.events.get_nowait())
    return [agent.db.get_alert(i) for i in ids]


def test_rules_execute_clear_cut_attacks(agent):  # noqa: F811
    agent.detector.rules_execute = True
    agent.detector.on_connection({"remote_ip": "45.1.2.3", "remote_port": 443, "pid": None, "process": "curl"})
    (alert,) = _raise(agent, None, None)
    assert alert["detail"]["route"] == "rules"
    (act,) = [agent.db.get_action(i) for i in alert["action_ids"]]
    assert act["status"] == "approved" and act["approved_by"] == "rules"
    asyncio.run(agent.process_approved())
    assert agent.db.get_action(act["id"])["status"] == "executed"
    assert call(agent, "agent", "list_alerts", ai_queue=True)["data"]["ai_queue"] == []      # nothing for the AI


def test_rules_act_when_an_open_attack_with_pending_actions_is_seen_again(agent):  # noqa: F811
    conn = {"remote_ip": "45.1.2.3", "remote_port": 443, "pid": None, "process": "curl"}
    agent.detector.on_connection(conn)                       # raised while the rules were off
    (alert,) = _raise(agent, None, None)
    assert agent.db.get_action(alert["action_ids"][0])["status"] == "pending"
    agent.detector.rules_execute = True
    agent.detector.on_connection({**conn, "observed_at": 1e10})   # the connection is still there
    assert _raise(agent, None, None) == []                   # same open attack: counted, no new alert
    assert agent.db.get_action(alert["action_ids"][0])["approved_by"] == "rules"
    assert agent.db.get_alert(alert["id"])["detail"]["route"] == "rules"


def test_unclear_behavior_goes_to_the_ai(agent):  # noqa: F811
    agent.detector.rules_execute = True
    (alert,) = _raise(agent, "new_listeners", {"key": "tcp:8771:python3", "port": 8771, "address": "0.0.0.0",
                                               "pid": 999999, "process": "python3", "severity": "high",
                                               "observed_at": 1e10})
    assert alert["detail"]["route"] == "ai"
    queue = call(agent, "agent", "list_alerts", ai_queue=True)["data"]["ai_queue"]
    assert [q["id"] for q in queue] == [alert["id"]]                     # waiting for the AI


def test_allowlisted_source_is_handled_not_escalated(agent):  # noqa: F811
    agent.detector.rules_execute = True
    agent.allowlist.add("192.168.21.1", "ip", "analyst PC")
    (alert,) = _raise(agent, "port_scans", {"src_ip": "192.168.21.1", "distinct_ports": 30, "window_s": 10,
                                            "allowlisted": "analyst PC", "observed_at": 1e10})
    assert alert["detail"]["route"] == "rules" and alert["action_ids"] == []


def test_a_failed_rule_action_hands_the_alert_to_the_ai(agent, backend):  # noqa: F811
    agent.detector.rules_execute = True
    agent.detector.on_connection({"remote_ip": "45.1.2.3", "remote_port": 443, "pid": None, "process": "curl"})
    (alert,) = _raise(agent, None, None)
    orig = backend.apply

    def boom(action):
        raise RuntimeError("nft not available")
    backend.apply = boom
    asyncio.run(agent.process_approved())
    backend.apply = orig
    assert agent.db.get_alert(alert["id"])["detail"]["route"] == "ai"
    assert [q["id"] for q in call(agent, "agent", "list_alerts", ai_queue=True)["data"]["ai_queue"]] == [alert["id"]]


def test_repeated_entries_are_grouped_not_cut():
    conns = [{"remote_ip": "9.9.9.9", "remote_port": 443, "pid": 2505, "last_seen": i, "observed_at": i}
             for i in range(63)]
    out = compact({"connections": conns, "sha256": "a" * 64})
    assert out["connections"] == [{"remote_ip": "9.9.9.9", "remote_port": 443, "pid": 2505, "last_seen": 0,
                                   "observed_at": 0, "repeated": 63}]
    assert out["sha256"] == "a" * 64                                             # evidence kept whole
    big = json.dumps({"rows": [{"n": i} for i in range(500)]})
    small = fit(big, 400)
    assert len(small) <= 450 and "more_entries_not_shown" in small
    brief, per_tool = budgets(8192)
    assert brief > per_tool >= 1500 and budgets(16384)[1] > per_tool


class QueueMCP:
    """MCP double: one AI alert that the model never resolves."""

    def __init__(self):
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        if args.get("ai_queue"):
            data = {"ai_queue": [{"id": 7, "actions": []}]}
        elif args.get("alert_id"):
            data = {"id": 7, "kind": "new_listener", "severity": "high", "title": "t", "actions": [], "detail": {}}
        else:
            data = {"ok": True}
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(data))])


def test_responder_ignores_an_agent_without_ai_queue():
    class OldAgentMCP(QueueMCP):
        async def call_tool(self, name, args):
            return SimpleNamespace(content=[SimpleNamespace(text=json.dumps([{"id": 1, "title": "old alert"}]))])
    r = watcher.Responder(OldAgentMCP(), SimpleNamespace())
    assert asyncio.run(r.queue()) == []                            # plain alert list: never treated as AI work


def test_responder_waits_for_qwen_then_escalates_if_it_cannot_decide(monkeypatch):
    mcp = QueueMCP()
    args = SimpleNamespace(no_ai=False, llm_url="http://llm", llm_timeout=5, llm_context=8192)
    r = watcher.Responder(mcp, args)
    up = {"v": False}

    async def available(url):
        return up["v"]

    async def no_decision(*a, **k):
        return "VERDICT: unsure", []
    monkeypatch.setattr(watcher, "llm_available", available)
    monkeypatch.setattr(watcher, "investigate", no_decision)
    monkeypatch.setattr(watcher, "notify", lambda *a: True)
    alert = {"id": 7}
    asyncio.run(r.decide(alert))                                    # Qwen off: nothing saved, retried later
    assert not any(n == "save_alert_report" for n, _ in mcp.calls) and r.next_try[7] > 0
    up["v"] = True
    for _ in range(watcher.MAX_AI_ATTEMPTS):
        r.next_try[7] = 0
        asyncio.run(r.decide(alert))
    resolved = [a for n, a in mcp.calls if n == "resolve_alert"]
    assert resolved and resolved[-1]["decision"] == "escalate"
    assert AGENT_TOKEN


def test_model_that_forgets_to_decide_is_asked_once():
    import httpx

    from mcp_threatintel.watch.llm import investigate

    class MCP:
        def __init__(self):
            self.calls = []

        async def list_tools(self):
            return [SimpleNamespace(name="resolve_alert", description="decide", inputSchema={"type": "object"})]

        async def call_tool(self, name, args):
            self.calls.append((name, args))
            return SimpleNamespace(content=[SimpleNamespace(text=json.dumps({"resolution": "executed"}))])

    replies = iter([
        {"content": "VERDICT: true positive - high"},                                     # forgot to decide
        {"tool_calls": [{"id": "r", "function": {"name": "resolve_alert",
                                                 "arguments": '{"alert_id": 21, "decision": "execute", '
                                                              '"justification": "Confirmed C2."}'}}]},
        {"content": "DECISION: executed"},
    ])
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", **next(replies)}}]})

    mcp = MCP()
    report, _ = asyncio.run(investigate(mcp, "http://llm", "alert", decide_alert=21,
                                        transport=httpx.MockTransport(handler)))
    assert [c[0] for c in mcp.calls] == ["resolve_alert"]
    assert "resolve_alert now" in sent[1]["messages"][-1]["content"] and report.startswith("VERDICT")


def test_connection_seen_before_the_kill_is_not_persisting(agent):  # noqa: F811
    agent.detector.rules_execute = True
    conn = {"remote_ip": "45.1.2.3", "remote_port": 443, "pid": 999999, "process": "curl"}
    agent.detector.on_connection(conn)
    (alert,) = _raise(agent, None, None)
    asyncio.run(agent.process_approved())                    # the block runs (the kill of a gone PID is refused)
    agent.db.save_resolution(alert["id"], "executed", "rules", "contained")
    agent.detector.on_connection({**conn, "observed_at": 2e10})   # sampled history, process already gone
    assert _raise(agent, None, None) == []                   # no "CONTAINED but persisting" alert


JOURNAL = """2026-11-13T08:48:31+00:00 devsecops sudo[2128]:    ahmed : TTY=pts/1 ; PWD=/home/ahmed ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash labuser3
2026-11-13T08:48:31+00:00 devsecops useradd[2130]: new user: name=labuser3, UID=1001, GID=1001, home=/home/labuser3, shell=/bin/bash, from=/dev/pts/1
2026-11-13T08:48:40+00:00 devsecops sudo[2138]:    ahmed : TTY=pts/0 ; PWD=/home/ahmed ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo labuser3
2026-11-13T08:48:40+00:00 devsecops usermod[2140]: add 'labuser3' to group 'sudo'
2026-11-13T08:49:00+00:00 devsecops sudo[2150]:    bob : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd backdoor"""
LAST = """ahmed    pts/1        192.168.21.1     Fri Nov 13 08:40   still logged in
ahmed    pts/0        192.168.21.1     Fri Nov 13 08:30   still logged in
bob      pts/3        203.0.113.9      Fri Nov 13 08:45   still logged in"""


def test_change_origin_says_who_made_an_account_change():
    from mcp_threatintel.responder.forensics import change_origin
    from mcp_threatintel.responder.validators import Allowlist
    allow = Allowlist([{"value": "192.168.21.1/32", "type": "cidr", "comment": "analyst PC"}])
    ok = change_origin(["labuser3"], allowlist=allow, admins=("root", "ahmed"), journal=JOURNAL, logins=LAST)
    sudo_runs = [m for m in ok["made_by"] if m["via"].startswith("sudo")]
    assert sudo_runs and all(m["user"] == "ahmed" and m["known_admin"] and m["from_ip"] == "192.168.21.1"
                             and m["from_allowlisted"] for m in sudo_runs)
    bad = change_origin(["backdoor"], allowlist=allow, admins=("root", "ahmed"), journal=JOURNAL, logins=LAST)
    (m,) = bad["made_by"]
    assert m["user"] == "bob" and not m["known_admin"] and m["from_ip"] == "203.0.113.9" and not m["from_allowlisted"]
    none = change_origin(["ghost"], journal=JOURNAL, logins=LAST)
    assert none["made_by"] == [] and "no record" in none["note"]
