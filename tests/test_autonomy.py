"""Autonomous mode: the model resolves alerts, inside server-side guardrails."""

from __future__ import annotations

import asyncio

import pytest

from mcp_threatintel.responder.autonomy import Autonomy
from mcp_threatintel.responder.validators import ValidationError
from test_responder import AGENT_TOKEN, agent, backend, call, config, ioc_db  # noqa: F401  (shared fixtures)


def make_alert(agent, actions):  # noqa: F811
    """An alert whose pending actions were created by detection (requested_by auto-detect)."""
    ids = [agent.manager.create(t, p, "detected", "auto-detect")["id"] for t, p in actions]
    return agent.db.insert_alert(key=f"k{ids}", kind="c2_connection", severity="critical", title="C2",
                                 detail={}, action_ids=ids), ids


def auto(agent, on=True, **kw):  # noqa: F811
    agent.config.autonomy = on
    for k, v in kw.items():
        setattr(agent.config, k, v)
    return Autonomy(agent.db, agent.manager, agent.config)


def test_off_by_default_only_records_a_recommendation(agent, backend):  # noqa: F811
    alert, ids = make_alert(agent, [("block_ip", {"ip": "45.1.2.3"})])
    out = auto(agent, on=False).resolve(alert, "execute", "Feodo C2 confirmed by two feeds.")
    assert out["autonomy"] is False and out["recorded_as"] == "recommended_execute"
    assert agent.db.get_action(ids[0])["status"] == "pending"
    asyncio.run(agent.process_approved())
    assert backend.applied == []


def test_execute_runs_every_action_of_the_alert_including_kill(agent, backend):  # noqa: F811
    import subprocess
    import sys

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        alert, ids = make_alert(agent, [("kill_process", {"pid": proc.pid}), ("block_ip", {"ip": "45.1.2.3"})])
        out = auto(agent).resolve(alert, "execute", "Process beacons to a confirmed Feodo C2.")
        assert out["resolution"] == "executed" and out["left_for_human"] == []
        assert sorted(h["type"] for h in out["handled"]) == ["block_ip", "kill_process"]
        asyncio.run(agent.process_approved())
        for i in ids:
            assert agent.db.get_action(i)["status"] == "executed"
            assert agent.db.get_action(i)["approved_by"] == "qwen-autonomous"
    finally:
        proc.kill()


def test_autonomy_actions_still_limits_types(agent):  # noqa: F811
    alert, ids = make_alert(agent, [("sinkhole_domain", {"domain": "evil.example"})])
    out = auto(agent, autonomy_actions=("block_ip",)).resolve(alert, "execute", "Domain confirmed malicious.")
    assert out["left_for_human"][0]["type"] == "sinkhole_domain"
    assert agent.db.get_action(ids[0])["status"] == "pending"


def test_model_requests_are_executed_at_once(agent, backend):  # noqa: F811
    agent.config.autonomy = True
    act = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.3"}, reason="C2")["data"]
    assert act["status"] == "approved" and act["approved_by"] == "qwen-autonomous"
    asyncio.run(agent.process_approved())
    assert agent.db.get_action(act["id"])["status"] == "executed"
    rb = call(agent, "agent", "request_rollback", id=act["id"], reason="false positive")["data"]
    assert rb["status"] == "approved"
    asyncio.run(agent.process_approved())
    assert agent.db.get_action(act["id"])["status"] == "rolled_back"
    # validation and the allowlist still refuse, and the hourly limit leaves the rest pending
    assert call(agent, "agent", "create_action", type="block_ip", params={"ip": "8.8.8.8"},
                reason="x")["data"]["status"] == "rejected"
    agent.config.autonomy_max_per_hour = 0
    left = call(agent, "agent", "create_action", type="block_ip", params={"ip": "45.1.2.9"}, reason="x")["data"]
    assert left["status"] == "pending" and "hourly" in left["left_pending"]


def test_ai_mode_is_forced_from_the_environment(monkeypatch):
    from mcp_threatintel.responder.config import ResponderConfig
    monkeypatch.setenv("AUTONOMY", "off")
    c = ResponderConfig.from_env()
    assert c.autonomy is True and "kill_process" in c.autonomy_actions and "lock_user" in c.autonomy_actions

def test_only_the_alerts_own_actions_can_be_approved(agent):  # noqa: F811
    other = agent.manager.create("block_ip", {"ip": "45.1.2.4"}, "created by the model", "mcp-server")
    alert, ids = make_alert(agent, [("sinkhole_domain", {"domain": "evil.example"})])
    auto(agent).resolve(alert, "execute", "Domain confirmed malicious in ThreatFox.")
    assert agent.db.get_action(ids[0])["status"] == "approved"
    assert agent.db.get_action(other["id"])["status"] == "pending"        # not part of the alert


def test_dismiss_and_escalate(agent):  # noqa: F811
    a1, ids1 = make_alert(agent, [("block_ip", {"ip": "45.1.2.3"})])
    assert auto(agent).resolve(a1, "dismiss", "Benign: known update server.")["resolution"] == "dismissed"
    assert agent.db.get_action(ids1[0])["status"] == "rejected"
    a2, ids2 = make_alert(agent, [("block_ip", {"ip": "45.1.2.4"})])
    assert auto(agent).resolve(a2, "escalate", "Evidence is contradictory.")["resolution"] == "escalated"
    assert agent.db.get_action(ids2[0])["status"] == "pending"


def test_hourly_limit_and_allowlist_recheck(agent):  # noqa: F811
    a1, _ = make_alert(agent, [("block_ip", {"ip": "45.1.2.3"})])
    a2, ids2 = make_alert(agent, [("block_ip", {"ip": "45.1.2.4"})])
    au = auto(agent, autonomy_max_per_hour=1)
    assert au.resolve(a1, "execute", "Confirmed C2 address.")["resolution"] == "executed"
    out = au.resolve(a2, "execute", "Confirmed C2 address.")
    assert out["left_for_human"][0]["reason"] == "hourly autonomous limit reached"
    assert agent.db.get_action(ids2[0])["status"] == "pending"
    a3, ids3 = make_alert(agent, [("block_ip", {"ip": "45.1.2.5"})])
    agent.allowlist.add("45.1.2.0/24", "cidr", "added after detection")
    auto(agent, autonomy_max_per_hour=50).resolve(a3, "execute", "Confirmed C2 address.")
    assert agent.db.get_action(ids3[0])["status"] == "rejected"          # allowlist still wins


def test_input_checks_and_single_resolution(agent):  # noqa: F811
    a, _ = make_alert(agent, [("block_ip", {"ip": "45.1.2.3"})])
    au = auto(agent)
    with pytest.raises(ValidationError):
        au.resolve(a, "approve-everything", "Confirmed C2 address.")
    with pytest.raises(ValidationError):
        au.resolve(a, "execute", "ok")                                     # justification required
    au.resolve(a, "escalate", "Unsure about this one.")
    assert au.resolve(a, "execute", "Changed my mind, execute.")["already_resolved"] == "escalated"


def test_resolve_alert_through_the_agent_channel(agent):  # noqa: F811
    a, ids = make_alert(agent, [("block_ip", {"ip": "45.1.2.3"})])
    agent.config.autonomy = True
    resp = call(agent, "agent", "resolve_alert", alert_id=a, decision="execute",
                justification="Confirmed Feodo C2 with an active connection.")
    assert resp["ok"] and resp["data"]["resolution"] == "executed"
    full = call(agent, "agent", "list_alerts", alert_id=a)["data"]
    assert full["autonomy"]["enabled"] is True and full["resolution"] == "executed"
    assert AGENT_TOKEN  # fixture import kept explicit
