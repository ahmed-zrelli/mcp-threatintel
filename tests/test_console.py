"""Dashboard (admin channel only), decision switch, analyst rollback, report generator."""

from __future__ import annotations

import asyncio

import pytest
from starlette.testclient import TestClient

from mcp_threatintel.console.dashboard import create_app
from mcp_threatintel.responder.protocol import ProtocolError
from mcp_threatintel.responder.report import build_report
from test_responder import ADMIN_TOKEN, AGENT_TOKEN, agent, backend, call, config, ioc_db  # noqa: F401

SESSION = "test-session-token"


class DirectAdmin:
    """The dashboard's AdminClient, wired straight to the agent's admin handler."""

    def __init__(self, host_agent):
        self.agent = host_agent
        self.ops = []

    async def call(self, op, **params):
        params.setdefault("actor", "dashboard:test")
        self.ops.append(op)
        resp = await self.agent.handle_admin({"op": op, "params": params, "token": ADMIN_TOKEN})
        if not resp["ok"]:
            raise ProtocolError(resp["error"])
        return resp["data"]


@pytest.fixture
def web(agent):  # noqa: F811
    admin = DirectAdmin(agent)
    client = TestClient(create_app(admin, SESSION), base_url="http://127.0.0.1:3720")
    client.headers["X-Dashboard-Token"] = SESSION
    return client, admin


def _alert_with_action(agent):  # noqa: F811
    eng = agent.detector
    eng.on_connection({"remote_ip": "45.1.2.3", "remote_port": 443, "pid": None, "process": "curl"})
    ids = []
    while not eng.events.empty():
        ids += eng.process_event(eng.events.get_nowait())
    alert = agent.db.get_alert(ids[0])
    return alert, alert["action_ids"][0]


def test_page_and_api_guards(web):
    client, _ = web
    page = client.get("/")
    assert page.status_code == 200 and SESSION in page.text and "Content-Security-Policy" in page.headers
    assert client.get("/api/overview", headers={"X-Dashboard-Token": "wrong"}).status_code == 403
    rebinding = TestClient(client.app, base_url="http://evil.example:3720")
    assert rebinding.get("/").status_code == 403
    assert rebinding.get("/api/overview", headers={"X-Dashboard-Token": SESSION}).status_code == 403


def test_dashboard_approve_and_rollback(web, agent):  # noqa: F811
    client, admin = web
    alert, action_id = _alert_with_action(agent)
    o = client.get("/api/overview").json()
    assert [a["id"] for a in o["pending"]] == [action_id]
    assert o["alerts"][0]["id"] == alert["id"] and o["status"]["decision"]["mode"] == "human"
    assert client.post(f"/api/actions/{action_id}/approve").json()["status"] == "approved"
    asyncio.run(agent.process_approved())
    o = client.get("/api/overview").json()
    assert [a["id"] for a in o["active"]] == [action_id] and o["pending"] == []
    rb = client.post(f"/api/actions/{action_id}/rollback", json={"reason": "test"}).json()
    assert rb["type"] == "rollback" and rb["status"] == "approved"
    asyncio.run(agent.process_approved())
    assert agent.db.get_action(action_id)["status"] == "rolled_back"
    # only admin-channel operations were used
    assert set(admin.ops) <= {"overview", "approve", "rollback"}
    actors = {e["actor"] for e in agent.db.audit(limit=50)}
    assert "analyst:dashboard:test" in actors


def test_decision_switch_is_persisted_and_audited(web, agent, config):  # noqa: F811
    client, _ = web
    assert client.post("/api/mode", json={"mode": "ai"}).json()["mode"] == "ai"
    assert agent.config.autonomy is True
    assert client.post("/api/mode", json={"mode": "maybe"}).status_code == 502
    assert any(e["event"] == "decision_mode" and e["details"]["mode"] == "ai" for e in agent.db.audit(limit=20))
    # a restarted agent keeps the analyst's choice even if AUTONOMY is off in its config
    from mcp_threatintel.responder.agent import HostAgent
    config.autonomy = False
    again = HostAgent(config, admin_token=ADMIN_TOKEN, discover=False, backends=agent.backends)
    assert again.config.autonomy is True and again.autonomy.status()["mode"] == "ai"
    # the agent channel (the model) cannot flip the switch
    assert not call(agent, "agent", "set_decision_mode", mode="human")["ok"]


def test_report_contains_facts_and_labelled_ai_text(agent):  # noqa: F811
    alert, action_id = _alert_with_action(agent)
    call(agent, "admin", "approve", id=action_id, actor="alice")
    asyncio.run(agent.process_approved())
    call(agent, "agent", "save_alert_report", alert_id=alert["id"], report="Verdict: TRUE POSITIVE <b>x</b>", by="qwen")
    md = build_report(agent.db, hours=24, dry_run=True, decision_mode="human")
    for section in ("## 1. Summary", "## 2. Timeline", "## 3. Incidents", "## 4. Problems", "## 5. Response",
                    "## 6. Recommended follow-up", "## 7. AI analysis", "## 8. Audit trail"):
        assert section in md
    assert "45.1.2.3" in md and "analyst:alice" in md and "executed" in md
    assert "> Verdict: TRUE POSITIVE &lt;b>x&lt;/b>" in md
    by_incident = call(agent, "admin", "report", incident_id=alert["incident_id"])["data"]["markdown"]
    assert f"incident #{alert['incident_id']}" in by_incident
    assert call(agent, "agent", "report", hours=1)["ok"]                    # the model can read it too
