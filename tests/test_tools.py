"""Tool smoke tests: exercise the MCP tool functions end-to-end against a
temp DB (DB_PATH is set by conftest.py before the server is imported).

The server module's @mcp.tool() decorator wraps each function; we call the
underlying coroutine via .fn to invoke the real logic without an MCP client.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel import db, server  # noqa: E402
from mcp_threatintel.clients.abusech import _split_ip_port  # noqa: E402


def _call(tool):
    """Return the underlying coroutine function behind a FastMCP tool object."""
    return getattr(tool, "fn", tool)


def _seed_ioc(indicator="9.9.9.9"):
    with db.connect(server.DB_PATH) as conn:
        db.upsert_ioc(
            conn,
            indicator=indicator,
            type="ip",
            source="threatfox",
            first_seen=None,
            last_seen=db._now(),
            tags="botnet",
            confidence=90,
            malware_family="qakbot",
            threat_type="c2",
            raw_json="{}",
        )
        conn.commit()


@pytest.mark.asyncio
async def test_lookup_ioc_finds_seeded_indicator():
    _seed_ioc()
    out = json.loads(await _call(server.lookup_ioc)("9.9.9.9"))
    assert out["indicator"] == "9.9.9.9"
    assert out["malicious"] is True
    assert any(m["source"] == "threatfox" for m in out["matches"])
    # raw_json is stripped from responses.
    assert all("raw_json" not in m for m in out["matches"])


@pytest.mark.asyncio
async def test_lookup_ioc_clean_for_unknown():
    out = json.loads(await _call(server.lookup_ioc)("203.0.113.255"))
    assert out["match_count"] == 0
    assert out["malicious"] is False


def test_threatfox_ip_port_is_split():
    assert _split_ip_port("45.1.2.3:443", "ip:port") == ("45.1.2.3", "443")
    assert _split_ip_port("evil.example", "domain") == ("evil.example", "")


@pytest.mark.asyncio
async def test_legacy_ip_port_rows_still_match_bare_ip():
    _seed_ioc("198.51.100.7:8080")
    out = json.loads(await _call(server.lookup_ioc)("198.51.100.7"))
    assert out["match_count"] == 1


@pytest.mark.asyncio
async def test_lookup_finds_local_lab_ioc():
    with db.connect(server.DB_PATH) as conn:
        db.replace_local_iocs(conn, [{"value": "192.168.56.66", "type": "ip", "comment": "kali"}])
    out = json.loads(await _call(server.lookup_ioc)("192.168.56.66"))
    assert out["malicious"] is True
    assert out["matches"][0]["source"] == "local"


@pytest.mark.asyncio
async def test_action_tool_reports_unreachable_agent(monkeypatch):
    from mcp_threatintel.responder.client import HostAgentClient

    monkeypatch.setattr(server, "_agent", HostAgentClient("tcp://127.0.0.1:9", "t", timeout=2))
    out = json.loads(await _call(server.block_ip)("45.1.2.3", "test"))
    assert "error" in out and "unreachable" in out["error"]
