"""Every tool declares what it does to the world, and the four families stay honest.

v1 was twelve read-only lookups. v2 has twenty tools in four families, and the
manifest alone must let a careful client tell them apart:

* intelligence: read-only; cache tools are closed-world, the two HIBP tools open-world;
* host detection: read-only, closed-world (the host agent reads the machine);
* response: NOT read-only and destructive (once approved);
* governance: not read-only (rollback requests), not destructive.
"""

from __future__ import annotations

import asyncio

import pytest

from mcp_threatintel import server

LOCAL = {
    "lookup_ioc", "search_threats", "get_recent_threats", "lookup_cve",
    "get_feed_status", "search_pulses",
}
REMOTE = {"check_password_breach", "get_latest_breach"}
HOST = {"scan_network_connections", "scan_files", "check_auth_logs", "scan_host", "list_alerts",
        "investigate_host", "related_iocs", "list_incidents"}
ACTIONS = {"block_ip", "sinkhole_domain", "quarantine_file", "kill_process", "block_feed_c2", "resolve_alert",
           "lock_user"}
GOVERNANCE = {"list_actions", "get_action_status", "rollback_action", "save_alert_report"}


@pytest.fixture(scope="module")
def tools():
    """The live manifest, not the source. What a client would receive."""
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_the_expected_twenty_seven_are_present(tools):
    assert set(tools) == LOCAL | REMOTE | HOST | ACTIONS | GOVERNANCE
    assert len(tools) == 27


def test_every_tool_is_annotated(tools):
    assert sorted(n for n, t in tools.items() if t.annotations is None) == []


def test_intelligence_and_detection_are_read_only(tools):
    wrong = sorted(n for n in LOCAL | REMOTE | HOST if not tools[n].annotations.read_only_hint)
    assert wrong == []


def test_response_tools_declare_they_are_destructive(tools):
    wrong = sorted(
        n for n in ACTIONS
        if tools[n].annotations.read_only_hint or not tools[n].annotations.destructive_hint
    )
    assert wrong == []


def test_only_response_tools_are_destructive(tools):
    assert {n for n, t in tools.items() if t.annotations.destructive_hint} == ACTIONS


def test_only_hibp_is_open_world(tools):
    assert {n for n, t in tools.items() if t.annotations.open_world_hint} == REMOTE


def test_there_is_no_approve_tool(tools):
    """Approval must stay outside the model's reach (spec §4.D / §11)."""
    assert not [n for n in tools if "approve" in n]
