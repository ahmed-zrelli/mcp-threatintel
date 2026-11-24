"""slim.to_json shrinks tool results without losing information."""

import json
from datetime import datetime

from mcp_threatintel.slim import to_json


def test_compact_json_is_equivalent_and_smaller():
    data = {"id": 7, "title": "Malicious domain", "nested": {"a": [1, 2, 3], "b": {"c": "é"}}}
    out = to_json(data)
    assert json.loads(out) == data
    assert "\n" not in out and ": " not in out
    assert "é" in out                                  # real characters, not é
    assert len(out) < len(json.dumps(data, indent=2))


def test_drops_only_null_and_empty_string_keys():
    data = {"a": None, "b": "", "c": [], "d": {}, "e": 0, "f": False, "g": "x", "h": [None, ""]}
    assert json.loads(to_json(data)) == {"c": [], "d": {}, "e": 0, "f": False, "g": "x", "h": [None, ""]}


def test_empty_results_stay_visible():
    out = json.loads(to_json({"malicious": False, "match_count": 0, "matches": [], "otx_pulses": []}))
    assert out == {"malicious": False, "match_count": 0, "matches": [], "otx_pulses": []}


def test_identical_entries_are_counted_not_lost():
    conn = {"remote": "9.9.9.9:443", "pid": 12}
    out = json.loads(to_json({"connections": [conn, {"remote": "1.1.1.1:53", "pid": 3}, dict(conn), dict(conn)]}))
    assert out["connections"] == [{**conn, "repeated": 3}, {"remote": "1.1.1.1:53", "pid": 3}]


def test_distinct_entries_and_order_are_untouched():
    alerts = [{"id": i, "title": f"t{i}", "detail": {"route": "ai"}} for i in (5, 6, 7)]
    assert json.loads(to_json(alerts)) == alerts


def test_non_json_values_fall_back_to_str():
    out = json.loads(to_json({"when": datetime(2026, 11, 23, 4, 0, 0)}))
    assert out["when"].startswith("2026-11-23")


def test_very_long_string_is_cut_with_a_marker(monkeypatch):
    monkeypatch.setenv("MCP_RESULT_MAX_STR", "500")
    out = json.loads(to_json({"log": "x" * 2000, "short": "ok"}))
    assert out["log"].startswith("x" * 500) and "1500 more characters omitted" in out["log"]
    assert out["short"] == "ok"


def test_opt_out_restores_indented_output(monkeypatch):
    monkeypatch.setenv("MCP_COMPACT", "0")
    data = {"a": None, "b": [1]}
    assert to_json(data) == json.dumps(data, indent=2)
