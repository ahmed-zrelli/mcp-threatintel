"""Smaller tool results for small context windows, without losing information.

Every MCP tool answers with a JSON string that the local model has to read, and in a chat it is read again
on every later turn. The default serialiser pretty-prints (indent=2) and keeps empty fields, which costs
about a third of the tokens for no information. This module removes only what carries no information:

* whitespace (compact separators) and ``\\uXXXX`` escapes (real characters instead);
* keys whose value is ``null`` or ``""`` (a missing key reads the same; ``[]``, ``{}``, ``0`` and ``false``
  are kept, because "no matches" must stay visible);
* repeated, exactly identical entries of a list (63 identical connections) become one entry with
  ``"repeated": 63``;
* a single string longer than ``MCP_RESULT_MAX_STR`` characters (default 4000: a raw log dump) is cut with
  an explicit marker saying how much was omitted.

Nothing else is dropped or reordered, so list_alerts(since_id) and every other consumer keep working.
``MCP_COMPACT=0`` restores the old indented output.
"""

from __future__ import annotations

import json
import os


def _max_str() -> int:
    try:
        return max(500, int(os.getenv("MCP_RESULT_MAX_STR", "4000")))
    except ValueError:
        return 4000


def _slim(value, max_str: int):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            item = _slim(item, max_str)
            if item is None or item == "":
                continue
            out[key] = item
        return out
    if isinstance(value, list):
        return _group([_slim(item, max_str) for item in value])
    if isinstance(value, str) and len(value) > max_str:
        return f"{value[:max_str]}...[{len(value) - max_str} more characters omitted]"
    return value


def _group(items: list) -> list:
    """Merge exactly identical dict entries (first position kept) and record how many there were."""
    seen: dict[str, int] = {}
    out: list = []
    counts: dict[int, int] = {}
    for item in items:
        if not isinstance(item, dict) or "repeated" in item:
            out.append(item)
            continue
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key in seen:
            counts[seen[key]] += 1
        else:
            seen[key] = len(out)
            counts[len(out)] = 1
            out.append(item)
    for index, count in counts.items():
        if count > 1:
            out[index] = {**out[index], "repeated": count}
    return out


def to_json(data: object) -> str:
    """Serialise a tool result compactly (see the module docstring)."""
    if os.getenv("MCP_COMPACT", "1").strip().lower() in ("0", "false", "no", "off"):
        return json.dumps(data, indent=2, default=str)
    plain = json.loads(json.dumps(data, default=str))   # datetimes, UUIDs, models -> plain JSON values
    return json.dumps(_slim(plain, _max_str()), separators=(",", ":"), ensure_ascii=False)
