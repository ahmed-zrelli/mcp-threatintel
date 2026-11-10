"""Event-driven detection: collector callbacks, inotify parsing, file events, long polling."""

from __future__ import annotations

import asyncio
import json
import struct
import time

from mcp_threatintel.responder.alerts import AlertEngine
from mcp_threatintel.responder.monitor import (
    IN_CLOSE_WRITE, IN_CREATE, IN_ISDIR, ConnectionSampler, DnsMonitor, parse_inotify,
)
from test_responder import AGENT_TOKEN, agent, backend, config, ioc_db  # noqa: F401  (shared fixtures)


def test_dns_callback_fires_once_per_new_name():
    seen = []
    dns = DnsMonitor(on_new=lambda name, rec: seen.append(name))
    line = json.dumps({"question": [{"name": "c2.lab.test."}]})
    dns.handle_line(line)
    dns.handle_line(line)
    assert seen == ["c2.lab.test"]


def test_sampler_callback_fires_once_per_new_endpoint(monkeypatch):
    import psutil
    from types import SimpleNamespace as NS

    conn = NS(raddr=NS(ip="45.1.2.3", port=443), laddr=NS(port=50000), status="ESTABLISHED", pid=None)
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [conn])
    got = []
    s = ConnectionSampler(on_new=got.append)
    s.sample()
    s.sample()
    assert len(got) == 1 and got[0]["remote_ip"] == "45.1.2.3"


def test_parse_inotify_events():
    def ev(wd, mask, name):
        raw = name.encode() + b"\0" * (16 - len(name))
        return struct.pack("iIII", wd, mask, 0, len(raw)) + raw
    data = ev(1, IN_CLOSE_WRITE, "update.bin") + ev(2, IN_CREATE | IN_ISDIR, "newdir")
    assert parse_inotify(data) == [(1, IN_CLOSE_WRITE, "update.bin"), (2, IN_CREATE | IN_ISDIR, "newdir")]


def test_events_raise_alerts_without_waiting_for_the_scan(agent, config, ioc_db):  # noqa: F811
    import sqlite3

    from mcp_threatintel.responder.backends.quarantine import sha256_file

    eng = agent.detector
    raised = []
    eng.on_alert = raised.append
    # DNS lookup of a lab domain (local_iocs has c2.lab.test in the ioc_db fixture)
    eng.on_dns("c2.lab.test", {"count": 1, "answers": []})
    # connection to a Feodo IP
    eng.on_connection({"remote_ip": "45.1.2.3", "remote_port": 443, "pid": None, "process": "curl"})
    # file written in a watched folder
    f = config.scan_paths[0] / "drop.bin"
    f.write_bytes(b"event payload")
    c = sqlite3.connect(ioc_db)
    c.execute("INSERT INTO local_iocs (value, type) VALUES (?, 'hash_sha256')", (sha256_file(f),))
    c.commit()
    c.close()
    eng.scanner.iocs.refresh_s = 0
    eng.on_file(str(f))
    eng.on_file(str(config.scan_paths[0].parent / "outside.bin"))   # outside scan paths: ignored
    while not eng.events.empty():
        eng.process_event(eng.events.get_nowait())
    kinds = {a["kind"] for a in agent.db.list_alerts()}
    assert kinds == {"malicious_dns", "c2_connection", "malicious_file"} and len(raised) == 3
    assert eng.event_alerts == 3
    eng.on_dns("c2.lab.test", {"count": 2})                           # same finding again: no new alert
    eng.process_event(eng.events.get_nowait())
    assert len(agent.db.list_alerts()) == 3


def test_long_poll_returns_as_soon_as_an_alert_is_raised(agent):  # noqa: F811
    async def scenario():
        agent._loop = asyncio.get_running_loop()
        first = agent.db.insert_alert(key="a", kind="c2_connection", severity="high", title="old",
                                      detail={}, action_ids=[])

        async def raise_later():
            await asyncio.sleep(0.3)
            agent.db.insert_alert(key="b", kind="malicious_dns", severity="high", title="new", detail={},
                                  action_ids=[])
            agent._alert_raised(0)

        t0 = time.monotonic()
        asyncio.create_task(raise_later())
        resp = await agent.handle_agent({"op": "list_alerts", "params": {"since_id": first, "wait_s": 10},
                                         "token": AGENT_TOKEN})
        return resp, time.monotonic() - t0

    resp, elapsed = asyncio.run(scenario())
    assert resp["ok"] and [a["title"] for a in resp["data"]] == ["new"]
    assert elapsed < 2                                                # woke up immediately, not after 10 s


def test_long_poll_times_out_quietly(agent):  # noqa: F811
    async def scenario():
        agent._loop = asyncio.get_running_loop()
        a = agent.db.insert_alert(key="a", kind="x", severity="low", title="t", detail={}, action_ids=[])
        return await agent.handle_agent({"op": "list_alerts", "params": {"since_id": a, "wait_s": 0.3},
                                         "token": AGENT_TOKEN})
    assert asyncio.run(scenario())["data"] == []


def test_engine_queue_is_bounded():
    eng = AlertEngine.__new__(AlertEngine)
    import queue
    eng.events = queue.Queue(maxsize=1)
    eng._submit(("file", "a"))
    eng._submit(("file", "b"))                                        # dropped, never blocks a collector
    assert eng.events.qsize() == 1
