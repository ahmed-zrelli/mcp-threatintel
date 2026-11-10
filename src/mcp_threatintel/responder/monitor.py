"""Background collectors run by the host agent (read-only observation).

* ConnectionSampler - remote endpoints seen by psutil every few seconds, so a
  short-lived beacon is still caught by the next scan.
* DnsMonitor - every name the server resolves, read live from
  ``resolvectl monitor --json=short`` (systemd-resolved; all local programs
  and the host-network containers resolve through the 127.0.0.53 stub).

Both keep a bounded, time-limited memory; scans read it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
import time
from collections import OrderedDict

import psutil

logger = logging.getLogger("threatintel.responder.monitor")

KEEP_S = 3600          # remember observations for one hour
MAX_ENTRIES = 5000


def _proc_name(pid):
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


class _Ring:
    """key -> record, oldest evicted first, expired after KEEP_S."""

    def __init__(self):
        self.items: OrderedDict = OrderedDict()

    def upsert(self, key, now: float, **fields) -> None:
        rec = self.items.pop(key, None) or {"first_seen": now, "count": 0}
        rec.update(fields)
        rec["last_seen"] = now
        rec["count"] += 1
        self.items[key] = rec
        while len(self.items) > MAX_ENTRIES:
            self.items.popitem(last=False)

    def recent(self, window_s: float, now: float | None = None) -> list[tuple]:
        now = now or time.time()
        for k in [k for k, r in self.items.items() if now - r["last_seen"] > KEEP_S]:
            del self.items[k]
        return [(k, r) for k, r in self.items.items() if now - r["last_seen"] <= window_s]


class ConnectionSampler:
    def __init__(self, interval_s: float = 2.0):
        self.interval_s = interval_s
        self.seen = _Ring()

    def sample(self, now: float | None = None) -> None:
        now = now or time.time()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return
        for c in conns:
            if not c.raddr:
                continue
            self.seen.upsert((c.raddr.ip, c.raddr.port, c.pid), now,
                             remote_ip=c.raddr.ip, remote_port=c.raddr.port,
                             local_port=c.laddr.port if c.laddr else None,
                             status=c.status, pid=c.pid, process=_proc_name(c.pid))

    async def run(self) -> None:
        while True:
            await asyncio.to_thread(self.sample)
            await asyncio.sleep(self.interval_s)


class DnsMonitor:
    def __init__(self):
        self.seen = _Ring()
        self.available = sys.platform != "win32" and shutil.which("resolvectl") is not None
        self.status = "starting" if self.available else "unavailable (needs systemd-resolved)"

    def handle_line(self, line: str, now: float | None = None) -> None:
        now = now or time.time()
        try:
            msg = json.loads(line)
        except ValueError:
            return
        answers = []
        for a in msg.get("answer") or []:
            rr = a.get("rr") or a
            addr = rr.get("address")
            if isinstance(addr, list):  # resolved prints addresses as byte lists
                addr = ".".join(map(str, addr)) if len(addr) == 4 else None
            if isinstance(addr, str):
                answers.append(addr)
        for q in msg.get("question") or []:
            name = (q.get("name") or "").lower().rstrip(".")
            if name:
                prev = self.seen.items.get(name, {}).get("answers", [])
                self.seen.upsert(name, now, domain=name, answers=sorted(set(prev + answers))[:10])

    async def run(self) -> None:
        if not self.available:
            return
        while True:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "resolvectl", "monitor", "--json=short",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                )
                self.status = "running"
                assert proc.stdout is not None
                async for raw in proc.stdout:
                    self.handle_line(raw.decode(errors="replace"))
                await proc.wait()
                self.status = f"stopped (exit {proc.returncode}), restarting"
            except Exception as e:
                self.status = f"error: {e}"
                logger.warning("DNS monitor: %s", e)
            await asyncio.sleep(10)
