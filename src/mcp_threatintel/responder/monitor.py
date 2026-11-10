"""Background collectors run by the host agent (read-only observation).

* ConnectionSampler - remote endpoints seen by psutil every few seconds, so a
  short-lived beacon is still caught by the next scan.
* DnsMonitor - every name the server resolves, read live from
  ``resolvectl monitor --json=short`` (systemd-resolved; all local programs
  and the host-network containers resolve through the 127.0.0.53 stub).

* FileWatcher - Linux inotify (ctypes, no extra package): a file closed after
  writing, or moved into a watched folder, is reported at once.

Both keep a bounded, time-limited memory; scans read it. Each collector also
calls an ``on_new`` callback the first time it sees something, so detection is
event-driven (the periodic scan remains as a safety net).
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import shutil
import struct
import sys
import time
from collections import OrderedDict
from pathlib import Path

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
    def __init__(self, interval_s: float = 2.0, on_new=None):
        self.interval_s = interval_s
        self.seen = _Ring()
        self.on_new = on_new  # callback(record) for an endpoint not seen in the last hour

    def sample(self, now: float | None = None) -> None:
        now = now or time.time()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return
        for c in conns:
            if not c.raddr:
                continue
            key = (c.raddr.ip, c.raddr.port, c.pid)
            is_new = key not in self.seen.items
            self.seen.upsert(key, now,
                             remote_ip=c.raddr.ip, remote_port=c.raddr.port,
                             local_port=c.laddr.port if c.laddr else None,
                             status=c.status, pid=c.pid, process=_proc_name(c.pid))
            if is_new and self.on_new:
                try:
                    self.on_new(dict(self.seen.items[key]))
                except Exception:  # a callback problem must never stop sampling
                    logger.exception("connection callback failed")

    async def run(self) -> None:
        while True:
            await asyncio.to_thread(self.sample)
            await asyncio.sleep(self.interval_s)


class DnsMonitor:
    def __init__(self, on_new=None):
        self.seen = _Ring()
        self.on_new = on_new  # callback(name, record) for a name not resolved in the last hour
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
                is_new = name not in self.seen.items
                prev = self.seen.items.get(name, {}).get("answers", [])
                self.seen.upsert(name, now, domain=name, answers=sorted(set(prev + answers))[:10])
                if is_new and self.on_new:
                    try:
                        self.on_new(name, dict(self.seen.items[name]))
                    except Exception:
                        logger.exception("DNS callback failed")

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


# --- inotify file watcher ------------------------------------------------------

IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000
_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
_EVENT = struct.Struct("iIII")


def parse_inotify(data: bytes) -> list[tuple[int, int, str]]:
    """(watch descriptor, mask, name) for each struct inotify_event in a read buffer."""
    out, off = [], 0
    while off + _EVENT.size <= len(data):
        wd, mask, _cookie, length = _EVENT.unpack_from(data, off)
        name = data[off + _EVENT.size: off + _EVENT.size + length].split(b"\0", 1)[0]
        out.append((wd, mask, os.fsdecode(name)))
        off += _EVENT.size + length
    return out


class FileWatcher:
    """Reports files written or moved into the watched folders (and their sub-folders)."""

    def __init__(self, paths: list[Path], on_file, max_dirs: int = 2000):
        self.paths = [Path(p) for p in paths]
        self.on_file = on_file
        self.max_dirs = max_dirs
        self.wds: dict[int, str] = {}
        self.fd = -1
        self.available = sys.platform.startswith("linux")
        self.status = "starting" if self.available else "unavailable (Linux inotify only)"

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        if not self.available:
            return
        try:
            self._libc = ctypes.CDLL(None, use_errno=True)
            self.fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
            if self.fd < 0:
                raise OSError(ctypes.get_errno(), "inotify_init1 failed")
            for root in self.paths:
                if root.is_dir():
                    for dirpath, _dirs, _files in os.walk(root):
                        if not self._add(dirpath):
                            break
            loop.add_reader(self.fd, self._readable)
            self.status = f"watching {len(self.wds)} folder(s)"
        except Exception as e:
            self.status = f"error: {e}"
            logger.warning("file watcher: %s", e)

    def _add(self, directory: str) -> bool:
        if len(self.wds) >= self.max_dirs:
            return False
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(directory), _MASK)
        if wd >= 0:
            self.wds[wd] = directory
        return True

    def _readable(self) -> None:
        try:
            data = os.read(self.fd, 65536)
        except (BlockingIOError, InterruptedError):
            return
        for wd, mask, name in parse_inotify(data):
            if mask & IN_Q_OVERFLOW:
                self.status = "queue overflow (the periodic scan covers the gap)"
                continue
            if mask & IN_IGNORED:
                self.wds.pop(wd, None)
                continue
            base = self.wds.get(wd)
            if not base or not name:
                continue
            path = os.path.join(base, name)
            if mask & IN_ISDIR:
                if mask & (IN_CREATE | IN_MOVED_TO):
                    self._add(path)
            elif mask & (IN_CLOSE_WRITE | IN_MOVED_TO):
                try:
                    self.on_file(path)
                except Exception:
                    logger.exception("file callback failed")
