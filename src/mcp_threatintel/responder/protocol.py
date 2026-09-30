"""Newline-delimited JSON over TCP (Windows) or a Unix socket (Linux).

Request:  {"op": "...", "params": {...}, "token": "..."}\\n
Response: {"ok": true, "data": ...}\\n  or  {"ok": false, "error": "..."}\\n

Addresses: ``tcp://127.0.0.1:3710`` or ``unix:///run/threatintel/agent.sock``.
TCP listeners must be loopback: the agent refuses to bind anywhere else.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from urllib.parse import urlparse

MAX_LINE = 1024 * 1024


class ProtocolError(RuntimeError):
    pass


def parse_addr(addr: str) -> tuple[str, str, int | None]:
    u = urlparse(addr)
    if u.scheme == "tcp":
        if not u.hostname or not u.port:
            raise ProtocolError(f"bad tcp address {addr!r}")
        return "tcp", u.hostname, u.port
    if u.scheme == "unix":
        return "unix", (u.netloc + u.path) or u.path, None
    raise ProtocolError(f"address must start with tcp:// or unix://, got {addr!r}")


async def serve(addr: str, handler, *, unix_mode: int = 0o660) -> asyncio.base_events.Server:
    """Start a listener; ``handler(dict) -> dict`` is awaited per request line."""

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                try:
                    line = await reader.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    await _send(writer, {"ok": False, "error": "request too large"})
                    break
                if not line:
                    break
                try:
                    req = json.loads(line)
                    if not isinstance(req, dict):
                        raise ValueError
                except ValueError:
                    await _send(writer, {"ok": False, "error": "invalid JSON request"})
                    continue
                await _send(writer, await handler(req))
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    kind, host, port = parse_addr(addr)
    if kind == "tcp":
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ProtocolError("refusing to expose the agent on a non-loopback address")
        return await asyncio.start_server(on_client, host, port, limit=MAX_LINE)
    path = host
    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    server = await asyncio.start_unix_server(on_client, path, limit=MAX_LINE)
    os.chmod(path, unix_mode)
    return server


async def _send(writer: asyncio.StreamWriter, payload: dict) -> None:
    writer.write(json.dumps(payload, default=str).encode() + b"\n")
    await writer.drain()


async def request(addr: str, op: str, params: dict | None, token: str, timeout: float = 30) -> dict:
    """Async one-shot request (used by the MCP server)."""
    kind, host, port = parse_addr(addr)
    try:
        if kind == "tcp":
            conn = asyncio.open_connection(host, port, limit=MAX_LINE)
        else:
            conn = asyncio.open_unix_connection(host, limit=MAX_LINE)
        reader, writer = await asyncio.wait_for(conn, timeout)
    except (OSError, asyncio.TimeoutError) as e:
        raise ProtocolError(f"host agent unreachable at {addr} ({e}); is threatintel-responder running?") from e
    try:
        writer.write(json.dumps({"op": op, "params": params or {}, "token": token}).encode() + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
    finally:
        writer.close()
    if not line:
        raise ProtocolError("host agent closed the connection")
    return json.loads(line)


def request_sync(addr: str, op: str, params: dict | None, token: str, timeout: float = 30) -> dict:
    """Blocking one-shot request (used by the approval CLI)."""
    kind, host, port = parse_addr(addr)
    try:
        if kind == "tcp":
            sock = socket.create_connection((host, port), timeout=timeout)
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(host)
    except OSError as e:
        raise ProtocolError(f"host agent unreachable at {addr} ({e}); is threatintel-responder running?") from e
    with sock:
        sock.sendall(json.dumps({"op": op, "params": params or {}, "token": token}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE:
                raise ProtocolError("response too large")
    if not buf:
        raise ProtocolError("host agent closed the connection")
    return json.loads(buf)
