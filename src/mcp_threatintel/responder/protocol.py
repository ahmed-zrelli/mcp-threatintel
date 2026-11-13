"""Newline-delimited JSON over a Unix socket, loopback TCP, or TLS.

Request:  {"op": "...", "params": {...}, "token": "..."}\\n
Response: {"ok": true, "data": ...}\\n  or  {"ok": false, "error": "..."}\\n

Addresses (several may be given, comma-separated, for a listener):
  * ``unix:///run/threatintel/agent.sock``  local only (file permissions)
  * ``tcp://127.0.0.1:3710``                 loopback only (refused on any other address)
  * ``tls://0.0.0.0:3712``                   network: the console on the analyst PC talks to the
    agent on the server. The agent presents its certificate (TLS_CERT/TLS_KEY); the client
    trusts ONLY that certificate (AGENT_CA, pinned), so no one else can impersonate the agent
    and nothing travels in clear text. The agent also accepts connections only from
    ALLOWED_CLIENTS (on top of the nftables rule and the token).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import ssl
from urllib.parse import urlparse

MAX_LINE = 1024 * 1024


class ProtocolError(RuntimeError):
    pass


def parse_addr(addr: str) -> tuple[str, str, int | None]:
    u = urlparse(addr.strip())
    if u.scheme in ("tcp", "tls"):
        if not u.hostname or not u.port:
            raise ProtocolError(f"bad {u.scheme} address {addr!r}")
        return u.scheme, u.hostname, u.port
    if u.scheme == "unix":
        return "unix", (u.netloc + u.path) or u.path, None
    raise ProtocolError(f"address must start with unix://, tcp:// or tls://, got {addr!r}")


def split_addrs(addr: str) -> list[str]:
    return [a.strip() for a in str(addr or "").split(",") if a.strip()]


def client_addr(addr: str) -> str:
    """The address a client should use from a (possibly multi-address) setting:
    a local socket first, otherwise the first address that is not a wildcard bind."""
    addrs = split_addrs(addr)
    for a in addrs:
        if a.startswith("unix://") and os.name != "nt":
            return a
    for a in addrs:
        if parse_addr(a)[1] not in ("0.0.0.0", "::"):
            return a
    raise ProtocolError(f"no usable address in {addr!r}")


# --- TLS ---------------------------------------------------------------------------

def server_ssl(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def client_ssl(ca_file: str | None) -> ssl.SSLContext:
    if not ca_file or not os.path.exists(ca_file):
        raise ProtocolError("AGENT_CA must point to the agent's certificate (copied from the server) "
                            "to use a tls:// address")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_file)   # the agent's own certificate is the ONLY trusted one
    ctx.check_hostname = False                   # pinned certificate: the name does not matter
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _allowed(peer, allowed: list[str] | None) -> bool:
    if not allowed:
        return True
    try:
        ip = ipaddress.ip_address(peer[0] if isinstance(peer, tuple) else str(peer))
    except (ValueError, TypeError, IndexError):
        return False
    if ip.is_loopback:
        return True
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    for a in allowed:
        try:
            if ip in ipaddress.ip_network(a, strict=False):
                return True
        except ValueError:
            continue
    return False


# --- server ------------------------------------------------------------------------

async def serve(addr: str, handler, *, unix_mode: int = 0o660, unix_group: str | None = None,
                tls_cert: str | None = None, tls_key: str | None = None,
                allowed_clients: list[str] | None = None, on_denied=None) -> asyncio.base_events.Server:
    """Start ONE listener; ``handler(dict) -> dict`` is awaited per request line.

    For a Unix socket, ``unix_group`` (if it exists) becomes the group of both
    the socket and its directory, and the directory is made 0750: only root
    and that group can reach the socket at all.
    """

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        if kind == "tls" and not _allowed(peer, allowed_clients):
            if on_denied:
                on_denied(peer)
            writer.close()
            return
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
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()

    kind, host, port = parse_addr(addr)
    if kind == "tcp":
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ProtocolError("refusing to expose the agent on a non-loopback address without TLS (use tls://)")
        return await asyncio.start_server(on_client, host, port, limit=MAX_LINE)
    if kind == "tls":
        if not tls_cert or not tls_key:
            raise ProtocolError("a tls:// listener needs TLS_CERT and TLS_KEY")
        return await asyncio.start_server(on_client, host, port, limit=MAX_LINE, ssl=server_ssl(tls_cert, tls_key))
    path = host
    directory = os.path.dirname(path)
    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(directory, exist_ok=True)
    server = await asyncio.start_unix_server(on_client, path, limit=MAX_LINE)
    os.chmod(path, unix_mode)
    gid = _group_id(unix_group)
    if gid is not None:
        for p in (directory, path):
            os.chown(p, -1, gid)
        os.chmod(directory, 0o750)
    return server


def _group_id(name: str | None) -> int | None:
    if not name or os.name == "nt":
        return None
    import grp

    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


async def _send(writer: asyncio.StreamWriter, payload: dict) -> None:
    writer.write(json.dumps(payload, default=str).encode() + b"\n")
    await writer.drain()


# --- clients -----------------------------------------------------------------------

def _ca(ca_file: str | None) -> str | None:
    return ca_file or os.getenv("AGENT_CA") or None


async def request(addr: str, op: str, params: dict | None, token: str, timeout: float = 30,
                  ca_file: str | None = None) -> dict:
    """Async one-shot request (MCP server, console)."""
    addr = client_addr(addr)
    kind, host, port = parse_addr(addr)
    try:
        if kind == "tcp":
            conn = asyncio.open_connection(host, port, limit=MAX_LINE)
        elif kind == "tls":
            conn = asyncio.open_connection(host, port, limit=MAX_LINE, ssl=client_ssl(_ca(ca_file)),
                                           server_hostname=host)
        else:
            conn = asyncio.open_unix_connection(host, limit=MAX_LINE)
        reader, writer = await asyncio.wait_for(conn, timeout)
    except ssl.SSLError as e:
        raise ProtocolError(f"TLS check of the agent at {addr} failed ({e}): is AGENT_CA the agent's "
                            f"current certificate?") from e
    except (OSError, asyncio.TimeoutError) as e:
        raise ProtocolError(f"host agent unreachable at {addr} ({e}); is threatintel-responder running?") from e
    try:
        writer.write(json.dumps({"op": op, "params": params or {}, "token": token}).encode() + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
    finally:
        writer.close()
    if not line:
        raise ProtocolError("host agent closed the connection (token or client IP refused?)")
    return json.loads(line)


def request_sync(addr: str, op: str, params: dict | None, token: str, timeout: float = 30,
                 ca_file: str | None = None) -> dict:
    """Blocking one-shot request (approval CLI, poller push)."""
    addr = client_addr(addr)
    kind, host, port = parse_addr(addr)
    try:
        if kind in ("tcp", "tls"):
            sock = socket.create_connection((host, port), timeout=timeout)
            if kind == "tls":
                sock = client_ssl(_ca(ca_file)).wrap_socket(sock, server_hostname=host)
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(host)
    except ssl.SSLError as e:
        raise ProtocolError(f"TLS check of the agent at {addr} failed ({e}): is AGENT_CA the agent's "
                            f"current certificate?") from e
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
        raise ProtocolError("host agent closed the connection (token or client IP refused?)")
    return json.loads(buf)
