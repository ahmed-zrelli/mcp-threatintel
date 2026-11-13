"""Split architecture: TLS channels with a pinned certificate, client allowlist, intel push."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import shutil
import socket
import sqlite3

import pytest

from mcp_threatintel.responder import protocol
from mcp_threatintel.responder.intel_push import push
from test_responder import ADMIN_TOKEN, AGENT_TOKEN, agent, backend, call, config, ioc_db  # noqa: F401

crypto = pytest.importorskip("cryptography")


def make_cert(dirpath, name="agent"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"threatintel-{name}")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    crt, k = dirpath / f"{name}.crt", dirpath / f"{name}.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return str(crt), str(k)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_tls_channel_with_pinned_certificate(agent, tmp_path):  # noqa: F811
    crt, key = make_cert(tmp_path)
    other, _ = make_cert(tmp_path, "impostor")
    port = free_port()
    addr = f"tls://127.0.0.1:{port}"

    async def scenario():
        srv = await protocol.serve(addr, agent.handle_agent, tls_cert=crt, tls_key=key, allowed_clients=["10.0.0.5"])
        async with srv:
            ok = await protocol.request(addr, "ping", {}, AGENT_TOKEN, ca_file=crt)
            bad_token = await protocol.request(addr, "ping", {}, "nope", ca_file=crt)
            with pytest.raises(protocol.ProtocolError, match="TLS"):
                await protocol.request(addr, "ping", {}, AGENT_TOKEN, ca_file=other)   # not the agent's cert
            sync = await asyncio.to_thread(protocol.request_sync, addr, "ping", {}, AGENT_TOKEN, 10, crt)
        return ok, bad_token, sync

    ok, bad_token, sync = asyncio.run(scenario())
    assert ok["ok"] and ok["data"]["channel"] == "agent"
    assert bad_token == {"ok": False, "error": "invalid token"}
    assert sync["ok"]


def test_tls_listener_needs_a_certificate_and_tcp_stays_loopback():
    with pytest.raises(protocol.ProtocolError, match="TLS_CERT"):
        asyncio.run(protocol.serve("tls://0.0.0.0:3712", None))
    with pytest.raises(protocol.ProtocolError, match="non-loopback"):
        asyncio.run(protocol.serve("tcp://0.0.0.0:3712", None))


def test_client_allowlist_and_address_choice():
    assert protocol._allowed(("192.168.21.1", 5000), ["192.168.21.1"])
    assert protocol._allowed(("127.0.0.1", 5000), ["192.168.21.1"])          # loopback always
    assert not protocol._allowed(("192.168.21.50", 5000), ["192.168.21.1"])
    assert protocol._allowed(("192.168.21.50", 5000), [])                     # no list = token only
    assert protocol.client_addr("tls://0.0.0.0:3713,tls://192.168.21.129:3713") == "tls://192.168.21.129:3713"
    with pytest.raises(protocol.ProtocolError):
        protocol.client_addr("tls://0.0.0.0:3713")


def test_intel_push_installs_the_console_database(agent, ioc_db, tmp_path):  # noqa: F811
    console_db = tmp_path / "console.db"
    shutil.copy(ioc_db, console_db)
    c = sqlite3.connect(console_db)
    c.execute("INSERT INTO local_iocs (value, type) VALUES ('203.0.113.77', 'ip')")
    c.commit()
    c.close()
    assert not agent.iocs.lookup("ip", "203.0.113.77")

    def send(op, params):
        resp = call(agent, "agent", op, **params)
        assert resp["ok"], resp
        return resp["data"]

    result = push(send, console_db)
    assert result["pushed"] and result["installed"] and result["counts"]["local_iocs"] >= 1
    assert push(send, console_db)["pushed"] is False                         # same snapshot: skipped
    agent.iocs.refresh_s = 0
    assert agent.iocs.lookup("ip", "203.0.113.77")
    # the admin channel cannot push intel, and a corrupted transfer is refused
    assert not call(agent, "admin", "push_intel", transfer="x", seq=0, last=True, data="")["ok"]
    bad = call(agent, "agent", "push_intel", transfer="t1", seq=0, last=True, sha256="0" * 64, data="aGVsbG8=")
    assert not bad["ok"] and "checksum" in bad["error"]
    audit = call(agent, "admin", "audit", limit=50)["data"]
    assert any(e["event"] == "intel_received" for e in audit)
