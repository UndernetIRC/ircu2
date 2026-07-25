"""TLS trust-policy tests: cert required, self-signed, expired, user ports.

Matrix covered here:

User TLS port (request optional, no CA verify):
  - no client cert          -> register OK
  - self-signed             -> register OK, fingerprint recorded (OPER)
  - CA-signed (tlspeer-ca)  -> register OK, fingerprint recorded (OPER)
  - expired                 -> register OK (dates not enforced without verifypeer)
  - rogue CA-signed         -> register OK (issuer not enforced without verifypeer)
  - no cert + fp-pinned OPER -> 532

Server TLS port (always require peer cert, no CA unless verifypeer):
  - no client cert          -> handshake fail
  - matching fingerprint    -> link OK (test_tls.py + selfsigned/expired pins here)
  - CA port + missing/expired/mismatch -> fail
"""

from __future__ import annotations

import asyncio
import ssl

import pytest

from irc_client import IRCClient
from p10_server import P10Server
from tls_certs import client_ssl_context, fingerprint

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

_TLS_CONNECT_ERRORS = (
    ssl.SSLError,
    ConnectionError,
    ConnectionResetError,
    BrokenPipeError,
    OSError,
    asyncio.TimeoutError,
    TimeoutError,
)


async def _expect_tls_handshake_fails(host: str, port: int, ctx: ssl.SSLContext):
    """Fail during or immediately after the TLS handshake."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=8.0,
        )
    except _TLS_CONNECT_ERRORS:
        return
    try:
        writer.write(b"\x00")
        await asyncio.wait_for(writer.drain(), timeout=3.0)
        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        if not data:
            return
    except _TLS_CONNECT_ERRORS:
        return
    finally:
        try:
            writer.close()
            transport = writer.transport
            if transport is not None:
                transport.abort()
        except Exception:
            pass
    pytest.fail("expected TLS connection to be rejected")


async def _oper_result(client: IRCClient, name: str, password: str) -> list[str]:
    await client.send(f"OPER {name} {password}")
    got = []
    deadline = asyncio.get_running_loop().time() + 10.0
    while asyncio.get_running_loop().time() < deadline:
        msg = await client.recv(timeout=5.0)
        got.append(msg.command)
        if msg.command in ("381", "532", "491", "464"):
            break
    return got


async def _register_on_user_tls(
    hub: dict, nick: str, *, cert: str | None = None
) -> None:
    ctx = client_ssl_context(cert=cert) if cert else None
    client = IRCClient()
    if ctx is None:
        await client.connect_tls(hub["host"], hub["tls_port"])
    else:
        await client.connect_tls(hub["host"], hub["tls_port"], ssl_context=ctx)
    try:
        msgs = await client.register(nick, "testuser", f"cert={cert or 'none'}")
        assert any(m.command == "001" for m in msgs), f"register failed for cert={cert}"
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# User TLS ports — optional client cert, allow self-signed
# ---------------------------------------------------------------------------


async def test_user_tls_port_allows_no_client_cert(ircd_tls_network):
    """User TLS ports request but do not require a client certificate."""
    await _register_on_user_tls(ircd_tls_network["hub"], "nocusr")


async def test_user_tls_port_accepts_selfsigned_and_records_fingerprint(
    ircd_tls_network,
):
    """User ports accept self-signed client certs and record the fingerprint."""
    hub = ircd_tls_network["hub"]
    assert fingerprint("selfsigned").startswith("c52767a9")
    ctx = client_ssl_context(cert="selfsigned")
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"], ssl_context=ctx)
    try:
        msgs = await client.register("certusr", "testuser", "Self-signed cert")
        assert any(m.command == "001" for m in msgs)
        got = await _oper_result(client, "certoper", "certpass")
        assert "381" in got, f"expected oper success with presented certfp, got {got}"
    finally:
        await client.disconnect()


async def test_user_tls_port_accepts_ca_signed_and_records_fingerprint(
    ircd_tls_network,
):
    """User ports accept CA-signed client certs and record the fingerprint."""
    hub = ircd_tls_network["hub"]
    assert fingerprint("tlspeer-ca").startswith("dd5517ac")
    ctx = client_ssl_context(cert="tlspeer-ca")
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"], ssl_context=ctx)
    try:
        msgs = await client.register("causr", "testuser", "CA-signed cert")
        assert any(m.command == "001" for m in msgs)
        got = await _oper_result(client, "caoper", "capass")
        assert "381" in got, f"expected oper success with CA certfp, got {got}"
    finally:
        await client.disconnect()


async def test_user_tls_port_accepts_expired_client_cert(ircd_tls_network):
    """Without verifypeer, expired client certs are still accepted on user ports."""
    await _register_on_user_tls(ircd_tls_network["hub"], "expusr", cert="expired")


async def test_user_tls_port_accepts_rogue_ca_client_cert(ircd_tls_network):
    """Without verifypeer, untrusted-CA client certs are accepted on user ports."""
    await _register_on_user_tls(ircd_tls_network["hub"], "rogusr", cert="rogue")


async def test_user_tls_port_fingerprint_absent_without_client_cert(ircd_tls_network):
    """Without a client cert, fingerprint-pinned oper auth must fail."""
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    try:
        await client.register("nocertfp", "testuser", "No cert for oper")
        got = await _oper_result(client, "certoper", "certpass")
        assert "381" not in got, "must not oper without a client certificate"
        assert "532" in got, f"expected ERR_TLSCLIFINGERPRINT, got {got}"
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# Server TLS ports — always require peer cert
# ---------------------------------------------------------------------------


async def test_s2s_server_port_rejects_missing_client_cert(ircd_tls_network):
    """Server TLS ports always require a peer certificate."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    await _expect_tls_handshake_fails(hub["host"], hub["server_port"], ctx)


async def test_s2s_ca_port_rejects_missing_client_cert(ircd_tls_network):
    """CA-verified server ports reject connections with no client certificate."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    await _expect_tls_handshake_fails(hub["host"], hub["server_tls_ca_port"], ctx)


async def test_s2s_fingerprint_accepts_selfsigned_with_matching_pin(ircd_tls_network):
    """Fingerprint pinning allows self-signed certs when the pin matches."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-selfsigned.test.net", numeric=46, password="testpass")
    ctx = client_ssl_context(cert="selfsigned")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_s2s_fingerprint_accepts_expired_with_matching_pin(ircd_tls_network):
    """Fingerprint pinning does not require PKIX certificate validity dates."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-expired.test.net", numeric=47, password="testpass")
    ctx = client_ssl_context(cert="expired")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_s2s_ca_port_rejects_expired_cert(ircd_tls_network):
    """Expired peer certificates are rejected under tls verifypeer = yes."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context(cert="expired")
    await _expect_tls_handshake_fails(hub["host"], hub["server_tls_ca_port"], ctx)


async def test_s2s_ca_inbound_rejects_hostname_mismatch(ircd_tls_network):
    """Connect tls verifypeer rejects inbound SERVER when cert CN/SAN mismatches."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-ca.test.net", numeric=48, password="testpass")
    ctx = client_ssl_context(cert="tlspeer")
    await srv.connect_tls(hub["host"], hub["server_tls_ca_port"], ctx)
    try:
        with pytest.raises(
            (
                ConnectionError,
                TimeoutError,
                asyncio.TimeoutError,
                ConnectionResetError,
                ssl.SSLError,
            )
        ):
            await srv.handshake(timeout=8.0)
    finally:
        await srv.disconnect()
