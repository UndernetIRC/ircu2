"""TLS trust-policy tests: cert required, self-signed, expired, user ports."""

from __future__ import annotations

import asyncio
import ssl

import pytest

from irc_client import IRCClient
from p10_server import P10Server
from tls_certs import client_ssl_context

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


async def test_user_tls_port_allows_no_client_cert(ircd_tls_network):
    """User TLS ports do not require a client certificate."""
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    try:
        msgs = await client.register("nocusr", "testuser", "No client cert")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


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
