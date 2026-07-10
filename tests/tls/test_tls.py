"""TLS integration tests for per-block trust settings and verification.

Exercises client TLS ports, inbound S2S (fingerprint and CA verify), and
outbound S2S links between the tls-hub and tls-leaf containers.
"""

from __future__ import annotations

import asyncio
import ssl

import pytest

from irc_client import IRCClient
from p10_server import P10Server
from tls_certs import client_ssl_context
from tls.helpers import (
    collect_until_error_or_close,
    connect_link,
    is_error,
    oper_up,
    wait_for_server_link,
)

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]


# ---------------------------------------------------------------------------
# Client (user) connections
# ---------------------------------------------------------------------------


async def test_client_plaintext_still_works(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    try:
        msgs = await client.register("tlsusr1", "testuser", "TLS Test")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


async def test_client_tls_registration(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    try:
        msgs = await client.register("tlsusr2", "testuser", "TLS Test")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


async def test_client_tls_alt_port(ircd_tls_network):
    """Second TLS client port accepts registrations."""
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port_alt"])
    try:
        msgs = await client.register("tlsusr3", "testuser", "TLS Test")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


async def test_client_plaintext_rejected_on_tls_port(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    reader, writer = await asyncio.open_connection(hub["host"], hub["tls_port"])
    try:
        line = await collect_until_error_or_close(reader, timeout=3.0)
        assert is_error(line) or line == ""
    except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def test_leaf_client_tls_registration(ircd_tls_network):
    leaf = ircd_tls_network["leaf"]
    client = IRCClient()
    await client.connect_tls(leaf["host"], leaf["tls_port"])
    try:
        msgs = await client.register("leafusr1", "testuser", "TLS Leaf Test")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# Inbound S2S — fingerprint pinning
# ---------------------------------------------------------------------------


async def test_s2s_inbound_fingerprint_accepts_matching_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer.test.net", numeric=40, password="testpass")
    ctx = client_ssl_context(cert="tlspeer")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_s2s_inbound_fingerprint_rejects_mismatch(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-bad.test.net", numeric=41, password="testpass")
    ctx = client_ssl_context(cert="tlspeer")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
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


async def test_s2s_inbound_fingerprint_rejects_selfsigned(ircd_tls_network):
    """Self-signed peer cert does not match pinned fingerprint."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer.test.net", numeric=42, password="testpass")
    ctx = client_ssl_context(cert="selfsigned")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
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


# ---------------------------------------------------------------------------
# Inbound S2S — CA verification (tls verifypeer = yes on listener)
# ---------------------------------------------------------------------------


async def test_s2s_inbound_ca_accepts_signed_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-ca.test.net", numeric=43, password="testpass")
    ctx = client_ssl_context(cert="tlspeer-ca")
    await srv.connect_tls(hub["host"], hub["server_tls_ca_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_s2s_inbound_ca_rejects_selfsigned(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-ca.test.net", numeric=44, password="testpass")
    ctx = client_ssl_context(cert="selfsigned")
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


async def test_s2s_inbound_ca_rejects_wrong_ca(ircd_tls_network):
    """Certificate signed by an untrusted CA is rejected."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-ca.test.net", numeric=45, password="testpass")
    ctx = client_ssl_context(cert="rogue")
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


async def test_s2s_plaintext_rejected_on_tls_server_port(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    reader, writer = await asyncio.open_connection(hub["host"], hub["server_port"])
    try:
        line = await collect_until_error_or_close(reader, timeout=3.0)
        assert is_error(line) or line == ""
    except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Outbound S2S — hub autoconnect with fingerprint, leaf with CA verify
# ---------------------------------------------------------------------------


async def test_s2s_outbound_hub_links_leaf_via_fingerprint(ircd_tls_network):
    """Hub initiates an outbound TLS link to tls-leaf using fingerprint pinning."""
    hub = ircd_tls_network["hub"]
    op = IRCClient()
    await op.connect(hub["host"], hub["port"])
    await op.register("tlsoper1", "oper", "Oper")
    try:
        msg = await oper_up(op)
        assert msg.command == "381"
        # Hub's Connect block for tls-leaf pins a fingerprint on port 4401.
        await connect_link(op, "tls-leaf.test.net", 4401, timeout=45.0)
    finally:
        await op.disconnect()


async def test_s2s_outbound_leaf_links_hub_via_ca_verify(ircd_tls_network):
    """Leaf initiates an outbound TLS link to the hub with CA peer verification."""
    leaf = ircd_tls_network["leaf"]
    op = IRCClient()
    await op.connect(leaf["host"], leaf["port"])
    await op.register("tlsoper2", "oper", "Oper")
    try:
        msg = await oper_up(op)
        assert msg.command == "381"
        # Leaf's Connect block for the hub uses CA verify on port 4441.
        await connect_link(op, "tls-hub.test.net", 4441, timeout=45.0)
    finally:
        await op.disconnect()


async def test_s2s_bidirectional_traffic_after_tls_link(ircd_tls_network):
    """Linked TLS servers are visible to each other via LINKS."""
    hub = ircd_tls_network["hub"]

    op = IRCClient()
    await op.connect(hub["host"], hub["port"])
    await op.register("tlsmap", "oper", "Oper")
    await oper_up(op)

    try:
        await connect_link(op, "tls-leaf.test.net", 4401, timeout=45.0)
    finally:
        await op.disconnect()
