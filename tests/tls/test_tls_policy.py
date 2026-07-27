"""TLS trust-policy connection matrices for client and server ports.

Client TLS port without verifypeer (REQUEST_SOFT):
  any/no client cert is accepted; fingerprint recorded when presented.

Client TLS port with verifypeer (REQUIRE_CA):
  peer cert required and must chain to the configured CA.

Server TLS port without verifypeer (REQUIRE_SOFT):
  peer cert required; any cert accepted at TLS layer; Connect fingerprint
  pin decides link acceptance after SERVER.

Server TLS port with verifypeer (REQUIRE_CA):
  peer cert required and must chain to the configured CA at handshake;
  Connect verifypeer also checks hostname after SERVER.
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

# Certs used as client identities on soft user ports (all must register).
_USER_SOFT_CERTS = (
    None,  # no client certificate
    "selfsigned",
    "tlspeer-ca",  # CA-signed, not self-signed
    "tlspeer",  # another CA-signed identity
    "expired",
    "notyet",
    "rogue",
    "nocliauth",  # serverAuth EKU only
)

# Soft server port: TLS handshake must succeed with these peer certs.
_SERVER_SOFT_HANDSHAKE_CERTS = (
    "selfsigned",
    "tlspeer",
    "tlspeer-ca",
    "expired",
    "notyet",
    "rogue",
    "nocliauth",
)

# CA server / user-CA ports: only our test CA leaf should pass handshake.
_CA_VALID_CERT = "tlspeer-ca"
_CA_INVALID_CERTS = (
    "selfsigned",
    "expired",
    "notyet",
    "rogue",
    "nocliauth",
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


async def _expect_tls_handshake_ok(host: str, port: int, ctx: ssl.SSLContext):
    """Complete a TLS handshake successfully (no IRC protocol)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx),
        timeout=8.0,
    )
    try:
        assert writer.get_extra_info("ssl_object") is not None
    finally:
        writer.close()
        transport = writer.transport
        if transport is not None:
            transport.abort()


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


def _user_soft_nick(cert: str | None) -> str:
    """Build a unique IRC nick from a cert id (avoid truncating collisions)."""
    # tlspeer + tlspeer-ca both became "utlspee" when truncated to 6 chars.
    raw = "".join(c if c.isalnum() else "x" for c in (cert or "none"))
    return f"u{raw[:14]}"


async def _register_on_user_tls(
    hub: dict, nick: str, *, cert: str | None = None, port_key: str = "tls_port"
) -> IRCClient:
    port = hub[port_key]
    ctx = client_ssl_context(cert=cert) if cert else None
    client = IRCClient()
    if ctx is None:
        await client.connect_tls(hub["host"], port)
    else:
        await client.connect_tls(hub["host"], port, ssl_context=ctx)
    msgs = await client.register(nick, "testuser", f"cert={cert or 'none'}")
    assert any(m.command == "001" for m in msgs), f"register failed for cert={cert}"
    return client


async def _quit(client: IRCClient) -> None:
    """QUIT then close so the nick is freed even if TLS close_notify is slow."""
    try:
        await client.send("QUIT :test done")
        await asyncio.sleep(0.05)
    except Exception:
        pass
    await client.disconnect()


# ---------------------------------------------------------------------------
# Client / user TLS port — REQUEST_SOFT (no verifypeer)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cert", _USER_SOFT_CERTS, ids=lambda c: c or "none")
async def test_user_soft_port_accepts_client_cert(ircd_tls_network, cert):
    """Soft user ports accept every realistic client-cert presentation."""
    hub = ircd_tls_network["hub"]
    client = await _register_on_user_tls(hub, _user_soft_nick(cert), cert=cert)
    await _quit(client)


async def test_user_soft_port_records_selfsigned_fingerprint(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    assert len(fingerprint("selfsigned")) == 64
    client = await _register_on_user_tls(hub, "fpself", cert="selfsigned")
    try:
        got = await _oper_result(client, "certoper", "certpass")
        assert "381" in got, f"expected OPER success with selfsigned certfp, got {got}"
    finally:
        await client.disconnect()


async def test_user_soft_port_records_ca_signed_fingerprint(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    assert len(fingerprint("tlspeer-ca")) == 64
    client = await _register_on_user_tls(hub, "fpca", cert="tlspeer-ca")
    try:
        got = await _oper_result(client, "caoper", "capass")
        assert "381" in got, f"expected OPER success with CA certfp, got {got}"
    finally:
        await client.disconnect()


async def test_user_soft_port_fingerprint_absent_without_client_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    client = await _register_on_user_tls(hub, "nofp")
    try:
        got = await _oper_result(client, "certoper", "certpass")
        assert "381" not in got
        assert "532" in got, f"expected ERR_TLSCLIFINGERPRINT, got {got}"
    finally:
        await client.disconnect()


async def test_user_soft_port_wrong_cert_fails_fingerprint_oper(ircd_tls_network):
    """Presenting a different cert must not satisfy certoper's pin."""
    hub = ircd_tls_network["hub"]
    client = await _register_on_user_tls(hub, "wrongfp", cert="rogue")
    try:
        got = await _oper_result(client, "certoper", "certpass")
        assert "381" not in got
        assert "532" in got, f"expected ERR_TLSCLIFINGERPRINT, got {got}"
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# Client / user TLS port — REQUIRE_CA (tls verifypeer = yes)
# ---------------------------------------------------------------------------


async def test_user_ca_port_rejects_missing_client_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    await _expect_tls_handshake_fails(hub["host"], hub["tls_port_ca"], ctx)


async def test_user_ca_port_accepts_ca_signed_client_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    client = await _register_on_user_tls(
        hub, "ucavalid", cert=_CA_VALID_CERT, port_key="tls_port_ca"
    )
    await client.disconnect()


@pytest.mark.parametrize("cert", _CA_INVALID_CERTS)
async def test_user_ca_port_rejects_invalid_client_cert(ircd_tls_network, cert):
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context(cert=cert)
    await _expect_tls_handshake_fails(hub["host"], hub["tls_port_ca"], ctx)


# ---------------------------------------------------------------------------
# Server TLS port — REQUIRE_SOFT (no verifypeer): cert required, any OK
# ---------------------------------------------------------------------------


async def test_server_soft_port_rejects_missing_peer_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    await _expect_tls_handshake_fails(hub["host"], hub["server_port"], client_ssl_context())


@pytest.mark.parametrize("cert", _SERVER_SOFT_HANDSHAKE_CERTS)
async def test_server_soft_port_handshake_accepts_peer_cert(ircd_tls_network, cert):
    """Without verifypeer, server ports accept any presented peer cert at TLS."""
    hub = ircd_tls_network["hub"]
    await _expect_tls_handshake_ok(
        hub["host"], hub["server_port"], client_ssl_context(cert=cert)
    )


async def test_server_soft_port_fingerprint_accepts_matching_selfsigned(
    ircd_tls_network,
):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-selfsigned.test.net", numeric=46, password="testpass")
    ctx = client_ssl_context(cert="selfsigned")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_server_soft_port_fingerprint_accepts_matching_expired(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-expired.test.net", numeric=47, password="testpass")
    ctx = client_ssl_context(cert="expired")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_server_soft_port_fingerprint_accepts_matching_ca_signed(
    ircd_tls_network,
):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer.test.net", numeric=40, password="testpass")
    ctx = client_ssl_context(cert="tlspeer")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_server_soft_port_fingerprint_rejects_mismatch(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-bad.test.net", numeric=41, password="testpass")
    ctx = client_ssl_context(cert="tlspeer")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        with pytest.raises(_TLS_CONNECT_ERRORS):
            await srv.handshake(timeout=8.0)
    finally:
        await srv.disconnect()


async def test_server_soft_port_fingerprint_rejects_wrong_cert_for_pin(
    ircd_tls_network,
):
    """Pinned Connect for tlspeer rejects a different presented cert."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer.test.net", numeric=42, password="testpass")
    ctx = client_ssl_context(cert="selfsigned")
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    try:
        with pytest.raises(_TLS_CONNECT_ERRORS):
            await srv.handshake(timeout=8.0)
    finally:
        await srv.disconnect()


# ---------------------------------------------------------------------------
# Server TLS port — REQUIRE_CA (tls verifypeer = yes)
# ---------------------------------------------------------------------------


async def test_server_ca_port_rejects_missing_peer_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    await _expect_tls_handshake_fails(
        hub["host"], hub["server_tls_ca_port"], client_ssl_context()
    )


async def test_server_ca_port_accepts_ca_signed_peer_cert(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-ca.test.net", numeric=43, password="testpass")
    ctx = client_ssl_context(cert=_CA_VALID_CERT)
    await srv.connect_tls(hub["host"], hub["server_tls_ca_port"], ctx)
    try:
        await srv.handshake(timeout=15.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


@pytest.mark.parametrize("cert", _CA_INVALID_CERTS)
async def test_server_ca_port_rejects_invalid_peer_cert(ircd_tls_network, cert):
    hub = ircd_tls_network["hub"]
    await _expect_tls_handshake_fails(
        hub["host"], hub["server_tls_ca_port"], client_ssl_context(cert=cert)
    )


async def test_server_ca_port_rejects_hostname_mismatch_after_server(
    ircd_tls_network,
):
    """CA-valid cert whose CN/SAN does not match Connect name fails after SERVER."""
    hub = ircd_tls_network["hub"]
    srv = P10Server(name="tlspeer-ca.test.net", numeric=48, password="testpass")
    # tlspeer is CA-signed but CN is tlspeer.test.net, not tlspeer-ca.test.net
    ctx = client_ssl_context(cert="tlspeer")
    await srv.connect_tls(hub["host"], hub["server_tls_ca_port"], ctx)
    try:
        with pytest.raises(_TLS_CONNECT_ERRORS):
            await srv.handshake(timeout=8.0)
    finally:
        await srv.disconnect()
