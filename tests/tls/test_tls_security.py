"""TLS security regression tests.

Each test maps to a finding from the TLS security review (see
TLS-SECURITY-REVIEW.md at the repo root):

  H3  MODE +z fingerprint injection / secure-flag spoofing
  M1  RPL_WHOISSECURE numeric-table off-by-one
  M5  minimum TLS protocol version (>= 1.2)
  H2  use-after-free on connection teardown (abrupt close mid-handshake)
  L1  stalled handshake must time out, not hang or spin forever

These complement test_tls.py / test_tls_policy.py, which cover the trust
modes (fingerprint pinning, CA verification) for accepted connections.
"""

from __future__ import annotations

import asyncio
import ssl

import pytest

from irc_client import IRCClient
from tls_certs import client_ssl_context

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

# Pinned in the "fpoper" Operator block of ircd-tls-hub.conf. Matches no
# certificate presented in these tests; an attacker would try to forge it.
PINNED_OPER_FINGERPRINT = (
    "a02e8424c0ab92aa344c869672b46fd60b68b2450161f5349f9058d0d25b9ee8"
)


async def _collect_whois(client: IRCClient, target: str, timeout: float = 10.0):
    """Send WHOIS and return the list of reply numerics until RPL_ENDOFWHOIS."""
    await client.send(f"WHOIS {target}")
    numerics: list[str] = []
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("WHOIS did not complete")
        msg = await client.recv(timeout=remaining)
        numerics.append(msg.command)
        if msg.command in ("318", "401"):  # ENDOFWHOIS or NOSUCHNICK
            return numerics


# ---------------------------------------------------------------------------
# M1 — RPL_WHOISSECURE (671) is emitted correctly for TLS users
# ---------------------------------------------------------------------------


async def test_whois_shows_secure_for_tls_user(ircd_tls_network):
    """A TLS-connected user is reported as secure (671) in WHOIS.

    Also a functional regression for the s_err.c numeric-table off-by-one:
    if 671 resolved to an empty slot the daemon would abort (asserted build)
    or send the wrong text.
    """
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    try:
        await client.register("securewho", "testuser", "Secure Whois")
        numerics = await _collect_whois(client, "securewho")
        assert "671" in numerics, f"expected RPL_WHOISSECURE, got {numerics}"
    finally:
        await client.disconnect()


async def test_whois_no_secure_for_plaintext_user(ircd_tls_network):
    """A plaintext user must NOT be reported as secure."""
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    try:
        await client.register("plainwho", "testuser", "Plain Whois")
        numerics = await _collect_whois(client, "plainwho")
        assert "671" not in numerics, "plaintext user must not appear secure"
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# H3 — MODE +z cannot forge TLS state or fingerprint from a client
# ---------------------------------------------------------------------------


async def test_mode_z_cannot_spoof_secure_flag(ircd_tls_network):
    """A plaintext client setting +z must not become 'secure' in WHOIS."""
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    try:
        await client.register("spoofz", "testuser", "Spoof Z")
        await client.send(f"MODE spoofz +z {PINNED_OPER_FINGERPRINT}")
        await asyncio.sleep(0.5)
        numerics = await _collect_whois(client, "spoofz")
        assert "671" not in numerics, "client +z must not forge secure status"
    finally:
        await client.disconnect()


async def test_mode_z_cannot_spoof_fingerprint_for_oper(ircd_tls_network):
    """The core H3 regression.

    A client forges the exact fingerprint pinned on the 'fpoper' Operator
    block via MODE +z, then supplies the correct oper password. The oper
    attempt must fail on the fingerprint check (ERR_TLSCLIFINGERPRINT, 532)
    because a directly-connected client is not allowed to set its own TLS
    fingerprint. Before the fix, +z populated cli_tls_fingerprint and this
    attempt would succeed (RPL_YOUREOPER, 381).
    """
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    try:
        await client.register("fakeoper", "testuser", "Fake Oper")
        await client.send(f"MODE fakeoper +z {PINNED_OPER_FINGERPRINT}")
        await asyncio.sleep(0.5)
        await client.send("OPER fpoper fppass")

        got = []
        deadline = asyncio.get_running_loop().time() + 10.0
        while asyncio.get_running_loop().time() < deadline:
            msg = await client.recv(timeout=5.0)
            got.append(msg.command)
            if msg.command in ("381", "532", "491", "464"):
                break
        assert "381" not in got, "forged fingerprint must NOT grant oper"
        assert "532" in got, f"expected ERR_TLSCLIFINGERPRINT, got {got}"
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# M5 — minimum TLS protocol version
# ---------------------------------------------------------------------------


async def test_tls_below_1_2_rejected(ircd_tls_network):
    """The server must not complete a handshake below TLS 1.2.

    Note: under TLS_BACKEND=gnutls the version floor depends on the system
    'NORMAL' priority (review finding M5); this test asserts the intended
    behaviour and will surface a regression if that floor is not enforced.
    """
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    try:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, AttributeError):
        pytest.skip("local OpenSSL cannot offer TLS < 1.2")

    completed = False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hub["host"], hub["tls_port"], ssl=ctx),
            timeout=8.0,
        )
        completed = True
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError):
        pass
    assert not completed, "server accepted a sub-TLS1.2 handshake"


async def test_tls_1_2_accepted(ircd_tls_network):
    """Positive control: TLS >= 1.2 negotiates and registers normally."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"], ssl_context=ctx)
    try:
        msgs = await client.register("tls12usr", "testuser", "TLS 1.2")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# H2 / L1 — teardown and timeout robustness during handshake
# ---------------------------------------------------------------------------


async def test_abrupt_close_during_handshake_survives(ircd_tls_network):
    """Rapidly abort connections mid-handshake; the server must stay healthy.

    Exercises the ET_DESTROY TLS teardown path (H2 use-after-free). A crashed
    or corrupted daemon would fail the follow-up registration.
    """
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()

    for _ in range(30):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hub["host"], hub["tls_port"], ssl=ctx),
                timeout=3.0,
            )
        except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError):
            continue
        # Abort immediately without a clean TLS shutdown.
        transport = writer.transport
        if transport is not None:
            transport.abort()
        try:
            writer.close()
        except Exception:
            pass

    # The daemon must still accept and register a normal TLS client.
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    try:
        msgs = await client.register("survivor", "testuser", "Survivor")
        assert any(m.command == "001" for m in msgs)
    finally:
        await client.disconnect()


async def test_stalled_handshake_times_out(ircd_tls_network):
    """A client that opens the TLS port but sends no handshake is dropped.

    Verifies the handshake timeout (TLS_HANDSHAKE_TIMEOUT = 5s) fires so a
    stalled handshake cannot hold a slot or spin the event loop indefinitely.
    """
    hub = ircd_tls_network["hub"]
    reader, writer = await asyncio.open_connection(hub["host"], hub["tls_port"])
    try:
        # Send nothing (no ClientHello). The server should close on timeout.
        data = await asyncio.wait_for(reader.read(1), timeout=15.0)
        assert data == b"", "server should close the stalled handshake"
    except (asyncio.TimeoutError, ConnectionResetError):
        pytest.fail("server did not close a stalled TLS handshake in time")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
