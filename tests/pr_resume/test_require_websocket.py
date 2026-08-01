"""RESUME_REQUIRE_WEBSOCKET: eligibility on plain TLS (non-WebSocket) links.

The security requirement for resume is TLS; RESUME_REQUIRE_WEBSOCKET (default
TRUE) further restricts eligibility to secure WebSockets.  When it is cleared,
the capability must be advertised on a direct TLS connection and a full
token-based resume must work over it.

These run against the shared tls-hub, so the test flips the feature at runtime
(SET, an oper command) and restores it in a finally block.
"""

import ssl

import pytest

from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient

RESUME_CAP = "draft/resume-0.5"

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]


def _tls_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _oper_up(client):
    await client.send("OPER testoper operpass")
    while True:
        m = await client.recv(timeout=10.0)
        if m.command == "381":
            return
        if m.command in ("464", "491"):
            raise AssertionError(f"OPER failed: {m}")


async def _cap_ls(client):
    """Return the set of advertised capability names after a CAP LS 302."""
    await client.send("CAP LS 302")
    caps = set()
    while True:
        m = await client.recv(timeout=10.0)
        if m.command == "CAP" and len(m.params) >= 3 and m.params[1] == "LS":
            caps.update(m.params[-1].split())
            # A non-"*" third param marks the final LS line.
            if len(m.params) < 4 or m.params[2] != "*":
                return caps


async def _set_feature(hub, name, value):
    """Flip a feature at runtime via an opered client; returns the oper client
    so the caller can restore it."""
    op = IRCClient()
    await op.connect_tls(hub["host"], hub["tls_port"], ssl_context=_tls_ctx())
    await op.register("wsfeat", "wsfeat", "wsfeat")
    await _oper_up(op)
    await op.send(f"SET {name} {value}")
    # Drain the SET acknowledgement notice(s).
    for _ in range(5):
        try:
            await op.recv(timeout=2.0)
        except Exception:
            break
    return op


async def test_cap_hidden_on_direct_tls_by_default(ircd_tls_network):
    """With RESUME_REQUIRE_WEBSOCKET on (default), a direct TLS client is not
    offered draft/resume-0.5 even though it is TLS."""
    hub = ircd_tls_network["hub"]
    c = IRCClient()
    await c.connect_tls(hub["host"], hub["tls_port"], ssl_context=_tls_ctx())
    caps = await _cap_ls(c)
    assert RESUME_CAP not in caps, (
        f"{RESUME_CAP} must not be advertised on a direct TLS link by default"
    )


async def test_resume_over_direct_tls_when_websocket_not_required(ircd_tls_network):
    """With RESUME_REQUIRE_WEBSOCKET cleared, a direct TLS (non-WS) client is
    offered the capability and can complete a full token resume."""
    hub = ircd_tls_network["hub"]
    op = await _set_feature(hub, "RESUME_REQUIRE_WEBSOCKET", "FALSE")
    try:
        # 1) The capability is now advertised on a direct TLS link.
        alice = IRCClient()
        await alice.connect_tls(hub["host"], hub["tls_port"], ssl_context=_tls_ctx())
        caps = await _cap_ls(alice)
        assert RESUME_CAP in caps, (
            f"{RESUME_CAP} should be advertised on direct TLS when "
            "RESUME_REQUIRE_WEBSOCKET is FALSE"
        )

        # 2) Register with the capability and capture the issued token.
        await alice.send(f"CAP REQ :{RESUME_CAP}")
        token = None
        await alice.send("NICK tlsrez")
        await alice.send("USER tlsrez 0 * :tlsrez")
        await alice.send("CAP END")
        for _ in range(40):
            m = await alice.recv(timeout=10.0)
            if m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
                token = m.params[-1]
            if m.command in ("376", "422") and token:
                break
        assert token, "no resume token issued on direct TLS"

        await alice.send("JOIN #tlsrez")
        await alice.wait_for("JOIN", timeout=5.0)

        # 3) Drop the transport and resume over a fresh direct TLS connection.
        alice._writer.transport.abort()  # abrupt loss -> auto-detach

        a2 = IRCClient()
        await a2.connect_tls(hub["host"], hub["tls_port"], ssl_context=_tls_ctx())
        await a2.send(f"CAP REQ :{RESUME_CAP}")
        await a2.send("NICK tlstmp")
        await a2.send("USER tlstmp 0 * :temp")
        await a2.send(f"RESUME {token}")

        success = False
        for _ in range(80):
            m = await a2.recv(timeout=10.0)
            if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
                success = True
                assert m.params[-1] == "tlsrez"
                break
            if m.command == "FAIL" and "RESUME" in m.params:
                raise AssertionError(f"resume over direct TLS failed: {m}")
        assert success, "resume over direct TLS did not succeed"
    finally:
        await op.send("SET RESUME_REQUIRE_WEBSOCKET TRUE")
        await op.disconnect()
