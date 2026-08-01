"""M2 tests for session-resume detach and expiry.

A secure-WebSocket client that negotiated draft/resume-0.5 can be detached
(transport released, session kept) and must:

  * NOT produce a network QUIT while detached,
  * remain visible to peers (WHOIS reports it as temporarily detached),
  * produce exactly one QUIT when the resume window expires without a resume.

Detach is triggered by an abrupt transport reset (the production path). The
TLS-hub test config sets RESUME_TIMEOUT=10 so expiry is observable quickly.
"""

import asyncio
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
        msg = await client.recv(timeout=10.0)
        if msg.command == "381":  # RPL_YOUREOPER
            return
        if msg.command in ("464", "491"):
            raise AssertionError(f"OPER failed: {msg}")


async def _ws_register_with_resume(hub, nick):
    """Register a WSS client that has negotiated and been issued a resume token."""
    c = IRCWebSocketClient()
    await c.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())

    await c.send("CAP LS 302")
    while True:
        m = await c.recv(timeout=10.0)
        if m.command == "CAP" and (len(m.params) < 4 or m.params[-2] != "*"):
            break

    await c.send(f"CAP REQ :{RESUME_CAP}")
    token = None
    for _ in range(10):
        m = await c.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
            token = m.params[-1]
            break

    await c.send(f"NICK {nick}")
    await c.send(f"USER {nick} 0 * :{nick}")
    await c.send("CAP END")
    while True:
        m = await c.recv(timeout=10.0)
        if m.command in ("376", "422"):
            break
    return c, token


async def _saw_command_from(client, command, nick, timeout):
    """Return True if a <command> prefixed by nick! arrives within timeout."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    prefix = nick + "!"
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return False
        try:
            m = await client.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            return False
        if m.command == command and m.prefix and m.prefix.startswith(prefix):
            return True


async def _whois_reports_detached(observer, nick, timeout=10.0):
    await observer.send(f"WHOIS {nick}")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    detached = False
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return detached
        try:
            m = await observer.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            return detached
        if m.command == "320" and "detached" in m.params[-1].lower():
            detached = True
        if m.command == "318":  # RPL_ENDOFWHOIS
            return detached


async def test_detach_keeps_client_visible_then_expires(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    # Observer + operator on the same server, sharing a channel with the target.
    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("obs", "obs", "Observer")
    await _oper_up(obs)
    await obs.send("JOIN #resume")
    await obs.wait_for("JOIN", timeout=5.0)  # own JOIN echo

    # Resume-capable WSS client joins the channel.
    alice, token = await _ws_register_with_resume(hub, "alice")
    assert token, "resume token was not issued"
    await alice.send("JOIN #resume")
    assert await _saw_command_from(obs, "JOIN", "alice", timeout=10.0), (
        "observer never saw alice join"
    )

    # Detach alice (stand-in for transport loss).
    alice._ws.transport.abort()  # abrupt transport loss -> auto-detach

    # No QUIT should reach peers while detached (window is 10s; check well under).
    assert not await _saw_command_from(obs, "QUIT", "alice", timeout=4.0), (
        "peer saw a QUIT while the session was only detached"
    )

    # Still network-visible: WHOIS reports the temporary detachment (to opers).
    assert await _whois_reports_detached(obs, "alice"), (
        "WHOIS did not report alice as temporarily detached"
    )

    # After the window expires, exactly one QUIT is emitted.
    assert await _saw_command_from(obs, "QUIT", "alice", timeout=15.0), (
        "no QUIT emitted after the resume window expired"
    )
    # And alice is gone: a second QUIT must not appear.
    assert not await _saw_command_from(obs, "QUIT", "alice", timeout=3.0), (
        "a second QUIT appeared for alice"
    )

    await obs.send("QUIT :done")
    await obs.disconnect()
    try:
        await alice.disconnect()
    except Exception:
        pass
