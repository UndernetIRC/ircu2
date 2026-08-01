"""M5 tests: automatic detach on unexpected transport loss.

When an eligible secure-WebSocket client loses its transport abnormally (here,
an abrupt TCP reset with no WebSocket close handshake -- the Cloudflare/Nginx
drop case), the server detaches the session instead of exiting it: peers see no
QUIT, WHOIS reports the client as detached, and a new connection can resume it.
A clean client QUIT still exits normally.

This exercises the production trigger directly (no RESUMEDETACH test command).
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
        if msg.command == "381":
            return
        if msg.command in ("464", "491"):
            raise AssertionError(f"OPER failed: {msg}")


async def _drain_cap_and_token(c):
    await c.send("CAP LS 302")
    while True:
        m = await c.recv(timeout=10.0)
        if m.command == "CAP" and (len(m.params) < 4 or m.params[-2] != "*"):
            break
    await c.send(f"CAP REQ :{RESUME_CAP}")
    for _ in range(10):
        m = await c.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
            return m.params[-1]
    raise AssertionError("no resume token issued")


async def _ws_register_with_resume(hub, nick):
    c = IRCWebSocketClient()
    await c.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    token = await _drain_cap_and_token(c)
    await c.send(f"NICK {nick}")
    await c.send(f"USER {nick} 0 * :{nick}")
    await c.send("CAP END")
    while True:
        m = await c.recv(timeout=10.0)
        if m.command in ("376", "422"):
            break
    return c, token


async def _saw_command_from(client, command, nick, timeout):
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
        if m.command == "318":
            return detached


async def test_transport_reset_auto_detaches_then_resumes(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("adzobs", "adzobs", "Observer")
    await _oper_up(obs)
    await obs.send("JOIN #adz")
    await obs.wait_for("JOIN", timeout=5.0)

    adz, token = await _ws_register_with_resume(hub, "adz")
    await adz.send("JOIN #adz")
    assert await _saw_command_from(obs, "JOIN", "adz", 10.0)

    # Abrupt transport loss: reset the TCP connection with no WS close handshake.
    adz._ws.transport.abort()

    # The server must detach, not exit: peers see no QUIT.
    assert not await _saw_command_from(obs, "QUIT", "adz", 5.0), (
        "peer saw a QUIT after an abrupt transport loss (should auto-detach)"
    )
    # And WHOIS reports the detachment.
    assert await _whois_reports_detached(obs, "adz"), (
        "auto-detached client not reported as detached in WHOIS"
    )

    # A fresh connection resumes the auto-detached session.
    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK adztmp")
    await a2.send("USER adztmp 0 * :tmp")
    await a2.send(f"RESUME {token}")

    success = False
    for _ in range(80):
        m = await a2.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            success = True
            assert m.params[-1] == "adz"
        if m.command == "RESUME" and m.params[:1] == ["TOKEN"] and success:
            break
    assert success, "could not resume the auto-detached session"

    await a2.send("PRIVMSG #adz :recovered")
    assert await _saw_command_from(obs, "PRIVMSG", "adz", 10.0)

    try:
        await a2.disconnect()
    except Exception:
        pass
    await obs.send("QUIT :done")
    await obs.disconnect()


async def test_brb_suspends_and_resumes(ircd_tls_network):
    """A client-initiated BRB detaches the session and can be resumed."""
    hub = ircd_tls_network["hub"]

    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("brbobs", "brbobs", "Observer")
    await obs.send("JOIN #brb")
    await obs.wait_for("JOIN", timeout=5.0)

    brbc, token = await _ws_register_with_resume(hub, "brbby")
    await brbc.send("JOIN #brb")
    assert await _saw_command_from(obs, "JOIN", "brbby", 10.0)

    await brbc.send("BRB :back soon")
    got_brb = False
    for _ in range(10):
        m = await brbc.recv(timeout=5.0)
        if m.command == "BRB":
            got_brb = True
            assert int(m.params[-1]) > 0  # server tells the client its window
            break
    assert got_brb, "did not receive BRB <timeout> acknowledgement"

    # Peers see no QUIT; the session was suspended, not exited.
    assert not await _saw_command_from(obs, "QUIT", "brbby", 4.0)

    # A fresh connection resumes the BRB'd session.
    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK brbtmp")
    await a2.send("USER brbtmp 0 * :tmp")
    await a2.send(f"RESUME {token}")
    success = False
    for _ in range(80):
        m = await a2.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            success = True
        if m.command == "RESUME" and m.params[:1] == ["TOKEN"] and success:
            break
    assert success, "could not resume the BRB'd session"

    try:
        await a2.disconnect()
    except Exception:
        pass
    await obs.send("QUIT :done")
    await obs.disconnect()


async def test_clean_quit_still_exits(ircd_tls_network):
    """A normal QUIT from an eligible client must still exit (not detach)."""
    hub = ircd_tls_network["hub"]

    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("adzobs2", "adzobs2", "Observer2")
    await obs.send("JOIN #adz2")
    await obs.wait_for("JOIN", timeout=5.0)

    adz, _ = await _ws_register_with_resume(hub, "adzq")
    await adz.send("JOIN #adz2")
    assert await _saw_command_from(obs, "JOIN", "adzq", 10.0)

    await adz.send("QUIT :leaving")
    assert await _saw_command_from(obs, "QUIT", "adzq", 10.0), (
        "a clean QUIT did not propagate (should exit, not detach)"
    )

    await obs.send("QUIT :done")
    await obs.disconnect()
