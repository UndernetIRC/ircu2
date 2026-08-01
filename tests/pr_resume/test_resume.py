"""M3 tests: the RESUME command and connection reattachment.

A new secure-WebSocket connection presenting a valid token for a detached
session adopts that session: it keeps the original nick, account, and channel
memberships, receives RESUME SUCCESS and a rotated token, and peers see no
churn. Invalid or already-used tokens fail with a single generic reply.

Detach is triggered by an abrupt transport reset (the production path).
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
    """Consume CAP LS, request resume, and consume the issued token."""
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


async def test_resume_reattaches_detached_session(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("rezobs", "rezobs", "Observer")
    await _oper_up(obs)
    await obs.send("JOIN #rez")
    await obs.wait_for("JOIN", timeout=5.0)

    alice, token = await _ws_register_with_resume(hub, "rezzy")
    await alice.send("JOIN #rez")
    assert await _saw_command_from(obs, "JOIN", "rezzy", 10.0)

    alice._ws.transport.abort()  # abrupt transport loss -> auto-detach
    # No QUIT while detached.
    assert not await _saw_command_from(obs, "QUIT", "rezzy", 2.0)

    # New connection resumes the detached session with the old token.
    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK rtmp")
    await a2.send("USER rtmp 0 * :temp")
    await a2.send(f"RESUME {token}")

    # Collect the resume response: SUCCESS, then the replayed view (welcome
    # burst, self JOIN + NAMES for #rez), then the rotated TOKEN last.
    success = False
    new_token = None
    saw_welcome = False   # RPL_WELCOME 001
    saw_self_join = False # self JOIN #rez
    saw_names = False     # RPL_NAMREPLY 353 for #rez
    for _ in range(80):
        m = await a2.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            success = True
            assert m.params[-1] == "rezzy"
        elif m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
            new_token = m.params[-1]
        elif m.command == "001":
            saw_welcome = True
        elif m.command == "JOIN" and m.prefix and m.prefix.startswith("rezzy!"):
            if m.params and m.params[-1] == "#rez":
                saw_self_join = True
        elif m.command == "353" and "#rez" in m.params:
            saw_names = True
        if new_token:  # TOKEN is sent last
            break
    assert success, "did not receive RESUME SUCCESS"
    assert new_token and new_token != token, "token was not rotated"
    # State replay reconstructed the client's own view (M4).
    assert saw_welcome, "resumed client did not get the welcome burst (001)"
    assert saw_self_join, "resumed client did not get its self JOIN for #rez"
    assert saw_names, "resumed client did not get NAMES for #rez"

    # Peers never saw a QUIT/JOIN churn for alice during the resume.
    assert not await _saw_command_from(obs, "QUIT", "rezzy", 2.0)

    # The resumed connection *is* alice: a message from it shows alice as source
    # on the channel she still belongs to.
    await a2.send("PRIVMSG #rez :back online")
    assert await _saw_command_from(obs, "PRIVMSG", "rezzy", 10.0), (
        "resumed connection did not act as alice on her channel"
    )

    # The old token is now invalid (rotated on success): reusing it fails.
    a3 = IRCWebSocketClient()
    await a3.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a3)
    await a3.send("NICK rtmp2")
    await a3.send("USER rtmp2 0 * :temp2")
    await a3.send(f"RESUME {token}")
    failed = False
    for _ in range(15):
        m = await a3.recv(timeout=10.0)
        if m.command == "FAIL" and "RESUME" in m.params:
            failed = True
            break
        if m.command in ("376", "422"):  # registered normally instead
            break
    assert failed, "reused (rotated) token was not rejected"

    for c in (a2, a3):
        try:
            await c.disconnect()
        except Exception:
            pass
    await obs.send("QUIT :done")
    await obs.disconnect()


async def test_resume_invalid_token_fails(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    c = IRCWebSocketClient()
    await c.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(c)
    await c.send("NICK nobody")
    await c.send("USER nobody 0 * :n")
    await c.send("RESUME bogus.token")
    failed = False
    for _ in range(15):
        m = await c.recv(timeout=10.0)
        if m.command == "FAIL" and "RESUME" in m.params:
            assert "INVALID_TOKEN" in m.params
            failed = True
            break
        if m.command in ("376", "422"):
            break
    assert failed, "invalid token did not produce FAIL RESUME"
    await c.disconnect()


DETACH_AWAY = "Temporarily detached, messages will be missed."


async def _whois_away(observer, nick, timeout=10.0):
    """WHOIS `nick` and return its RPL_AWAY (301) text, or None if not away."""
    await observer.send(f"WHOIS {nick}")
    away = None
    for _ in range(40):
        m = await observer.recv(timeout=timeout)
        if m.command == "301" and len(m.params) >= 3 and m.params[1] == nick:
            away = m.params[-1]
        if m.command == "318":  # end of WHOIS
            break
    return away


async def _wait_whois_away(observer, nick, expected, timeout=15.0):
    """Poll WHOIS until `nick`'s away equals `expected` (state changes such as
    detach/reattach are processed asynchronously), returning the last value."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    last = object()
    while loop.time() < deadline:
        last = await _whois_away(observer, nick)
        if last == expected:
            return last
        await asyncio.sleep(0.3)
    return last


async def test_resume_restores_away_modes_and_channel_state(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("rzwobs", "rzwobs", "Observer")

    # A secure-WS client (so it holds +z), opered (+o), away, ops+moderates a chan.
    alice = IRCWebSocketClient()
    await alice.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    token = await _drain_cap_and_token(alice)
    await alice.send("NICK rzw")
    await alice.send("USER rzw 0 * :rzw")
    await alice.send("CAP END")
    while True:
        m = await alice.recv(timeout=10.0)
        if m.command in ("376", "422"):
            break
    await _oper_up(alice)  # +o
    await alice.send("AWAY :gone fishing")
    await alice.send("JOIN #rzw")
    await alice.send("MODE #rzw +m")
    await alice.send("TOPIC #rzw :hi there")
    await alice.wait_for("TOPIC", timeout=10.0)  # settle: all prior applied

    # Baseline: peers see alice's own away.
    assert await _wait_whois_away(obs, "rzw", "gone fishing") == "gone fishing"

    alice._ws.transport.abort()  # unexpected loss -> detach

    # While detached, the away is the temporary detach message.
    assert await _wait_whois_away(obs, "rzw", DETACH_AWAY) == DETACH_AWAY

    # Resume, and verify the full replayed view.
    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK rzwtmp")
    await a2.send("USER rzwtmp 0 * :t")
    await a2.send(f"RESUME {token}")

    saw = dict(success=False, usermode=False, nowaway=False,
               join=False, chanmode=False, names=False)
    new_token = None
    for _ in range(120):
        m = await a2.recv(timeout=10.0)
        c = m.command
        if c == "RESUME" and m.params[:1] == ["SUCCESS"]:
            saw["success"] = True
        elif (c == "MODE" and m.prefix and m.prefix.startswith("rzw!")
              and m.params[:1] == ["rzw"]
              and "z" in m.params[-1] and "o" in m.params[-1]):
            saw["usermode"] = True          # user modes echoed (incl. +z and +o)
        elif c == "306":                     # RPL_NOWAWAY
            saw["nowaway"] = True
        elif (c == "JOIN" and m.prefix and m.prefix.startswith("rzw!")
              and m.params[-1:] == ["#rzw"]):
            saw["join"] = True
        elif c == "324" and "#rzw" in m.params:  # RPL_CHANNELMODEIS
            if "m" in "".join(m.params[2:]):
                saw["chanmode"] = True
        elif c == "353" and "#rzw" in m.params:  # RPL_NAMREPLY (members)
            if "rzw" in m.params[-1]:
                saw["names"] = True
        elif c == "RESUME" and m.params[:1] == ["TOKEN"]:
            new_token = m.params[-1]
        if new_token:
            break

    assert saw["success"], "no RESUME SUCCESS"
    assert saw["usermode"], "user modes (+z, +o) not echoed on resume"
    assert saw["nowaway"], "away state not restored on resume"
    assert saw["join"], "channel not rejoined on resume"
    assert saw["chanmode"], "channel modes (+m) not replayed on resume"
    assert saw["names"], "channel members not replayed on resume"

    # The original away is restored (not left as the detach message).
    assert await _wait_whois_away(obs, "rzw", "gone fishing") == "gone fishing"

    await a2.disconnect()
    await obs.disconnect()


async def test_message_to_detached_client_gets_cannotsend(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("dmsndr", "dmsndr", "Sender")

    alice, _tok = await _ws_register_with_resume(hub, "dmz")
    alice._ws.transport.abort()  # detach
    assert await _wait_whois_away(sender, "dmz", DETACH_AWAY) == DETACH_AWAY

    # PRIVMSG to a detached client: sender gets RPL_AWAY (301) and
    # ERR_CANNOTSENDTOUSER (531); the message is not delivered.
    await sender.send("PRIVMSG dmz :hello")
    got_531 = got_301 = False
    text_531 = ""
    for _ in range(15):
        m = await sender.recv(timeout=10.0)
        if m.command == "531" and "dmz" in m.params:
            got_531 = True
            text_531 = m.params[-1]
        if m.command == "301" and "dmz" in m.params:
            got_301 = True
        if got_531:
            break
    assert got_301, "no RPL_AWAY (301) for a message to a detached client"
    assert got_531, "no ERR_CANNOTSENDTOUSER (531) for PRIVMSG to detached client"
    assert "Cannot send message:" in text_531 and "temporarily detached" in text_531

    # NOTICE must NOT trigger an auto-reply (RFC); no 531.
    await sender.send("NOTICE dmz :hi")
    saw_531_for_notice = False
    for _ in range(5):
        try:
            m = await sender.recv(timeout=2.0)
        except (asyncio.TimeoutError, ConnectionError):
            break
        if m.command == "531":
            saw_531_for_notice = True
            break
    assert not saw_531_for_notice, "NOTICE to a detached client wrongly got a 531"

    await sender.disconnect()


async def test_resume_clears_detach_away_when_not_previously_away(
        ircd_tls_network):
    hub = ircd_tls_network["hub"]

    obs = IRCClient()
    await obs.connect(hub["host"], hub["port"])
    await obs.register("rzcobs", "rzcobs", "Observer")

    alice, token = await _ws_register_with_resume(hub, "rzc")
    await alice.send("JOIN #rzc")
    await alice.wait_for("JOIN", timeout=5.0)
    assert await _wait_whois_away(obs, "rzc", None) is None  # not away

    alice._ws.transport.abort()  # detach
    assert await _wait_whois_away(obs, "rzc", DETACH_AWAY) == DETACH_AWAY  # temporary away set

    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK rzctmp")
    await a2.send("USER rzctmp 0 * :t")
    await a2.send(f"RESUME {token}")

    success = False
    saw_nowaway = False
    new_token = None
    for _ in range(80):
        m = await a2.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            success = True
        elif m.command == "306":
            saw_nowaway = True
        elif m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
            new_token = m.params[-1]
        if new_token:
            break
    assert success, "no RESUME SUCCESS"
    assert not saw_nowaway, "resumed client was wrongly left away"
    assert await _wait_whois_away(obs, "rzc", None) is None  # detach away cleared

    await a2.disconnect()
    await obs.disconnect()


async def test_resume_preserves_oper_privileges(ircd_tls_network):
    """Regression: a resumed oper keeps +o AND usable privileges.

    The bug restored the +o umode but not con_privs / OPER_HANDLER, so oper
    commands failed with ERR_NOPRIVILEGES (481) after resume.  PRIVS is a
    side-effect-free oper-only command: 270 on success, 481 if the handler or
    privileges were not carried across the connection swap.
    """
    hub = ircd_tls_network["hub"]

    alice, token = await _ws_register_with_resume(hub, "operez")
    await _oper_up(alice)  # global oper (holds PRIV_REHASH etc.)

    alice._ws.transport.abort()  # abrupt loss -> auto-detach

    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK otmp")
    await a2.send("USER otmp 0 * :temp")
    await a2.send(f"RESUME {token}")

    saw_success = False
    saw_oper_mode = False
    for _ in range(80):
        m = await a2.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            saw_success = True
        elif (m.command == "MODE" and m.prefix and m.prefix.startswith("operez!")
              and "o" in "".join(m.params)):
            saw_oper_mode = True
        elif m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
            break
    assert saw_success, "no RESUME SUCCESS"
    assert saw_oper_mode, "+o umode not restored on resume"

    # The regression check: an oper-only command must work, not return 481.
    await a2.send("PRIVS")
    outcome = None
    for _ in range(20):
        m = await a2.recv(timeout=10.0)
        if m.command == "481":
            outcome = "481"
            break
        if m.command == "270":  # RPL_PRIVS
            outcome = "270"
            break
    assert outcome == "270", (
        f"resumed oper PRIVS returned {outcome!r}; privileges/handler not restored"
    )


async def test_resume_on_insecure_websocket_is_refused(ircd_tls_network):
    """RESUME over a non-TLS WebSocket is refused with INSECURE_SESSION, which
    is checked before the token is even parsed."""
    hub = ircd_tls_network["hub"]
    c = IRCWebSocketClient()
    await c.connect(f"ws://{hub['host']}:{hub['ws_plain_port']}/")
    await c.send("NICK inseckz")
    await c.send("USER inseckz 0 * :inseckz")
    await c.send("RESUME aaaa.bbbb")
    saw = None
    for _ in range(40):
        m = await c.recv(timeout=10.0)
        if m.command == "FAIL" and "RESUME" in m.params:
            saw = m.params
            break
    assert saw and "INSECURE_SESSION" in saw, f"expected INSECURE_SESSION, got {saw}"


async def test_resume_after_registration_is_refused(ircd_tls_network):
    """RESUME sent after registration completes is refused with
    REGISTRATION_IS_COMPLETED."""
    hub = ircd_tls_network["hub"]
    c, token = await _ws_register_with_resume(hub, "regdonez")  # fully registered
    await c.send(f"RESUME {token}")
    saw = None
    for _ in range(20):
        m = await c.recv(timeout=10.0)
        if m.command == "FAIL" and "RESUME" in m.params:
            saw = m.params
            break
    assert saw and "REGISTRATION_IS_COMPLETED" in saw, (
        f"expected REGISTRATION_IS_COMPLETED, got {saw}"
    )


async def test_resume_attempts_are_capped(ircd_tls_network):
    """After RESUME_MAX_ATTEMPTS invalid presentations on one connection the
    server returns CANNOT_RESUME instead of INVALID_TOKEN.  A capability client
    holds its own session, so the per-connection attempt counter engages."""
    hub = ircd_tls_network["hub"]
    c = IRCWebSocketClient()
    await c.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(c)  # CAP REQ resume -> token issued -> cli_resume
    await c.send("NICK maxatt")
    await c.send("USER maxatt 0 * :maxatt")

    codes = []
    for _ in range(5):  # still pre-registration (no CAP END)
        await c.send("RESUME zzzzzzzzzzzzzzzzzzzzzz.zzzzzzzzzzzz")
        while True:
            m = await c.recv(timeout=10.0)
            if m.command == "FAIL" and m.params[:1] == ["RESUME"]:
                codes.append(m.params[1])
                break

    assert codes[:3] == ["INVALID_TOKEN"] * 3, f"first 3 should be INVALID_TOKEN: {codes}"
    assert codes[3] == "CANNOT_RESUME", f"4th attempt should be CANNOT_RESUME: {codes}"
