"""Account-based auto-reattach (RESUME_AUTO_ACCOUNT).

An authenticated client that reconnects with the same nick + account is
reattached to its detached session with no client support and no token.

The security path needs no account and runs against the shared tls-hub: a
same-nick reconnect that is not authenticated must not hijack the session, and
the deferred collision must leave that session intact (still resumable by
token).

The authenticated paths run against the dedicated acct-hub, whose iauth stub
logs every client into an account named after its USER username (login-on-
connect), so a reconnecting client gets a verified account during registration.
"""

import asyncio
import ssl

import pytest

from irc_ws_client import IRCWebSocketClient

RESUME_CAP = "draft/resume-0.5"
ERR_NICKNAMEINUSE = "433"

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]


def _tls_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _drain_cap_and_token(c):
    """Consume CAP LS, request resume, and return the issued token."""
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


async def _acct_connect(acct):
    c = IRCWebSocketClient()
    await c.connect(f"wss://{acct['host']}:{acct['wss_port']}/", ssl=_tls_ctx())
    return c


async def _acct_register(acct, nick, account):
    """Register a secure-WS client with no resume capability; the iauth stub
    logs it into `account` (its USER username).  Returns once registered."""
    c = await _acct_connect(acct)
    await c.send(f"NICK {nick}")
    await c.send(f"USER {account} 0 * :{nick}")
    while True:
        m = await c.recv(timeout=15.0)
        if m.command in ("376", "422"):
            return c


async def _acct_register_with_resume(acct, nick, account):
    """Register a resume-capable client (gets a token) that the iauth stub also
    logs into `account`.  Returns (client, token)."""
    c = await _acct_connect(acct)
    token = await _drain_cap_and_token(c)
    await c.send(f"NICK {nick}")
    await c.send(f"USER {account} 0 * :{nick}")
    await c.send("CAP END")
    while True:
        m = await c.recv(timeout=15.0)
        if m.command in ("376", "422"):
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


async def test_unauthenticated_same_nick_does_not_hijack(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    alice, token = await _ws_register_with_resume(hub, "acctzz")
    await alice.send("JOIN #acct")
    await alice.wait_for("JOIN", timeout=5.0)

    alice._ws.transport.abort()  # abrupt loss -> auto-detach; session held

    # A brand-new, UNAUTHENTICATED secure-WS client claiming the same nick must
    # not adopt the session: the collision is deferred, then resolved as an
    # ordinary nick-in-use once registration would complete.
    imposter = await _acct_connect(hub)
    await imposter.send("NICK acctzz")
    await imposter.send("USER acctzz 0 * :imposter")

    got_inuse = False
    for _ in range(20):
        m = await imposter.recv(timeout=10.0)
        assert not (m.command == "RESUME" and m.params[:1] == ["SUCCESS"]), (
            "unauthenticated same-nick reconnect hijacked the session"
        )
        if m.command == ERR_NICKNAMEINUSE:
            got_inuse = True
            break
    assert got_inuse, "deferred collision was not resolved as nick-in-use"
    await imposter.disconnect()

    # The detached session survived the deferred collision intact: the rightful
    # owner can still resume it with its token.
    a2 = IRCWebSocketClient()
    await a2.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await _drain_cap_and_token(a2)
    await a2.send("NICK rtmp")
    await a2.send("USER rtmp 0 * :temp")
    await a2.send(f"RESUME {token}")

    success = False
    for _ in range(40):
        m = await a2.recv(timeout=10.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            success = True
            assert m.params[-1] == "acctzz"
            break
        if m.command == "FAIL" and "RESUME" in m.params:
            raise AssertionError("session was lost after the deferred collision")
    assert success, "rightful owner could not resume the surviving session"
    await a2.disconnect()


async def test_account_reattach_same_account(ircd_tls_network):
    acct = ircd_tls_network["acct"]

    # An observer sharing the channel confirms the reattach is seamless.
    obs = await _acct_register(acct, "aracobs", "obsacct")
    await obs.send("JOIN #ar")
    await obs.wait_for("JOIN", timeout=5.0)

    # An authenticated client with NO resume capability -- resumable purely by
    # account (resume_session_ensure).
    alice = await _acct_register(acct, "araccy", "araccount")
    await alice.send("JOIN #ar")
    assert await _saw_command_from(obs, "JOIN", "araccy", 10.0)

    alice._ws.transport.abort()  # abrupt loss -> auto-detach
    assert not await _saw_command_from(obs, "QUIT", "araccy", 2.0)

    # Reconnect with the SAME nick and SAME account: no token, no resume cap.
    a2 = await _acct_connect(acct)
    await a2.send("NICK araccy")
    await a2.send("USER araccount 0 * :re")

    success = False
    saw_self_join = False
    for _ in range(80):
        m = await a2.recv(timeout=15.0)
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            success = True
            assert m.params[-1] == "araccy"
        elif (m.command == "JOIN" and m.prefix
              and m.prefix.startswith("araccy!") and m.params[-1:] == ["#ar"]):
            saw_self_join = True
        if success and saw_self_join:
            break
    assert success, "authenticated same-account reconnect did not reattach"
    assert saw_self_join, "reattached client did not get its channel back"

    # No churn for peers, and the reattached connection *is* araccy.
    assert not await _saw_command_from(obs, "QUIT", "araccy", 2.0)
    await a2.send("PRIVMSG #ar :back")
    assert await _saw_command_from(obs, "PRIVMSG", "araccy", 10.0)

    await a2.disconnect()
    await obs.disconnect()


async def test_account_reattach_wrong_account_rejected(ircd_tls_network):
    acct = ircd_tls_network["acct"]

    bob = await _acct_register(acct, "arwrong", "acct_one")
    await bob.send("JOIN #arw")
    await bob.wait_for("JOIN", timeout=5.0)

    bob._ws.transport.abort()  # auto-detach; session held

    # Same nick, DIFFERENT account: must not adopt the session.
    other = await _acct_connect(acct)
    await other.send("NICK arwrong")
    await other.send("USER acct_two 0 * :other")

    got_inuse = False
    for _ in range(30):
        m = await other.recv(timeout=15.0)
        assert not (m.command == "RESUME" and m.params[:1] == ["SUCCESS"]), (
            "a different account reattached another user's session"
        )
        if m.command == ERR_NICKNAMEINUSE:
            got_inuse = True
            break
    assert got_inuse, "wrong-account reconnect was not rejected as nick-in-use"
    await other.disconnect()


async def test_deferred_collision_after_prior_nick_keeps_hash_consistent(
        ircd_tls_network):
    hub = ircd_tls_network["hub"]

    # A detached session holds the nick "dfrx".
    alice, _tok = await _ws_register_with_resume(hub, "dfrx")
    alice._ws.transport.abort()

    # A client that first registers (and is hashed under) a temp nick, then
    # sends the detached nick, which is deferred.  The deferral must unhash the
    # temp nick, or the client's hash entry is left dangling when it exits.
    imp = IRCWebSocketClient()
    await imp.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await imp.send("NICK dfrtmp")   # free -> hashed under dfrtmp
    await imp.send("NICK dfrx")     # collides with detached session -> deferred
    await imp.send("USER dfrx 0 * :imp")
    for _ in range(20):
        m = await imp.recv(timeout=10.0)
        if m.command == ERR_NICKNAMEINUSE:  # unauthenticated -> rejected
            break
    await imp.disconnect()

    # The temp nick must be cleanly reusable afterwards (no stale hash entry).
    other = IRCWebSocketClient()
    await other.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx())
    await other.send("NICK dfrtmp")
    await other.send("USER dfrtmp 0 * :o")
    registered = False
    for _ in range(20):
        m = await other.recv(timeout=10.0)
        if m.command in ("376", "422"):
            registered = True
            break
    assert registered, "temp nick unusable after deferred collision (hash desync)"
    await other.disconnect()


async def test_account_optout_flag_is_not_detached(ircd_tls_network):
    acct = ircd_tls_network["acct"]

    obs = await _acct_register(acct, "optobs", "obswatch")
    await obs.send("JOIN #opt")
    await obs.wait_for("JOIN", timeout=5.0)

    # An account whose flags carry the resume opt-out bit (X_NO_AUTO_RESUME).
    user = await _acct_register(acct, "optme", "optoutacc")
    await user.send("JOIN #opt")
    assert await _saw_command_from(obs, "JOIN", "optme", 10.0)

    # Abrupt transport loss is normally auto-detached; an opted-out account is
    # not, so peers see an ordinary QUIT instead.
    user._ws.transport.abort()
    assert await _saw_command_from(obs, "QUIT", "optme", 10.0), (
        "opted-out account was detached instead of disconnecting normally"
    )
    await obs.disconnect()


async def test_account_optout_blocks_account_reattach_of_token_session(
        ircd_tls_network):
    acct = ircd_tls_network["acct"]

    obs = await _acct_register(acct, "optcobs", "obswatch2")
    await obs.send("JOIN #optc")
    await obs.wait_for("JOIN", timeout=5.0)

    # A resume-capable client with an opted-out account still gets a token
    # session, so it detaches on loss (the token path is unaffected)...
    c, _token = await _acct_register_with_resume(acct, "optcap", "optoutcap")
    await c.send("JOIN #optc")
    assert await _saw_command_from(obs, "JOIN", "optcap", 10.0)
    c._ws.transport.abort()
    assert not await _saw_command_from(obs, "QUIT", "optcap", 3.0), (
        "opt-out wrongly suppressed detach for a token session"
    )

    # ...but a no-token reconnect with the same nick+account must NOT be
    # adopted via the account path.
    c2 = await _acct_connect(acct)
    await c2.send("NICK optcap")
    await c2.send("USER optoutcap 0 * :re")
    for _ in range(30):
        m = await c2.recv(timeout=15.0)
        assert not (m.command == "RESUME" and m.params[:1] == ["SUCCESS"]), (
            "opted-out account was reattached via the account path"
        )
        if m.command == ERR_NICKNAMEINUSE:
            break
    await c2.disconnect()
    await obs.disconnect()


async def test_account_reattach_issues_no_token(ircd_tls_network):
    """Regression: an account-path resumer that never negotiated the capability
    must NOT be handed a RESUME TOKEN (the token path is opt-in via the cap)."""
    acct = ircd_tls_network["acct"]

    alice = await _acct_register(acct, "notoky", "notokacct")
    await alice.send("JOIN #notok")
    await alice.wait_for("JOIN", timeout=10.0)

    alice._ws.transport.abort()  # abrupt loss -> auto-detach; session held

    # Reconnect: same nick + account, no resume cap, no token presented.
    a2 = await _acct_connect(acct)
    await a2.send("NICK notoky")
    await a2.send("USER notokacct 0 * :re")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + 20.0
    saw_success = False
    saw_token = False
    while loop.time() < deadline:
        try:
            m = await a2.recv(timeout=3.0)
        except (asyncio.TimeoutError, ConnectionError):
            break  # idle -> the resume burst is complete
        if m.command == "RESUME" and m.params[:1] == ["SUCCESS"]:
            saw_success = True
        elif m.command == "RESUME" and m.params[:1] == ["TOKEN"]:
            saw_token = True
    assert saw_success, "account reattach did not succeed"
    assert not saw_token, "account-path resumer was wrongly issued a RESUME TOKEN"
