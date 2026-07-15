"""Adversarial / edge-case tests for PR #77 (umode +I, hide idle time).

Covers:
  - interaction with WHOX %l (whocmds.c change)
  - oper and self bypasses in WHO
  - +I vs +i case sensitivity
  - idempotent set/unset, setting modes on other users
  - toggling -I restores visibility
  - multi-server: +I must propagate so the target's server enforces it
    for remote targeted WHOIS, and remote opers must still bypass it
"""

import asyncio

import pytest

from irc_client import IRCClient


async def get_umodes(client, nick=None):
    """Query own usermodes via MODE <nick>; returns the RPL_UMODEIS string.

    Uses a generous timeout: tests here issue several commands in a row
    from one client, and ircu's flood penalty delays later replies.
    """
    msg = await client.send_and_expect(
        f"MODE {nick or client.nick}", "221", timeout=20.0
    )
    return msg.params[-1]


async def set_hideidle_or_skip(client):
    """Set +I on the client, skipping the test if the build lacks +I."""
    await client.send(f"MODE {client.nick} +I")
    umodes = await get_umodes(client)
    if "I" not in umodes:
        pytest.skip("+I usermode not supported by this server build")


async def whois_shows_idle(client, target):
    """Issue a targeted WHOIS (parc >= 3) and report whether 317 came back."""
    await client.send(f"WHOIS {target} {target}")
    msgs = await client.collect_until("318", timeout=20.0)
    return any(m.command == "317" for m in msgs)


async def whox_idle(client, target):
    """WHOX query for nick + idle (%nl); returns the idle field as a string."""
    await client.send(f"WHO {target} %nl")
    msgs = await client.collect_until("315", timeout=20.0)  # RPL_ENDOFWHO
    for m in msgs:
        if m.command == "354":  # RPL_WHOSPCRPL: <me> <nick> <idle>
            return m.params[-1]
    return None


# ---------------------------------------------------------------------------
# Single-server edge cases
# ---------------------------------------------------------------------------

pytestmark = []  # marks are applied per test below


@pytest.mark.single_server
async def test_hideidle_set_unset_idempotent(make_client):
    """Setting +I twice and unsetting -I twice must not error or wedge."""
    user = await make_client("idem77")
    await set_hideidle_or_skip(user)

    await user.send(f"MODE {user.nick} +I")
    assert "I" in await get_umodes(user)

    await user.send(f"MODE {user.nick} -I")
    await user.send(f"MODE {user.nick} -I")
    assert "I" not in await get_umodes(user)


@pytest.mark.single_server
async def test_hideidle_distinct_from_invisible(make_client):
    """+I (hide idle) and +i (invisible) are distinct, case-sensitive modes."""
    user = await make_client("case77")
    await set_hideidle_or_skip(user)

    # Force a known state for +i, then check +I survived independently.
    await user.send(f"MODE {user.nick} -i")
    umodes = await get_umodes(user)
    assert "I" in umodes and "i" not in umodes

    await user.send(f"MODE {user.nick} +i")
    umodes = await get_umodes(user)
    assert "I" in umodes and "i" in umodes

    await user.send(f"MODE {user.nick} -I")
    umodes = await get_umodes(user)
    assert "I" not in umodes and "i" in umodes, (
        f"-I must not touch +i: {umodes!r}"
    )


@pytest.mark.single_server
async def test_cannot_set_hideidle_on_another_user(make_client):
    """MODE <othernick> +I must be rejected (ERR_USERSDONTMATCH 502)."""
    alice = await make_client("alice77")
    bob = await make_client("bob77")

    msg = await alice.send_and_expect(f"MODE {bob.nick} +I", "502")
    assert msg.command == "502"

    # Bob's umodes must be untouched.
    assert "I" not in await get_umodes(bob)


@pytest.mark.single_server
async def test_unset_restores_whois_idle_visibility(make_client):
    """After -I, a non-oper's targeted WHOIS shows idle time again."""
    target = await make_client("flip77")
    observer = await make_client("watch77")
    await set_hideidle_or_skip(target)

    assert not await whois_shows_idle(observer, target.nick)

    await target.send(f"MODE {target.nick} -I")
    assert "I" not in await get_umodes(target)

    assert await whois_shows_idle(observer, target.nick), (
        "Idle time should be visible again after -I"
    )


@pytest.mark.single_server
async def test_whox_idle_zero_for_nonoper(make_client):
    """WHOX %l reports 0 idle for a +I target queried by a non-oper.

    (With HIS_WHO_SERVERNAME enabled this is already 0 for non-opers;
    the assertion guards that +I never makes it worse, e.g. by breaking
    the field format.)
    """
    target = await make_client("wtgt77")
    observer = await make_client("wobs77")
    await set_hideidle_or_skip(target)

    # Share a channel so WHO can see the target regardless of +i defaults.
    await target.send("JOIN #test_pr77_who")
    await target.wait_for("366")
    await observer.send("JOIN #test_pr77_who")
    await observer.wait_for("366")

    idle = await whox_idle(observer, target.nick)
    assert idle == "0", f"non-oper should see idle 0 for +I user, got {idle!r}"


@pytest.mark.single_server
async def test_whox_idle_visible_to_oper_and_self(make_client):
    """WHOX %l still reports a numeric idle to opers and to the user."""
    target = await make_client("wtgt77b")
    oper = await make_client("woper77")
    await set_hideidle_or_skip(target)

    await target.send("JOIN #test_pr77_whob")
    await target.wait_for("366")
    await oper.send("JOIN #test_pr77_whob")
    await oper.wait_for("366")

    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=5.0)

    oper_idle = await whox_idle(oper, target.nick)
    assert oper_idle is not None and oper_idle.isdigit(), (
        f"oper should see numeric idle for +I user, got {oper_idle!r}"
    )

    self_idle = await whox_idle(target, target.nick)
    assert self_idle is not None and self_idle.isdigit(), (
        f"+I user should see their own idle, got {self_idle!r}"
    )


# ---------------------------------------------------------------------------
# Multi-server: propagation
# ---------------------------------------------------------------------------


@pytest.mark.multi_server
async def test_hideidle_propagates_to_remote_server(ircd_network):
    """+I set on leaf1 must be enforced when WHOIS arrives via the hub.

    A targeted "WHOIS nick nick" from a hub user is forwarded to leaf1
    (the target's server), where the idle check runs. If +I were not
    propagated (it must be a global umode), leaf1 would leak the idle
    time. Also verifies -I propagates and restores visibility.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    target = IRCClient()
    await target.connect(leaf1["host"], leaf1["port"])
    await target.register("rtgt77", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("robs77", "testuser", "Test User")

    try:
        await target.send(f"MODE {target.nick} +I")
        umodes = await get_umodes(target)
        if "I" not in umodes:
            pytest.skip("+I usermode not supported by this server build")
        await asyncio.sleep(1.0)  # let the mode propagate leaf1 -> hub

        assert not await whois_shows_idle(observer, target.nick), (
            "+I did not propagate: remote targeted WHOIS leaked idle time"
        )

        await target.send(f"MODE {target.nick} -I")
        assert "I" not in await get_umodes(target)
        await asyncio.sleep(1.0)

        assert await whois_shows_idle(observer, target.nick), (
            "-I did not propagate: idle time still hidden remotely"
        )
    finally:
        for client in (target, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


@pytest.mark.multi_server
async def test_remote_oper_bypasses_hideidle(ircd_network):
    """An oper on the hub still sees a +I leaf1 user's idle time.

    The oper's targeted WHOIS is answered by leaf1, so this checks that
    the oper bypass works with a *remote* sptr (relies on +o propagation).
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    target = IRCClient()
    await target.connect(leaf1["host"], leaf1["port"])
    await target.register("rtgt77b", "testuser", "Test User")

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("roper77", "testuser", "Test User")

    try:
        await target.send(f"MODE {target.nick} +I")
        umodes = await get_umodes(target)
        if "I" not in umodes:
            pytest.skip("+I usermode not supported by this server build")

        await oper.send("OPER testoper operpass")
        await oper.wait_for("381", timeout=5.0)
        await asyncio.sleep(1.0)  # let +I and +o propagate

        assert await whois_shows_idle(oper, target.nick), (
            "Remote oper should still see a +I user's idle time"
        )
    finally:
        for client in (target, oper):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
