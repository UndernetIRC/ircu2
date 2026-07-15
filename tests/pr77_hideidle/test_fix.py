"""TDD tests for PR #77: usermode +I hides idle time from non-opers.

Feature: when a user sets umode +I, their idle time (RPL_WHOISIDLE, 317)
is hidden from other users in WHOIS. The user themselves and IRC
operators can still see it.

With HIS_WHOIS_IDLETIME enabled (the default), a non-oper only ever sees
another local user's idle time via the targeted form "WHOIS nick nick"
(parc >= 3). PR #77 must hide the idle time even on that path.

This file also contains regression tests for a switch fall-through bug
in the PR as submitted: in set_user_mode() (ircd/s_user.c), the new
`case 'I':` was inserted between the end of `case 'z':` and its `break;`,
so processing mode 'z' falls through into the 'I' handler:

  - "MODE nick +z" incorrectly sets +I as a side effect (FLAG_TLS itself
    is reverted by the post-switch rules for non-servers, but the
    fall-through's SetHideIdle() sticks).
  - "MODE nick -z" (documented as a no-op: "There is no -z") incorrectly
    clears +I, silently and without propagation.

The two test_regression_* tests below FAIL on the unfixed PR branch and
pass once the missing `break;` is restored.
"""

import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.single_server


async def get_umodes(client, nick=None):
    """Query own usermodes via MODE <nick>; returns the RPL_UMODEIS string."""
    msg = await client.send_and_expect(f"MODE {nick or client.nick}", "221")
    return msg.params[-1]


async def whois_shows_idle(client, target):
    """Issue a targeted WHOIS (parc >= 3) and report whether 317 came back."""
    await client.send(f"WHOIS {target} {target}")
    msgs = await client.collect_until("318")
    return any(m.command == "317" for m in msgs)


async def test_myinfo_advertises_hideidle(ircd_hub):
    """The +I usermode must be advertised in RPL_MYINFO (004).

    PR #77 adds 'I' to infousermodes, which is reported in the 004
    registration numeric.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK myinfo77")
        await client.send("USER testuser 0 * :Test User")
        msg = await client.wait_for("004", timeout=10.0)
        # 004 params: <nick> <servername> <version> <usermodes> <chanmodes>
        usermodes = msg.params[3]
        assert "I" in usermodes, (
            f"usermode I not advertised in 004: {usermodes!r}"
        )
    finally:
        await client.disconnect()


async def test_hideidle_can_be_set_and_unset(make_client):
    """A user can set and unset umode +I on themselves."""
    user = await make_client("setter77")

    await user.send(f"MODE {user.nick} +I")
    umodes = await get_umodes(user)
    assert "I" in umodes, f"+I not set: umodes are {umodes!r}"

    await user.send(f"MODE {user.nick} -I")
    umodes = await get_umodes(user)
    assert "I" not in umodes, f"+I not cleared: umodes are {umodes!r}"


async def test_whois_idle_visible_without_hideidle(make_client):
    """Control: without +I, targeted WHOIS shows idle time to a non-oper.

    This confirms the test methodology — if this fails, the other WHOIS
    tests in this file prove nothing.
    """
    target = await make_client("tgt77a")
    observer = await make_client("obs77a")

    assert await whois_shows_idle(observer, target.nick), (
        "Targeted WHOIS of a user without +I should include RPL_WHOISIDLE"
    )


async def test_whois_idle_hidden_from_nonoper(make_client):
    """Core feature: +I hides RPL_WHOISIDLE from a non-oper.

    Even the targeted "WHOIS nick nick" form, which bypasses
    HIS_WHOIS_IDLETIME, must not reveal idle time of a +I user.
    """
    target = await make_client("tgt77b")
    observer = await make_client("obs77b")

    await target.send(f"MODE {target.nick} +I")
    # Synchronize: once the target sees its own umode reply, the server
    # has processed the mode change.
    assert "I" in await get_umodes(target)

    assert not await whois_shows_idle(observer, target.nick), (
        "RPL_WHOISIDLE leaked to a non-oper despite +I"
    )


async def test_whois_idle_visible_to_self(make_client):
    """A +I user can still see their own idle time in WHOIS."""
    user = await make_client("self77")

    await user.send(f"MODE {user.nick} +I")
    assert "I" in await get_umodes(user)

    assert await whois_shows_idle(user, user.nick), (
        "+I user should still see their own idle time"
    )


async def test_whois_idle_visible_to_oper(make_client):
    """An IRC operator can still see a +I user's idle time in WHOIS."""
    target = await make_client("tgt77c")
    oper = await make_client("oper77c")

    await target.send(f"MODE {target.nick} +I")
    assert "I" in await get_umodes(target)

    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=5.0)  # RPL_YOUREOPER

    assert await whois_shows_idle(oper, target.nick), (
        "Oper should still see a +I user's idle time"
    )


async def test_regression_plus_z_must_not_set_hideidle(make_client):
    """Regression: 'MODE +z' must not set +I via case fall-through.

    In the PR as submitted, case 'z' in set_user_mode() lost its break
    and falls through into case 'I'. A client sending +z (which is
    otherwise reverted for non-servers) ends up with +I set. On the
    network this means every TLS user bursted with +z silently gets +I.

    FAILS on the unfixed PR branch; passes once the break is restored.
    """
    user = await make_client("zplus77")

    await user.send(f"MODE {user.nick} +z")
    umodes = await get_umodes(user)
    assert "I" not in umodes, (
        f"MODE +z set +I as a side effect (fall-through bug): {umodes!r}"
    )
    assert "z" not in umodes, (
        f"MODE +z should be reverted for local users: {umodes!r}"
    )


async def test_regression_minus_z_must_not_clear_hideidle(make_client):
    """Regression: 'MODE -z' must not clear +I via case fall-through.

    -z is documented as a no-op ("There is no -z"), but the fall-through
    makes it silently clear +I without reporting or propagating a mode
    change, desyncing the flag across the network.

    FAILS on the unfixed PR branch; passes once the break is restored.
    """
    user = await make_client("zminus77")

    await user.send(f"MODE {user.nick} +I")
    umodes = await get_umodes(user)
    if "I" not in umodes:
        pytest.skip("+I usermode not supported by this server build")

    await user.send(f"MODE {user.nick} -z")
    umodes = await get_umodes(user)
    assert "I" in umodes, (
        f"MODE -z cleared +I as a side effect (fall-through bug): {umodes!r}"
    )
