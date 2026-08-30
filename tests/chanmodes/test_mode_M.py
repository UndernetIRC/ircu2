"""Channel mode +M: moderate unauthenticated users (commit 47af138, #5).

On a +M channel, members without an account cannot speak or change nick
unless voiced/opped; users with an account (set via services ACCOUNT) can.
"""

from __future__ import annotations

import asyncio

import pytest

from common import chan_modes, drain, join, sender_nick, wait_for_join

pytestmark = pytest.mark.single_server


async def _setup(make_client, chan, nicks=("mop", "mplain")):
    op = await make_client(nicks[0])
    plain = await make_client(nicks[1])
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    await op.wait_for("MODE")
    await join(plain, chan)
    await wait_for_join(op, chan, nicks[1])
    await drain(op)
    await drain(plain)
    return op, plain


async def test_mode_M_shown(make_client):
    op = await make_client("mshow1")
    chan = "#modem_show"
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    echo = await op.wait_for("MODE")
    assert "M" in echo.params[1], echo.raw
    assert "M" in await chan_modes(op, chan)


async def test_unregistered_member_cannot_speak(make_client):
    """PRIVMSG from an account-less member is refused with ERR_CANNOTSENDTOCHAN."""
    chan = "#modem_speak"
    op, plain = await _setup(make_client, chan, ("mop2", "mplain2"))
    await plain.send(f"PRIVMSG {chan} :hello?")
    err = await plain.wait_for("404", timeout=5.0)
    assert err.params[1].lower() == chan
    await op.assert_no_message("PRIVMSG", timeout=1.0)


async def test_voiced_unregistered_member_can_speak(make_client):
    """+v overrides +M for an account-less member."""
    chan = "#modem_voice"
    op, plain = await _setup(make_client, chan, ("mop3", "mplain3"))
    await op.send(f"MODE {chan} +v mplain3")
    await op.wait_for("MODE")
    await plain.wait_for("MODE")
    await plain.send(f"PRIVMSG {chan} :voiced hello")
    msg = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert sender_nick(msg) == "mplain3" and msg.params[-1] == "voiced hello"


async def test_unregistered_member_cannot_change_nick(make_client):
    """Nick changes are blocked (ERR_BANNICKCHANGE) for account-less members of +M."""
    chan = "#modem_nick"
    op, plain = await _setup(make_client, chan, ("mop4", "mplain4"))
    await plain.send("NICK mplain4b")
    err = await plain.wait_for("437", timeout=5.0)
    assert err.params[1].lower() == chan, err.raw
    await op.assert_no_message("NICK", timeout=1.0)

    await op.send(f"MODE {chan} +v mplain4")
    await plain.wait_for("MODE")
    await plain.send("NICK mplain4c")
    nick = await plain.wait_for("NICK", timeout=5.0)
    assert nick.params[0] == "mplain4c"


async def test_registered_member_can_speak(make_client, ulined_server):
    """A member with an account (services ACCOUNT) is not moderated by +M."""
    chan = "#modem_acct"
    op, acct = await _setup(make_client, chan, ("mop5", "macct5"))
    numnick = await ulined_server.wait_for_user("macct5")
    await ulined_server.send_account(numnick, "AcctFive")
    await asyncio.sleep(0.4)
    await drain(acct)

    await acct.send(f"PRIVMSG {chan} :registered hello")
    msg = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert sender_nick(msg) == "macct5" and msg.params[-1] == "registered hello"

    await acct.send("NICK macct5b")
    nick = await acct.wait_for("NICK", timeout=5.0)
    assert nick.params[0] == "macct5b"


async def test_unregistered_non_member_cannot_speak(make_client, ulined_server):
    """Without +n, +M still blocks account-less non-members but not registered ones."""
    chan = "#modem_ext"
    op = await make_client("mop6")
    await join(op, chan)
    await op.send(f"MODE {chan} +M-n")
    await op.wait_for("MODE")
    await drain(op)

    outsider = await make_client("mout6")
    await outsider.send(f"PRIVMSG {chan} :outside")
    err = await outsider.wait_for("404", timeout=5.0)
    assert err.params[1].lower() == chan
    await op.assert_no_message("PRIVMSG", timeout=1.0)

    numnick = await ulined_server.wait_for_user("mout6")
    await ulined_server.send_account(numnick, "AcctOut")
    await asyncio.sleep(0.4)
    await outsider.send(f"PRIVMSG {chan} :outside registered")
    msg = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "outside registered"


async def test_unsetting_M_allows_speaking(make_client):
    chan = "#modem_unset"
    op, plain = await _setup(make_client, chan, ("mop7", "mplain7"))
    await op.send(f"MODE {chan} -M")
    await op.wait_for("MODE")
    await plain.wait_for("MODE")
    await plain.send(f"PRIVMSG {chan} :free again")
    msg = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "free again"


async def test_clearmode_clears_M(make_client, oper):
    op = await make_client("mop8")
    chan = "#modem_clear"
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    await op.wait_for("MODE")
    await oper.send(f"CLEARMODE {chan} M")
    await op.wait_for("MODE", timeout=5.0)
    assert "M" not in await chan_modes(op, chan)


async def test_isupport_advertises_M(make_client):
    """RPL_ISUPPORT CHANMODES lists +M among the argument-less modes (e3bf7e9)."""
    client = await make_client("msup9")
    chanmodes = None
    for msg in client.received_messages:
        if msg.command == "005":
            for p in msg.params:
                if p.startswith("CHANMODES="):
                    chanmodes = p.split("=", 1)[1]
    assert chanmodes, "no CHANMODES token in 005"
    groups = chanmodes.split(",")
    assert len(groups) == 4 and "M" in groups[3], chanmodes
