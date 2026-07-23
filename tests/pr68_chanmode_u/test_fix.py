"""Tests for channel mode +u: suppress part messages.

When a channel has +u set, a user leaving the channel has their PART
reason hidden from other members; the PART itself is still shown.
"""

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def chan_modes(client, channel):
    msg = await client.send_and_expect(f"MODE {channel}", "324")
    return next((p for p in msg.params if p.startswith("+")), "")


async def make_op(make_client, nick, channel):
    op = await make_client(nick)
    await op.send(f"JOIN {channel}")
    await op.wait_for("366")
    return op


async def test_myinfo_advertises_chanmode_u(ircd_hub):
    """+u is advertised as a channel mode in RPL_MYINFO (004)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK myinfo68")
        await client.send("USER testuser 0 * :Test User")
        msg = await client.wait_for("004", timeout=10.0)
        chanmodes = msg.params[4]
        assert "u" in chanmodes, f"chanmode u not in 004: {chanmodes!r}"
    finally:
        await client.disconnect()


async def test_isupport_advertises_chanmode_u(ircd_hub):
    """+u is advertised in the RPL_ISUPPORT (005) CHANMODES token."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK isupp68")
        await client.send("USER testuser 0 * :Test User")
        chanmodes = None
        while chanmodes is None:
            msg = await client.wait_for("005", timeout=10.0)
            chanmodes = next(
                (p for p in msg.params if p.startswith("CHANMODES=")), None
            )
        modes = chanmodes.removeprefix("CHANMODES=")
        assert "u" in modes, f"chanmode u not in 005 CHANMODES: {modes!r}"
        assert "P" not in modes, f"old chanmode P still in 005 CHANMODES: {modes!r}"
    finally:
        await client.disconnect()


async def test_chanmode_u_set_and_unset(make_client):
    """A chanop can set and clear +u on a channel."""
    op = await make_op(make_client, "op68set", "#pr68set")

    await op.send("MODE #pr68set +u")
    await op.wait_for("MODE")
    assert "u" in await chan_modes(op, "#pr68set")

    await op.send("MODE #pr68set -u")
    await op.wait_for("MODE")
    assert "u" not in await chan_modes(op, "#pr68set")


async def test_part_reason_suppressed_with_u(make_client):
    """In a +u channel, a leaving user's PART reason is hidden."""
    op = await make_op(make_client, "op68sup", "#pr68sup")
    await op.send("MODE #pr68sup +u")
    await op.wait_for("MODE")

    leaver = await make_client("lv68sup")
    await leaver.send("JOIN #pr68sup")
    await leaver.wait_for("366")
    await op.wait_for("JOIN")

    await leaver.send("PART #pr68sup :secret reason")
    part = await op.wait_for("PART", timeout=5.0)
    assert len(part.params) == 1 or part.params[-1] == "", (
        f"part reason leaked despite +u: {part.params}"
    )


async def test_part_reason_visible_without_u(make_client):
    """Without +u, a leaving user's PART reason is shown normally."""
    op = await make_op(make_client, "op68vis", "#pr68vis")

    leaver = await make_client("lv68vis")
    await leaver.send("JOIN #pr68vis")
    await leaver.wait_for("366")
    await op.wait_for("JOIN")

    await leaver.send("PART #pr68vis :goodbye all")
    part = await op.wait_for("PART", timeout=5.0)
    assert part.params[-1] == "goodbye all", (
        f"part reason missing without +u: {part.params}"
    )


async def test_quit_reason_suppressed_with_u(make_client):
    """A quitting user in a +u channel has their QUIT reason replaced."""
    op = await make_op(make_client, "op68q", "#pr68q")
    await op.send("MODE #pr68q +u")
    await op.wait_for("MODE")

    quitter = await make_client("qt68q")
    await quitter.send("JOIN #pr68q")
    await quitter.wait_for("366")
    await op.wait_for("JOIN")

    await quitter.send("QUIT :secret quit reason")
    q = await op.wait_for("QUIT", timeout=5.0)
    assert "secret quit reason" not in q.params[-1], (
        f"quit reason leaked despite +u: {q.params}"
    )


async def test_quit_reason_visible_without_u(make_client):
    """Without +u, a quitting user's QUIT reason is shown to the channel."""
    op = await make_op(make_client, "op68qv", "#pr68qv")

    quitter = await make_client("qt68qv")
    await quitter.send("JOIN #pr68qv")
    await quitter.wait_for("366")
    await op.wait_for("JOIN")

    await quitter.send("QUIT :goodbye cruel world")
    q = await op.wait_for("QUIT", timeout=5.0)
    assert "goodbye cruel world" in q.params[-1], (
        f"quit reason missing without +u: {q.params}"
    )
