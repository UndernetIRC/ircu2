"""Edge cases for extended-join and echo-message (commits 4db844d, dfd9afa,
cd6e2e4)."""

from __future__ import annotations

import asyncio

import pytest

from common import drain, join, sender_nick, wait_for_join

pytestmark = pytest.mark.single_server


async def test_extended_join_reveal_by_voice(make_client):
    """Giving +v to a hidden (+D) member reveals it with an extended JOIN."""
    chan = "#eje_voice"
    op = await make_client("eje_op1", caps=["extended-join"])
    await join(op, chan)
    await op.send(f"MODE {chan} +D")
    await op.wait_for("MODE")
    await drain(op)
    hidden = await make_client("eje_hid1", realname="Hidden Voice")
    await join(hidden, chan)
    await op.assert_no_message("JOIN", timeout=1.0)
    await op.send(f"MODE {chan} +v eje_hid1")
    reveal = await wait_for_join(op, chan, "eje_hid1")
    assert reveal.params == [chan, "*", "Hidden Voice"], reveal.raw
    mode = await op.wait_for("MODE", timeout=5.0)
    assert mode.params[0].lower() == chan and "v" in mode.params[1]


async def test_extended_join_account_with_hidden_host(make_client, ulined_server):
    """Account + hidden host: JOIN prefix uses the hidden host, param the account."""
    chan = "#eje_hidden"
    obs = await make_client("eje_obs2", caps=["extended-join"])
    await join(obs, chan)
    await drain(obs)
    joiner = await make_client("eje_join2", realname="Hidden Two")
    numnick = await ulined_server.wait_for_user("eje_join2")
    await ulined_server.send_account(numnick, "HidTwo")
    await asyncio.sleep(0.3)
    await joiner.send("MODE eje_join2 +x")
    await joiner.wait_for("396", timeout=5.0)
    await join(joiner, chan)
    msg = await wait_for_join(obs, chan, "eje_join2")
    assert msg.params == [chan, "HidTwo", "Hidden Two"], msg.raw
    assert msg.prefix.endswith("@HidTwo.users.undernet.org"), msg.raw


async def test_extended_join_after_cap_removed(make_client):
    """CAP REQ :-extended-join switches the client back to plain JOINs."""
    chan = "#eje_remove"
    obs = await make_client("eje_obs3", caps=["extended-join"])
    await join(obs, chan)
    await obs.send("CAP REQ :-extended-join")
    ack = await obs.wait_for("CAP", timeout=5.0)
    assert ack.params[1] == "ACK" and "-extended-join" in ack.params[-1]
    await drain(obs)
    joiner = await make_client("eje_join3")
    await join(joiner, chan)
    msg = await wait_for_join(obs, chan, "eje_join3")
    assert len(msg.params) == 1, msg.raw


async def test_extended_join_realname_with_spaces_and_colon(make_client):
    chan = "#eje_realname"
    obs = await make_client("eje_obs4", caps=["extended-join"])
    await join(obs, chan)
    await drain(obs)
    joiner = await make_client("eje_join4", realname="Real: Name  with   spaces")
    await join(joiner, chan)
    msg = await wait_for_join(obs, chan, "eje_join4")
    assert msg.params[2] == "Real: Name  with   spaces", msg.raw


async def test_echo_message_to_self(make_client):
    """PRIVMSG to one's own nick: delivery plus echo => two copies."""
    client = await make_client("ech_self1", caps=["echo-message"])
    await client.send("PRIVMSG ech_self1 :talking to myself")
    first = await client.wait_for_user_msg("PRIVMSG", timeout=5.0)
    second = await client.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert first.params[-1] == second.params[-1] == "talking to myself"
    await client.assert_no_message("PRIVMSG", timeout=0.5)


async def test_echo_message_wallchops(make_client):
    chan = "#ech_wallchops"
    op = await make_client("ech_op2", caps=["echo-message"])
    peer = await make_client("ech_peer2")
    await join(op, chan)
    await join(peer, chan)
    await asyncio.sleep(0.2)
    await drain(op)
    await op.send(f"WALLCHOPS {chan} :ops only")
    # WALLCHOPS is delivered (and echoed) as NOTICE @#chan :@ <text>
    echo = await op.wait_for_user_msg("NOTICE", timeout=5.0)
    assert sender_nick(echo) == "ech_op2", echo.raw
    assert echo.params == [f"@{chan}", "@ ops only"], echo.raw


async def test_echo_message_not_sent_when_blocked(make_client):
    """A message the server refuses (+n, not on channel) is not echoed."""
    chan = "#ech_blocked"
    op = await make_client("ech_op3")
    await join(op, chan)
    await op.send(f"MODE {chan} +n")
    await op.wait_for("MODE")
    outsider = await make_client("ech_out3", caps=["echo-message"])
    await outsider.send(f"PRIVMSG {chan} :from outside")
    err = await outsider.wait_for("404", timeout=5.0)
    assert err.params[1].lower() == chan
    await outsider.assert_no_message("PRIVMSG", timeout=1.0)


async def test_echo_message_multi_target(make_client):
    """PRIVMSG a,b: one echo per delivered target."""
    sender = await make_client("ech_multi4", caps=["echo-message"])
    t1 = await make_client("ech_t4a")
    t2 = await make_client("ech_t4b")
    await sender.send("PRIVMSG ech_t4a,ech_t4b :both of you")
    echoes = [await sender.wait_for_user_msg("PRIVMSG", timeout=5.0) for _ in range(2)]
    assert sorted(e.params[0] for e in echoes) == ["ech_t4a", "ech_t4b"]
    for t in (t1, t2):
        got = await t.wait_for_user_msg("PRIVMSG", timeout=5.0)
        assert got.params[-1] == "both of you"


async def test_echo_message_cprivmsg(make_client):
    chan = "#ech_cprivmsg"
    op = await make_client("ech_op5", caps=["echo-message"])
    peer = await make_client("ech_peer5")
    await join(op, chan)
    await join(peer, chan)
    await asyncio.sleep(0.2)
    await drain(op)
    await op.send(f"CPRIVMSG ech_peer5 {chan} :whispered")
    got = await peer.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert got.params == ["ech_peer5", "whispered"], got.raw
    echo = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert sender_nick(echo) == "ech_op5" and echo.params == ["ech_peer5", "whispered"], echo.raw


async def test_echo_message_cnotice(make_client):
    chan = "#ech_cnotice"
    op = await make_client("ech_op6", caps=["echo-message"])
    peer = await make_client("ech_peer6")
    await join(op, chan)
    await join(peer, chan)
    await asyncio.sleep(0.2)
    await drain(op)
    await op.send(f"CNOTICE ech_peer6 {chan} :whispered notice")
    got = await peer.wait_for_user_msg("NOTICE", timeout=5.0)
    assert got.params == ["ech_peer6", "whispered notice"], got.raw
    echo = await op.wait_for_user_msg("NOTICE", timeout=5.0)
    assert echo.params == ["ech_peer6", "whispered notice"], echo.raw


async def test_no_cprivmsg_echo_without_cap(make_client):
    chan = "#ech_cprivmsg_nocap"
    op = await make_client("ech_op7")
    peer = await make_client("ech_peer7")
    await join(op, chan)
    await join(peer, chan)
    await asyncio.sleep(0.2)
    await drain(op)
    await op.send(f"CPRIVMSG ech_peer7 {chan} :quiet")
    await peer.wait_for_user_msg("PRIVMSG", timeout=5.0)
    await op.assert_no_message("PRIVMSG", timeout=1.0)


async def test_refused_cprivmsg_is_not_echoed(make_client):
    """A whisper the server rejects (target not on channel) has no echo."""
    chan = "#ech_cprivmsg_refused"
    op = await make_client("ech_op8", caps=["echo-message"])
    other = await make_client("ech_other8")
    await join(op, chan)
    await op.send(f"CPRIVMSG ech_other8 {chan} :nope")
    await op.wait_for("441", timeout=5.0)
    await op.assert_no_message("PRIVMSG", timeout=1.0)
