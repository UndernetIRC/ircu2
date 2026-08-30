"""extended-join is honoured on every JOIN path (commits 4db844d, dfd9afa,
cd6e2e4).

Clients with extended-join receive ``JOIN <chan> <account|*> :<realname>``;
clients without it receive the classic single-parameter JOIN.  Covered
paths: normal join, own join, delayed-join reveal (+D), kick of a hidden
member, server burst, remote join, and the host-hiding re-JOIN.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from common import drain, join, sender_nick, wait_for_join

pytestmark = pytest.mark.single_server


def _assert_extended(msg, chan, account, realname):
    assert msg.params[0].lower() == chan.lower(), msg.raw
    assert len(msg.params) == 3, f"expected extended JOIN, got {msg.raw}"
    assert msg.params[1] == account, msg.raw
    assert msg.params[2] == realname, msg.raw


def _assert_plain(msg, chan):
    assert msg.params[0].lower() == chan.lower(), msg.raw
    assert len(msg.params) == 1, f"expected plain JOIN, got {msg.raw}"


async def test_join_extended_vs_plain(make_client):
    chan = "#ej_basic"
    ext = await make_client("ejobs1", caps=["extended-join"])
    plain = await make_client("ejplain1")
    await join(ext, chan)
    await join(plain, chan)
    await wait_for_join(ext, chan, "ejplain1")
    await drain(ext)
    await drain(plain)

    joiner = await make_client("ejjoin1", realname="Joiner One")
    await join(joiner, chan)
    _assert_extended(await wait_for_join(ext, chan, "ejjoin1"), chan, "*", "Joiner One")
    _assert_plain(await wait_for_join(plain, chan, "ejjoin1"), chan)


async def test_own_join_is_extended(make_client):
    ext = await make_client("ejself2", caps=["extended-join"], realname="Self Two")
    msg = await join(ext, "#ej_self")
    _assert_extended(msg, "#ej_self", "*", "Self Two")


async def test_join_carries_account(make_client, ulined_server):
    chan = "#ej_acct"
    ext = await make_client("ejobs3", caps=["extended-join"])
    await join(ext, chan)
    await drain(ext)

    joiner = await make_client("ejacct3", realname="Account Three")
    numnick = await ulined_server.wait_for_user("ejacct3")
    await ulined_server.send_account(numnick, "AcctThree")
    await asyncio.sleep(0.4)
    await join(joiner, chan)
    _assert_extended(await wait_for_join(ext, chan, "ejacct3"), chan, "AcctThree", "Account Three")


async def test_delayed_join_reveal_is_extended(make_client):
    """RevealDelayedJoin() sends extended/plain JOIN per capability."""
    chan = "#ej_delay"
    op = await make_client("ejop4")
    await join(op, chan)
    await op.send(f"MODE {chan} +D")
    await op.wait_for("MODE")
    ext = await make_client("ejobs4", caps=["extended-join"])
    plain = await make_client("ejplain4")
    await join(ext, chan)
    await join(plain, chan)
    await asyncio.sleep(0.3)
    await drain(ext)
    await drain(plain)

    hidden = await make_client("ejhid4", realname="Hidden Four")
    await join(hidden, chan)
    # Delayed: nobody sees the join yet.
    await ext.assert_no_message("JOIN", timeout=1.0)
    await hidden.send(f"PRIVMSG {chan} :reveal me")
    _assert_extended(await wait_for_join(ext, chan, "ejhid4"), chan, "*", "Hidden Four")
    _assert_plain(await wait_for_join(plain, chan, "ejhid4"), chan)


async def test_delayed_join_reveal_sends_away(make_client):
    """An away user's reveal is followed by AWAY for away-notify clients (cd6e2e4)."""
    chan = "#ej_delay_away"
    op = await make_client("ejop5")
    await join(op, chan)
    await op.send(f"MODE {chan} +D")
    await op.wait_for("MODE")
    obs = await make_client("ejobs5", caps=["extended-join", "away-notify"])
    nocap = await make_client("ejnocap5")
    await join(obs, chan)
    await join(nocap, chan)
    await asyncio.sleep(0.3)
    await drain(obs)
    await drain(nocap)

    hidden = await make_client("ejhid5", realname="Hidden Five")
    await hidden.send("AWAY :gone")
    await hidden.wait_for("306")
    await join(hidden, chan)
    await hidden.send(f"PRIVMSG {chan} :reveal me")
    _assert_extended(await wait_for_join(obs, chan, "ejhid5"), chan, "*", "Hidden Five")
    away = await obs.wait_for_user_msg("AWAY", timeout=5.0)
    assert sender_nick(away) == "ejhid5" and away.params[-1] == "gone"
    await wait_for_join(nocap, chan, "ejhid5")
    await nocap.assert_no_message("AWAY", timeout=1.0)


async def test_kick_of_hidden_member_shows_extended_join_to_kicker(make_client):
    """m_kick reveals a delayed member to the kicker with sendjointo_one()."""
    chan = "#ej_kick"
    op = await make_client("ejop6", caps=["extended-join"])
    await join(op, chan)
    await op.send(f"MODE {chan} +D")
    await op.wait_for("MODE")
    await drain(op)
    hidden = await make_client("ejhid6", realname="Hidden Six")
    await join(hidden, chan)
    await op.assert_no_message("JOIN", timeout=1.0)

    await op.send(f"KICK {chan} ejhid6 :out")
    _assert_extended(await wait_for_join(op, chan, "ejhid6"), chan, "*", "Hidden Six")
    kick = await op.wait_for_user_msg("KICK", timeout=5.0)
    assert kick.params[1] == "ejhid6"


async def test_burst_join_is_extended(make_client, ulined_server):
    """Members added by a server BURST get extended JOINs (ms_burst)."""
    chan = "#ej_burst"
    ext = await make_client("ejobs7", caps=["extended-join"])
    plain = await make_client("ejplain7")
    await join(ext, chan)
    await join(plain, chan)
    await asyncio.sleep(0.3)
    await drain(ext)
    await drain(plain)

    numnick = await ulined_server.introduce_user(
        "ejburst7", modes="+ir BurstAcct", realname="Burst Seven"
    )
    await ulined_server._send(f"{ulined_server.server_numnick} B {chan} {int(time.time())} {numnick}")
    _assert_extended(await wait_for_join(ext, chan, "ejburst7"), chan, "BurstAcct", "Burst Seven")
    _assert_plain(await wait_for_join(plain, chan, "ejburst7"), chan)


async def test_host_hiding_rejoin_is_extended(make_client, ulined_server):
    """hide_hostmask() re-JOINs non-chghost peers with sendjointo_channel_butserv()."""
    chan = "#ej_hide"
    ext = await make_client("ejobs8", caps=["extended-join"])
    await join(ext, chan)
    subject = await make_client("ejhide8", realname="Hide Eight")
    await join(subject, chan)
    await wait_for_join(ext, chan, "ejhide8")
    await drain(ext)

    numnick = await ulined_server.wait_for_user("ejhide8")
    await ulined_server.send_account(numnick, "HideAcct")
    await asyncio.sleep(0.3)
    await subject.send("MODE ejhide8 +x")
    quit_msg = await ext.wait_for_user_msg("QUIT", timeout=5.0)
    assert sender_nick(quit_msg) == "ejhide8" and quit_msg.params[-1] == "Registered"
    rejoin = await wait_for_join(ext, chan, "ejhide8")
    _assert_extended(rejoin, chan, "HideAcct", "Hide Eight")
    assert rejoin.prefix.endswith("@HideAcct.users.undernet.org"), rejoin.raw


@pytest.mark.multi_server
async def test_remote_join_is_extended(ircd_network, make_client):
    chan = "#ej_remote"
    hub, leaf = ircd_network["hub"], ircd_network["leaf1"]
    ext = await make_client("ejobs9", caps=["extended-join"])
    plain = await make_client("ejplain9")
    await join(ext, chan)
    await join(plain, chan)
    await asyncio.sleep(0.3)
    await drain(ext)
    await drain(plain)

    remote = await make_client("ejrem9", host=leaf["host"], port=leaf["port"], realname="Remote Nine")
    await join(remote, chan)
    _assert_extended(await wait_for_join(ext, chan, "ejrem9"), chan, "*", "Remote Nine")
    _assert_plain(await wait_for_join(plain, chan, "ejrem9"), chan)
