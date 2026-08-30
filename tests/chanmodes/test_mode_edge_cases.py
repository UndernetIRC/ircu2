"""Edge cases for channel modes +u (no part/quit messages; introduced as +u by
68727a8/c1bd976 and renamed to +u by PR #68) and +M (47af138).

The basic +u behaviour (set/unset, part/quit suppression, remote part) is
covered by pr68_chanmode_u/; these are the remaining angles.
"""

from __future__ import annotations

import asyncio

import pytest

from common import chan_modes, drain, join, sender_nick, wait_for_join


@pytest.mark.single_server
async def test_u_hides_chanop_part_message_too(make_client):
    """+u applies to everybody on the channel, including its operators."""
    op = await make_client("pe_op2")
    member = await make_client("pe_mem2")
    chan = "#modeu_oppart"
    await join(op, chan)
    await op.send(f"MODE {chan} +u")
    await op.wait_for("MODE")
    await join(member, chan)
    await drain(member)
    await op.send(f"PART {chan} :op leaving")
    part = await member.wait_for_user_msg("PART", timeout=5.0)
    assert sender_nick(part) == "pe_op2"
    assert len(part.params) == 1 or part.params[-1] == "", part.raw


@pytest.mark.single_server
async def test_u_on_local_channel(make_client):
    """Local (&) channels support +u as well."""
    op = await make_client("pe_op3")
    member = await make_client("pe_mem3")
    chan = "&modeu_local"
    await join(op, chan)
    await op.send(f"MODE {chan} +u")
    echo = await op.wait_for("MODE")
    assert "u" in echo.params[1], echo.raw
    await join(member, chan)
    await drain(op)
    await member.send(f"PART {chan} :local bye")
    part = await op.wait_for_user_msg("PART", timeout=5.0)
    assert len(part.params) == 1 or part.params[-1] == "", part.raw


@pytest.mark.single_server
async def test_u_with_empty_part_message(make_client):
    """A PART without a comment on +u stays a bare PART (no empty trailing)."""
    op = await make_client("pe_op4")
    member = await make_client("pe_mem4")
    chan = "#modeu_empty"
    await join(op, chan)
    await op.send(f"MODE {chan} +u")
    await op.wait_for("MODE")
    await join(member, chan)
    await drain(op)
    await member.send(f"PART {chan}")
    part = await op.wait_for_user_msg("PART", timeout=5.0)
    assert part.params[0].lower() == chan
    assert len(part.params) == 1 or part.params[-1] == "", part.raw


@pytest.mark.multi_server
async def test_u_quit_rewritten_across_servers(ircd_network, make_client):
    leaf = ircd_network["leaf1"]
    op = await make_client("pe_op6")
    chan = "#modeu_s2s_quit"
    await join(op, chan)
    await op.send(f"MODE {chan} +u")
    await op.wait_for("MODE")
    remote = await make_client("pe_rem6", host=leaf["host"], port=leaf["port"])
    await join(remote, chan)
    await wait_for_join(op, chan, "pe_rem6")
    await asyncio.sleep(0.3)
    await drain(op)
    await remote.send("QUIT :remote custom quit")
    quit_msg = await op.wait_for_user_msg("QUIT", timeout=5.0)
    assert sender_nick(quit_msg) == "pe_rem6"
    assert quit_msg.params[-1] == "Signed off", quit_msg.raw


@pytest.mark.single_server
async def test_M_notice_from_unregistered_is_dropped_silently(make_client):
    """NOTICE has no error reply; the notice simply is not delivered."""
    op = await make_client("me_op1")
    plain = await make_client("me_plain1")
    chan = "#modem_notice"
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    await op.wait_for("MODE")
    await join(plain, chan)
    await drain(op)
    await drain(plain)
    await plain.send(f"NOTICE {chan} :psst")
    await op.assert_no_message("NOTICE", timeout=1.5)
    await plain.assert_no_message("404", timeout=0.5)


@pytest.mark.single_server
async def test_M_opped_unregistered_member_can_speak(make_client):
    op = await make_client("me_op2")
    plain = await make_client("me_plain2")
    chan = "#modem_opped"
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    await op.wait_for("MODE")
    await join(plain, chan)
    await op.send(f"MODE {chan} +o me_plain2")
    await op.wait_for("MODE")
    await plain.wait_for("MODE")
    await plain.send(f"PRIVMSG {chan} :opped hello")
    msg = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "opped hello"


@pytest.mark.single_server
async def test_M_devoice_moderates_again(make_client):
    op = await make_client("me_op3")
    plain = await make_client("me_plain3")
    chan = "#modem_devoice"
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    await op.wait_for("MODE")
    await join(plain, chan)
    await op.send(f"MODE {chan} +v me_plain3")
    await op.wait_for("MODE")
    await plain.wait_for("MODE")
    await op.send(f"MODE {chan} -v me_plain3")
    await op.wait_for("MODE")
    await plain.wait_for("MODE")
    await plain.send(f"PRIVMSG {chan} :still allowed?")
    err = await plain.wait_for("404", timeout=5.0)
    assert err.params[1].lower() == chan


@pytest.mark.single_server
async def test_M_and_m_together(make_client):
    """+Mm: voice lifts both restrictions for an account-less member."""
    op = await make_client("me_op4")
    plain = await make_client("me_plain4")
    chan = "#modem_both"
    await join(op, chan)
    await op.send(f"MODE {chan} +Mm")
    await op.wait_for("MODE")
    await join(plain, chan)
    await plain.send(f"PRIVMSG {chan} :blocked")
    await plain.wait_for("404", timeout=5.0)
    await op.send(f"MODE {chan} +v me_plain4")
    await plain.wait_for("MODE")
    await plain.send(f"PRIVMSG {chan} :voiced")
    msg = await op.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "voiced"


@pytest.mark.multi_server
async def test_M_enforced_on_remote_member_server(ircd_network, make_client):
    """A leaf user in a hub-created +M channel is moderated by its own server."""
    leaf = ircd_network["leaf1"]
    op = await make_client("me_op5")
    chan = "#modem_s2s"
    await join(op, chan)
    await op.send(f"MODE {chan} +M")
    await op.wait_for("MODE")
    remote = await make_client("me_rem5", host=leaf["host"], port=leaf["port"])
    await join(remote, chan)
    await wait_for_join(op, chan, "me_rem5")
    await asyncio.sleep(0.3)
    await remote.send(f"PRIVMSG {chan} :from leaf")
    err = await remote.wait_for("404", timeout=5.0)
    assert err.params[1].lower() == chan
    await op.assert_no_message("PRIVMSG", timeout=1.0)


@pytest.mark.single_server
async def test_M_persists_in_mode_query_with_other_modes(make_client):
    op = await make_client("me_op6")
    chan = "#modem_list"
    await join(op, chan)
    await op.send(f"MODE {chan} +Munt")
    await op.wait_for("MODE")
    modes = await chan_modes(op, chan)
    for m in "Munt":
        assert m in modes, modes


@pytest.mark.single_server
async def test_u_quit_hides_message_on_other_channels_too(make_client):
    """The QUIT rewrite applies to every channel the user shares, not only +u ones."""
    op = await make_client("ue_op7")
    other = await make_client("ue_other7")
    quitter = await make_client("ue_quit7")
    uchan, plain = "#modeu_multi_u", "#modeu_multi_plain"
    await join(op, uchan)
    await op.send(f"MODE {uchan} +u")
    await op.wait_for("MODE")
    await join(other, plain)
    await join(quitter, uchan)
    await join(quitter, plain)
    await wait_for_join(other, plain, "ue_quit7")
    await drain(other)
    await quitter.send("QUIT :leaked?")
    quit_msg = await other.wait_for_user_msg("QUIT", timeout=5.0)
    assert quit_msg.params[-1] == "Signed off", quit_msg.raw


@pytest.mark.single_server
async def test_u_toggle_restores_part_messages(make_client):
    op = await make_client("ue_op8")
    leaver = await make_client("ue_leave8")
    chan = "#modeu_toggle"
    await join(op, chan)
    await op.send(f"MODE {chan} +u")
    await op.wait_for("MODE")
    await op.send(f"MODE {chan} -u")
    await op.wait_for("MODE")
    await join(leaver, chan)
    await wait_for_join(op, chan, "ue_leave8")
    await drain(op)
    await leaver.send(f"PART {chan} :bye again")
    part = await op.wait_for_user_msg("PART", timeout=5.0)
    assert part.params[-1] == "bye again", part.raw


@pytest.mark.single_server
async def test_clearmode_clears_u(make_client, oper):
    """CLEARMODE removes +u like any other simple mode (do_clearmode table)."""
    op = await make_client("ue_op9")
    chan = "#modeu_clear"
    await join(op, chan)
    await op.send(f"MODE {chan} +un")
    await op.wait_for("MODE")
    assert "u" in await chan_modes(op, chan)
    await oper.send(f"CLEARMODE {chan} u")
    await op.wait_for("MODE", timeout=5.0)
    modes = await chan_modes(op, chan)
    assert "u" not in modes and "n" in modes, modes
