"""CPRIVMSG resets the sender's idle time like PRIVMSG (commit c61b856)."""

from __future__ import annotations

import asyncio

import pytest

from common import drain, join, sender_nick, wait_for_join, whois

pytestmark = pytest.mark.single_server


async def _idle(client) -> int:
    """Own idle time; HIS_WHOIS_IDLETIME hides other users' idle from non-opers."""
    replies = await whois(client, client.nick)
    assert "317" in replies, sorted(replies)
    return int(replies["317"].params[2])


async def test_cprivmsg_resets_idle(make_client):
    chan = "#cp_idle"
    op = await make_client("cpop1")
    peer = await make_client("cppeer1")
    await join(op, chan)
    await join(peer, chan)
    await wait_for_join(op, chan, "cppeer1")
    await asyncio.sleep(3.2)
    assert await _idle(op) >= 3

    await op.send(f"CPRIVMSG cppeer1 {chan} :quiet hello")
    msg = await peer.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert sender_nick(msg) == "cpop1" and msg.params[-1] == "quiet hello"
    assert await _idle(op) <= 1


async def test_cnotice_does_not_reset_idle(make_client):
    """Only CPRIVMSG got the idle reset; CNOTICE is unchanged (control)."""
    chan = "#cn_idle"
    op = await make_client("cnop2")
    peer = await make_client("cnpeer2")
    await join(op, chan)
    await join(peer, chan)
    await wait_for_join(op, chan, "cnpeer2")
    await asyncio.sleep(3.2)
    before = await _idle(op)
    assert before >= 3

    await op.send(f"CNOTICE cnpeer2 {chan} :quiet notice")
    msg = await peer.wait_for_user_msg("NOTICE", timeout=5.0)
    assert msg.params[-1] == "quiet notice"
    assert await _idle(op) >= before
