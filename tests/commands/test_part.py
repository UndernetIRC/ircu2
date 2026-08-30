"""PART of a channel one is not on is answered with ERR_NOTONCHANNEL and
does not disturb the connection (commit 7e978f9 made joinbuf_join() bail
early when there is no membership)."""

from __future__ import annotations

import pytest

from common import join

pytestmark = pytest.mark.single_server


async def test_part_not_member(make_client):
    other = await make_client("partown1")
    await join(other, "#part_notmember")
    client = await make_client("partnm1")
    await client.send("PART #part_notmember :not here")
    err = await client.wait_for("442", timeout=5.0)
    assert err.params[1].lower() == "#part_notmember"
    await client.send("PING :alive")
    pong = await client.wait_for("PONG", timeout=5.0)
    assert pong.params[-1] == "alive"


async def test_part_list_mixed_membership(make_client):
    keeper = await make_client("partkeep2")
    await join(keeper, "#part_mix_b")
    client = await make_client("partmix2")
    await join(client, "#part_mix_a")
    await client.send("PART #part_mix_a,#part_mix_b,#part_mix_none :leaving")
    part = await client.wait_for("PART", timeout=5.0)
    assert part.params[0].lower() == "#part_mix_a"
    err = await client.wait_for("442", timeout=5.0)
    assert err.params[1].lower() == "#part_mix_b"
    err = await client.wait_for("403", timeout=5.0)
    assert err.params[1].lower() == "#part_mix_none"


async def test_part_twice(make_client):
    keeper = await make_client("partkeep3")
    await join(keeper, "#part_twice")
    client = await make_client("parttwice3")
    await join(client, "#part_twice")
    await client.send("PART #part_twice")
    await client.wait_for("PART", timeout=5.0)
    await client.send("PART #part_twice")
    err = await client.wait_for("442", timeout=5.0)
    assert err.params[1].lower() == "#part_twice"


async def test_part_unknown_channel(make_client):
    client = await make_client("partnone4")
    await client.send("PART #part_never_existed")
    err = await client.wait_for("403", timeout=5.0)
    assert err.params[1].lower() == "#part_never_existed"
