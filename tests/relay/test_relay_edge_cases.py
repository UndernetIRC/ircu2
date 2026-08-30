"""Edge cases for nick@server relaying, JOIN target limits and CPRIVMSG
(commits 0039f1f, 5ffe0a1, 54cfd56, c61b856)."""

from __future__ import annotations

import asyncio

import pytest

from common import collect, drain, join, set_feature, wait_for_join

pytestmark = pytest.mark.single_server


async def test_notice_with_host_qualifier_to_service(make_client, ulined_server):
    """nick%host@server keeps the full target when forwarded to a service."""
    await ulined_server.introduce_user("QualSvc", modes="+ik", host="svc.host")
    sender = await make_client("rel_q1")
    await sender.send("NOTICE QualSvc%svc.host@services.test.net :qualified")
    line = await ulined_server.wait_for_token("O", timeout=5.0)
    assert "QualSvc%svc.host@services.test.net :qualified" in line, line


async def test_directed_notice_rules_apply_to_opers(oper, make_client):
    target = await make_client("rel_t2")
    await oper.send("NOTICE rel_t2@hub.test.net :oper says hi")
    err = await oper.wait_for("401", timeout=5.0)
    assert err.params[1] == "rel_t2@hub.test.net"
    await target.assert_no_message("NOTICE", timeout=1.0)


async def test_directed_notice_to_nonexistent_service_user(make_client, ulined_server):
    """Forwarding to a service server does not check that the nick exists."""
    sender = await make_client("rel_s3")
    await sender.send("NOTICE Nobody@services.test.net :anyone?")
    line = await ulined_server.wait_for_token("O", timeout=5.0)
    assert "Nobody@services.test.net :anyone?" in line
    await sender.assert_no_message("401", timeout=1.0)


async def test_directed_privmsg_silence_does_not_apply_remotely(make_client, ulined_server):
    """is_silenced() is only consulted for local delivery."""
    await ulined_server.introduce_user("SilSvc", modes="+ik")
    sender = await make_client("rel_s4")
    await sender.send("PRIVMSG SilSvc@services.test.net :hello")
    line = await ulined_server.wait_for_token("P", timeout=5.0)
    assert "SilSvc@services.test.net :hello" in line


async def test_rejoining_same_channel_is_not_a_new_target(make_client, oper):
    await set_feature(oper, "JOIN_TARGET", "TRUE")
    try:
        client = await make_client("rel_jt6")
        chan = "#rel_jt6_same"
        for _ in range(5):
            await join(client, chan)
            await client.send(f"PART {chan}")
            await client.wait_for("PART", timeout=5.0)
        await client.assert_no_message("439", timeout=0.5)
    finally:
        await set_feature(oper, "JOIN_TARGET", "FALSE")


@pytest.mark.multi_server
async def test_join_burst_from_leaf_user_not_limited(ircd_network, make_client):
    leaf = ircd_network["leaf1"]
    client = await make_client("rel_jt7", host=leaf["host"], port=leaf["port"])
    chans = [f"#rel_jt7_{i}" for i in range(15)]
    await client.send("JOIN " + ",".join(chans))
    msgs = await collect(client, 3.0)
    joined = {m.params[0].lower() for m in msgs if m.command == "JOIN"}
    assert joined == {c.lower() for c in chans}


async def test_cprivmsg_requires_op_or_voice(make_client):
    chan = "#rel_cp8"
    op = await make_client("rel_op8")
    peon = await make_client("rel_peon8")
    await join(op, chan)
    await join(peon, chan)
    await peon.send(f"CPRIVMSG rel_op8 {chan} :may I?")
    err = await peon.wait_for("489", timeout=5.0)
    assert err.params[1].lower() == chan
    await op.assert_no_message("PRIVMSG", timeout=0.5)


async def test_cprivmsg_target_must_be_on_channel(make_client):
    chan = "#rel_cp9"
    op = await make_client("rel_op9")
    other = await make_client("rel_other9")
    await join(op, chan)
    await op.send(f"CPRIVMSG rel_other9 {chan} :you there?")
    err = await op.wait_for("441", timeout=5.0)
    assert err.params[1] == "rel_other9" and err.params[2].lower() == chan
    await other.assert_no_message("PRIVMSG", timeout=0.5)


async def test_cprivmsg_needs_all_parameters(make_client):
    op = await make_client("rel_op10")
    await op.send("CPRIVMSG rel_op10 #rel_cp10")
    err = await op.wait_for("461", timeout=5.0)
    assert err.params[1] == "CPRIVMSG"
