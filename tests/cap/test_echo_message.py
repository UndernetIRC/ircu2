"""echo-message capability (commit 4db844d).

A client that negotiated echo-message receives a copy of every PRIVMSG and
NOTICE it sends (to users, channels, and nick@server targets); a client
without it receives nothing back.
"""

from __future__ import annotations

import asyncio

import pytest

from common import drain, join, sender_nick

pytestmark = pytest.mark.single_server


async def test_privmsg_to_user_is_echoed(make_client):
    sender = await make_client("echo1", caps=["echo-message"])
    target = await make_client("echot1")
    await sender.send("PRIVMSG echot1 :hello there")
    echo = await sender.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert sender_nick(echo) == "echo1"
    assert echo.params == ["echot1", "hello there"], echo.raw
    delivered = await target.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert delivered.params[-1] == "hello there"


async def test_notice_to_user_is_echoed(make_client):
    sender = await make_client("echo2", caps=["echo-message"])
    target = await make_client("echot2")
    await sender.send("NOTICE echot2 :notice me")
    echo = await sender.wait_for_user_msg("NOTICE", timeout=5.0)
    assert sender_nick(echo) == "echo2"
    assert echo.params == ["echot2", "notice me"], echo.raw
    delivered = await target.wait_for_user_msg("NOTICE", timeout=5.0)
    assert delivered.params[-1] == "notice me"


async def test_channel_messages_are_echoed(make_client):
    chan = "#echo_chan"
    sender = await make_client("echo3", caps=["echo-message"])
    peer = await make_client("echop3")
    await join(sender, chan)
    await join(peer, chan)
    await asyncio.sleep(0.3)
    await drain(sender)
    await drain(peer)

    await sender.send(f"PRIVMSG {chan} :chan hello")
    echo = await sender.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert sender_nick(echo) == "echo3" and echo.params == [chan, "chan hello"]
    got = await peer.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert got.params[-1] == "chan hello"

    await sender.send(f"NOTICE {chan} :chan notice")
    echo = await sender.wait_for_user_msg("NOTICE", timeout=5.0)
    assert echo.params == [chan, "chan notice"]


async def test_no_echo_without_cap(make_client):
    chan = "#echo_nocap"
    sender = await make_client("echo4")
    target = await make_client("echot4")
    await join(sender, chan)
    await join(target, chan)
    await asyncio.sleep(0.3)
    await drain(sender)
    await drain(target)

    await sender.send("PRIVMSG echot4 :direct")
    await sender.send(f"PRIVMSG {chan} :channel")
    await sender.send("NOTICE echot4 :direct notice")
    await target.wait_for_user_msg("PRIVMSG", timeout=5.0)
    await sender.assert_no_message("PRIVMSG", timeout=1.5)
    await sender.assert_no_message("NOTICE", timeout=0.5)


async def test_directed_message_to_service_is_echoed(make_client, ulined_server):
    """nick@server targets on a service server are echoed too (relay_directed_*)."""
    await ulined_server.introduce_user("EchoSvc", modes="+ik")
    sender = await make_client("echo5", caps=["echo-message"])
    await sender.send("PRIVMSG EchoSvc@services.test.net :svc msg")
    echo = await sender.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert echo.params == ["EchoSvc@services.test.net", "svc msg"], echo.raw
    line = await ulined_server.wait_for_token("P", timeout=5.0)
    assert "EchoSvc@services.test.net :svc msg" in line

    await sender.send("NOTICE EchoSvc@services.test.net :svc notice")
    echo = await sender.wait_for_user_msg("NOTICE", timeout=5.0)
    assert echo.params == ["EchoSvc@services.test.net", "svc notice"], echo.raw
    line = await ulined_server.wait_for_token("O", timeout=5.0)
    assert "EchoSvc@services.test.net :svc notice" in line
