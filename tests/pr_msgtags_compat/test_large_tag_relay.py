"""Regression: large relayed client-only tags must not overflow the MsgBuf pool.

Before the pool-ceiling fix, a message whose relayed tag prefix + body exceeded
the MsgBuf pool maximum (2048 bytes, MB_MAX_SHIFT=11) drove
make_wire_msgbuf() -> msgq_raw_alloc() past the largest pool bucket. In the
docker build (./configure --enable-debug, asserts on, optionally ASan) that is
an assertion abort / out-of-bounds msgBufs[] index -> the server crashes.

The test config sets CLIENTTAGDENY = "*,-example.com/foo", so the
client-only tag `+example.com/foo` is the one tag a client may have relayed.
Sending many copies of it builds a relayed prefix well past 2048 bytes, which
is exactly the path that used to crash.
"""

import asyncio

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.single_server

# The single client-only tag the docker configs allow to be relayed.
ALLOWED_TAG = "example.com/foo"


def _big_tag_string(num_tags: int, value_len: int) -> str:
    """Build `@+k=v;+k=v;...` with `num_tags` copies of the allowed tag.

    value_len is kept under the server's per-value escape buffer (256) so the
    relayed values are not truncated, letting us assert an exact round-trip
    while still pushing the total prefix well over the 2048-byte pool limit.
    """
    value = "x" * value_len
    return ";".join(f"+{ALLOWED_TAG}={value}" for _ in range(num_tags))


async def _assert_alive(client: IRCClient) -> None:
    """A crashed server drops the socket; a live one answers PING."""
    token = "liveness-probe"
    await client.send(f"PING :{token}")
    pong = await client.wait_for("PONG", timeout=5.0)
    assert token in pong.raw, pong.raw


async def test_large_client_tag_relay_does_not_crash(ircd_hub):
    """A channel PRIVMSG with a >2KB relayed tag prefix is delivered intact.

    Pre-fix this crashes the server (assert/OOB in the msgq pool); the observer
    then never receives the message and the liveness probe fails.
    """
    hub = ircd_hub
    channel = "#bigtag"

    # ~14 * (len("+example.com/foo=") + 200 + 1) ~= 3050 bytes of tag data,
    # comfortably over the old 2048 pool ceiling and under TAGDATA_CLIENT_MAX.
    tags = _big_tag_string(num_tags=14, value_len=200)

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("bigtagsnd", "testuser", "Big Tag Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags", "server-time"])
    await observer.register("bigtagobs", "testuser", "Big Tag Obs")

    try:
        await sender.send(f"JOIN {channel}")
        await observer.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)

        await sender.send(f"@{tags} PRIVMSG {channel} :payload body")

        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "payload body", msg.raw
        # The allowed client-only tag survived relay (server stayed up).
        assert f"+{ALLOWED_TAG}=" in msg.tags, msg.tags
        # Server-time is prepended for message-tags clients.
        assert "time=" in msg.tags, msg.tags

        # Server must still be responsive to both parties.
        await _assert_alive(observer)
        await _assert_alive(sender)
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_large_client_tag_relay_private_message(ircd_hub):
    """Same overflow path via a direct (private) PRIVMSG rather than a channel."""
    hub = ircd_hub

    tags = _big_tag_string(num_tags=14, value_len=200)

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("bigtagpsnd", "testuser", "Big Tag PM Sender")

    target = IRCClient()
    await target.connect(hub["host"], hub["port"])
    await target.negotiate_cap(["message-tags", "server-time"])
    await target.register("bigtagptgt", "testuser", "Big Tag PM Target")

    try:
        # Shared channel so commonchans_drop() does not block the PM.
        await sender.send("JOIN #bigtagpm")
        await target.send("JOIN #bigtagpm")
        await asyncio.sleep(0.3)

        await sender.send(f"@{tags} PRIVMSG bigtagptgt :direct payload")

        msg = await target.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "direct payload", msg.raw
        assert f"+{ALLOWED_TAG}=" in msg.tags, msg.tags

        await _assert_alive(target)
        await _assert_alive(sender)
    finally:
        for c in (sender, target):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
