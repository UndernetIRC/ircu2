"""Regression: WebSocket outbound framing must carry full tagged lines.

websocket_frame_msgbuf() sanitized outbound lines into a buffer sized for an
untagged BUFSIZE line (WS_UTF8_OUT_MAX derived from BUFSIZE ~= 1542 bytes).
A tag-prefixed line can be OUTBOUND_TAG_MAX + BUFSIZE bytes, so WebSocket
clients with message-tags received silently truncated lines once the relayed
tag prefix pushed past ~1.5KB.

Uses the CLIENTTAGDENY-allowed `+example.com/foo` tag, duplicated to build a
large relayed prefix, with an end-of-body sentinel that vanishes if the frame
is truncated.
"""

import asyncio

import pytest

from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient

from .helpers import parse_tag_list

pytestmark = pytest.mark.single_server

WS_PORT = 7000
ALLOWED_TAG = "+example.com/foo"
CHANNEL = "#wsbigtags"
SENTINEL = "END-OF-BODY-SENTINEL"

# 10 copies of a 250-char value: ~2.7KB of tag data on the wire, well past
# the old 1542-byte WebSocket sanitize buffer but under TAGDATA_CLIENT_MAX.
NUM_TAGS = 10
VALUE = "z" * 250
TAGS = ";".join(f"{ALLOWED_TAG}={VALUE}" for _ in range(NUM_TAGS))


async def _cleanup(*clients):
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        await c.disconnect()


async def test_ws_client_receives_large_tagged_line_intact(ircd_hub):
    """A WebSocket observer receives the full tag prefix and full body."""
    hub = ircd_hub

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("wsbigsnd", "testuser", "WS Big Sender")

    observer = IRCWebSocketClient()
    await observer.connect(f"ws://{hub['host']}:{WS_PORT}/")
    await observer.negotiate_cap(["message-tags"])
    await observer.register("wsbigobs", "testuser", "WS Big Obs")

    try:
        await sender.send(f"JOIN {CHANNEL}")
        await observer.send(f"JOIN {CHANNEL}")
        await observer.wait_for("JOIN", timeout=5.0)
        await asyncio.sleep(0.3)

        await sender.send(f"@{TAGS} PRIVMSG {CHANNEL} :big tagged line {SENTINEL}")

        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        # Body intact through the end (truncation eats the tail first).
        assert msg.params[-1] == f"big tagged line {SENTINEL}", msg.raw[-200:]
        # The relayed client-only tag survived with a full-length value.
        tags = parse_tag_list(msg.tags)
        assert ALLOWED_TAG in tags, msg.tags[:200]
        assert tags[ALLOWED_TAG] == VALUE, f"len={len(tags[ALLOWED_TAG] or '')}"

        # Framing must not desync: a follow-up plain message arrives intact.
        await sender.send(f"PRIVMSG {CHANNEL} :follow-up plain")
        nxt = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert nxt.params[-1] == "follow-up plain", nxt.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_binary_client_receives_large_tagged_line_intact(ircd_hub):
    """Same delivery guarantee for binary-mode WebSocket clients."""
    hub = ircd_hub

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("wsbinsnd", "testuser", "WS Bin Sender")

    observer = IRCWebSocketClient(binary=True)
    await observer.connect(f"ws://{hub['host']}:{WS_PORT}/")
    await observer.negotiate_cap(["message-tags"])
    await observer.register("wsbinobs", "testuser", "WS Bin Obs")

    try:
        await sender.send(f"JOIN {CHANNEL}bin")
        await observer.send(f"JOIN {CHANNEL}bin")
        await observer.wait_for("JOIN", timeout=5.0)
        await asyncio.sleep(0.3)

        await sender.send(
            f"@{TAGS} PRIVMSG {CHANNEL}bin :binary big line {SENTINEL}"
        )

        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == f"binary big line {SENTINEL}", msg.raw[-200:]
        tags = parse_tag_list(msg.tags)
        assert tags.get(ALLOWED_TAG) == VALUE, msg.tags[:200]
    finally:
        await _cleanup(sender, observer)
