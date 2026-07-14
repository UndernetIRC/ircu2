"""Regression test for fragmented WebSocket message reassembly.

Review finding #4 (MED): a message split across frames (a FIN=0 data frame
followed by continuation frames, opcode 0x0) was not reassembled — the
continuation frames were dropped and only the first fragment was delivered.
The fix accumulates fragments and delivers the message only on FIN.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import pytest

from irc_client import IRCClient
from ws_frame_helpers import (
    HOST,
    masked_ws_frame,
    raw_ws_connect,
    register_over_raw_ws,
)

pytestmark = pytest.mark.websocket_stress

NORMAL_PORT = 6667


@pytest.mark.asyncio
async def test_ws_fragmented_message_is_reassembled(ircd_hub):
    """A PRIVMSG split across a data frame + continuation frame is delivered whole."""
    recv = IRCClient()
    await recv.connect(HOST, NORMAL_PORT)
    await recv.register("fragrecv", "rx", "frag receiver")

    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "fragsend", timeout=15.0)

    full = b"PRIVMSG fragrecv :hello fragmented world\r\n"
    split = 10
    # Frame 1: text, FIN=0 (more fragments coming).
    w.write(masked_ws_frame(0x1, full[:split], fin=False))
    # Frame 2: continuation (opcode 0x0), FIN=1 (final).
    w.write(masked_ws_frame(0x0, full[split:], fin=True))
    await w.drain()

    got = await recv.wait_for("PRIVMSG", timeout=10.0)
    await recv.disconnect()
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert got.params[-1] == "hello fragmented world", (
        f"fragmented message not reassembled: {got.params[-1]!r}"
    )


@pytest.mark.asyncio
async def test_ws_three_way_fragmentation_is_reassembled(ircd_hub):
    """A message split into three frames (text + 2 continuations) is delivered whole."""
    recv = IRCClient()
    await recv.connect(HOST, NORMAL_PORT)
    await recv.register("frag3recv", "rx", "frag3 receiver")

    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "frag3send", timeout=15.0)

    full = b"PRIVMSG frag3recv :one two three parts\r\n"
    a, b = 8, 20
    w.write(masked_ws_frame(0x1, full[:a], fin=False))
    w.write(masked_ws_frame(0x0, full[a:b], fin=False))
    w.write(masked_ws_frame(0x0, full[b:], fin=True))
    await w.drain()

    got = await recv.wait_for("PRIVMSG", timeout=10.0)
    await recv.disconnect()
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert got.params[-1] == "one two three parts", (
        f"three-way fragmented message not reassembled: {got.params[-1]!r}"
    )
