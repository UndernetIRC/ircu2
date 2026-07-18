"""Regression test for the per-message MsgBuf leak on WebSocket output.

Review finding #1 (HIGH): send_buffer() framed every outbound line for a WS
client into a fresh MsgBuf but never released it, so one pooled buffer leaked
per message sent, eventually exhausting the buffer pool.

Strategy: an oper reads ``STATS z`` (message-buffer accounting) before and
after driving a large volume of outbound frames to a WS client, then after the
client disconnects. With the leak, the "used" MsgBuf count stays elevated after
disconnect; when fixed, it returns to near baseline.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from irc_client import IRCClient
from ws_frame_helpers import (
    HOST,
    WS_EXEMPT_PORT,
    masked_text_frame,
    raw_ws_connect,
    read_server_frame,
    register_over_raw_ws,
)

pytestmark = pytest.mark.websocket_stress

NORMAL_PORT = 6667
_USED_RE = re.compile(r"MsgBufs of size \d+ allocated \d+\([\d]+\) used (\d+)")


async def _msgbuf_used(oper: IRCClient) -> int:
    """Sum the 'used' MsgBuf counts across all size classes from STATS z."""
    await oper.send("STATS z")
    total = 0
    while True:
        msg = await oper.wait_for_any(("249", "219"), timeout=10.0)
        if msg.command == "219":
            break
        m = _USED_RE.search(msg.params[-1]) if msg.params else None
        if m:
            total += int(m.group(1))
    return total


async def _wait_for_any(self, commands, timeout=5.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"Timed out waiting for {commands}")
        msg = await self._recv_from_stream(timeout=remaining)
        if msg.command in commands:
            return msg


# Attach a small helper to IRCClient for this test module.
IRCClient.wait_for_any = _wait_for_any


@pytest.mark.asyncio
async def test_ws_outbound_does_not_leak_msgbufs(ircd_hub):
    oper = IRCClient()
    await oper.connect(HOST, NORMAL_PORT)
    await oper.register("leakoper", "op", "leak oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)  # RPL_YOUREOPER

    baseline = await _msgbuf_used(oper)

    # Connect a WS client and make the server emit a large volume of frames.
    # Use the exempt port so the rapid PING burst is not flood-throttled.
    r, w = await raw_ws_connect(WS_EXEMPT_PORT)
    assert await register_over_raw_ws(r, w, "leakws", timeout=15.0)

    n = 400
    for i in range(n):
        w.write(masked_text_frame(f"PING :probe{i}\r\n".encode()))
    await w.drain()

    pongs = 0
    try:
        while pongs < n:
            opcode, payload = await read_server_frame(r, timeout=10.0)
            if opcode in (0x1, 0x2) and b"PONG" in payload:
                pongs += payload.count(b"PONG")
            elif opcode == 0x9:  # RFC6455 ping -> pong
                w.write(masked_text_frame(payload))
                await w.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    assert pongs >= n // 2, f"server did not return enough PONGs ({pongs})"

    # Disconnect the WS client and let the server reclaim its queues.
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await asyncio.sleep(2.0)

    after = await _msgbuf_used(oper)
    await oper.disconnect()

    growth = after - baseline
    # Each leaked frame keeps one MsgBuf "used"; ~400 PONGs + registration burst
    # would show as hundreds of retained buffers. Allow generous slack for noise.
    assert growth < 100, (
        f"MsgBuf 'used' grew by {growth} (baseline={baseline}, after={after}); "
        "outbound WS frames are leaking buffers"
    )
