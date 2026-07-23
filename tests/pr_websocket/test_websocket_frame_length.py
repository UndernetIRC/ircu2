"""Tests for WebSocket extended (16-bit) frame length decoding.

Review finding #3 (MED): frame length bytes were shifted as signed char, so a
length byte >= 0x80 sign-extended and corrupted the decoded length. The fix
casts each byte to unsigned char before shifting.

Note: the specific sign-extension path requires a 16-bit length >= 0x8000
(>= 32768), which exceeds the post-handshake frame-reassembly buffer
(READBUFSIZE + header), so that path is not reachable behaviorally. This test
therefore guards the 126-form (16-bit) extended-length decode within the
supported range and verifies the parser stays in sync afterwards.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from ws_frame_helpers import (
    HOST,
    masked_text_frame,
    raw_ws_connect,
    register_over_raw_ws,
    wait_for_numeric,
)

pytestmark = pytest.mark.websocket_stress

NORMAL_PORT = 6667


@pytest.mark.asyncio
async def test_ws_126_extended_length_frame_is_processed(ircd_hub):
    """A 126-form (16-bit length) text frame must decode fully and be processed."""
    recv = IRCClient()
    await recv.connect(HOST, NORMAL_PORT)
    await recv.register("lenrecv", "rx", "length receiver")

    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "lentest", timeout=15.0)

    # 200-char message forces the 126 (16-bit) length encoding on the frame.
    text = "L" * 200
    payload = f"PRIVMSG lenrecv :{text}\r\n".encode()
    assert len(payload) >= 126  # ensures 126-form
    w.write(masked_text_frame(payload))
    await w.drain()

    # The receiver must get the full 200-char text: proves the extended length
    # was decoded correctly and the whole payload consumed.
    got = await recv.wait_for("PRIVMSG", timeout=10.0)
    assert got.params[-1] == text, f"payload corrupted/truncated: {got.params[-1]!r}"

    # Parser must still be in sync: a following short frame gets a reply.
    w.write(masked_text_frame(b"PING :after126\r\n"))
    await w.drain()
    in_sync = await wait_for_numeric(r, w, "PONG", timeout=10.0)

    await recv.disconnect()
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert in_sync, "parser desynced after a 126-form extended-length frame"
