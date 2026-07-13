"""Regression test: oversized WebSocket frames are drained, not fatal.

Refinement of review finding #2: a single frame larger than the frame-assembly
buffer must not drop the connection. The server delivers the first line's worth
of octets and drains the rest (even across TCP reads), staying synchronized so
the following frame is still parsed.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from ws_frame_helpers import (
    HOST,
    masked_ws_frame,
    masked_text_frame,
    raw_ws_connect,
    register_over_raw_ws,
)

pytestmark = pytest.mark.websocket_stress

NORMAL_PORT = 6667


@pytest.mark.asyncio
async def test_ws_oversize_frame_drained_and_parser_resyncs(ircd_hub):
    recv = IRCClient()
    await recv.connect(HOST, NORMAL_PORT)
    await recv.register("ovrecv", "rx", "oversize receiver")

    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "ovsend", timeout=15.0)

    # A single ~20 KiB frame of junk (no valid command); far bigger than the
    # frame buffer. Split across two writes so the drain must span reads.
    big = masked_ws_frame(0x1, b"X" * 20000 + b"\r\n")
    w.write(big[:5000])
    await w.drain()
    await asyncio.sleep(0.15)
    w.write(big[5000:])
    await w.drain()

    # A normal command after the oversized frame must still be parsed.
    w.write(masked_text_frame(b"PRIVMSG ovrecv :after-oversize\r\n"))
    await w.drain()

    got = await recv.wait_for("PRIVMSG", timeout=10.0)
    await recv.disconnect()
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert got.params[-1] == "after-oversize", (
        f"parser did not resync after oversized frame: {got.params[-1]!r}"
    )
