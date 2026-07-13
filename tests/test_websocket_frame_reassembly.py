"""Regression test for WebSocket frame reassembly across TCP reads.

Review finding #2 (HIGH): a WS frame split across two TCP reads had its
unconsumed tail silently discarded, desyncing the parser. This test splits a
registration-critical frame across two writes and asserts the client still
registers (proving the tail was reassembled, not dropped).

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from ws_frame_helpers import (
    HOST,
    WS_PORT,
    RAW_HANDSHAKE,
    masked_text_frame,
    read_http_101,
    wait_for_numeric,
)

pytestmark = pytest.mark.websocket_stress


@pytest.mark.asyncio
async def test_ws_frame_split_across_two_reads_still_registers(ircd_hub):
    """USER frame delivered in two TCP writes must be reassembled, not dropped."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(RAW_HANDSHAKE)
    await w.drain()
    await read_http_101(r)

    # NICK arrives whole.
    w.write(masked_text_frame(b"NICK splitreg\r\n"))
    await w.drain()

    # USER frame is cut mid-way; second read must complete the frame.
    user_frame = masked_text_frame(b"USER splitreg 0 * :split frame\r\n")
    cut = 4
    w.write(user_frame[:cut])
    await w.drain()
    await asyncio.sleep(0.2)
    w.write(user_frame[cut:])
    await w.drain()

    registered = await wait_for_numeric(r, w, "001", timeout=15.0)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert registered, "registration did not complete: split USER frame was dropped"


@pytest.mark.asyncio
async def test_ws_frame_header_split_from_payload_still_registers(ircd_hub):
    """Even a 1-byte first write (partial header) must not desync the parser."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(RAW_HANDSHAKE)
    await w.drain()
    await read_http_101(r)

    w.write(masked_text_frame(b"NICK hdrsplit\r\n"))
    await w.drain()

    user_frame = masked_text_frame(b"USER hdrsplit 0 * :header split\r\n")
    # One byte at a time for the first few bytes (header), then the rest.
    for i in range(3):
        w.write(user_frame[i : i + 1])
        await w.drain()
        await asyncio.sleep(0.05)
    w.write(user_frame[3:])
    await w.drain()

    registered = await wait_for_numeric(r, w, "001", timeout=15.0)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert registered, "registration did not complete: partial-header frame was dropped"
