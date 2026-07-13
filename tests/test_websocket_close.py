"""Regression test: server responds to a WebSocket Close frame.

Review finding #5 (LOW): a client Close frame (opcode 0x8) was consumed but the
server neither replied with a Close nor tore the connection down, so the socket
lingered. The fix echoes a Close frame and closes the connection.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from ws_frame_helpers import (
    masked_ws_frame,
    raw_ws_connect,
    read_server_frame,
    register_over_raw_ws,
)

pytestmark = pytest.mark.websocket_stress


@pytest.mark.asyncio
async def test_ws_close_frame_gets_close_and_disconnect(ircd_hub):
    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "closer", timeout=15.0)

    # Client Close (masked, status 1000).
    w.write(masked_ws_frame(0x8, b"\x03\xe8"))
    await w.drain()

    got_close = False
    eof = False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 6.0
    while loop.time() < deadline:
        try:
            opcode, _ = await read_server_frame(r, timeout=deadline - loop.time())
        except asyncio.IncompleteReadError:
            eof = True
            break
        except (asyncio.TimeoutError, ConnectionError):
            break
        if opcode == 0x8:
            got_close = True
            # After Close the server drops the socket; it may first flush a
            # trailing ERROR frame, so drain until an actual EOF.
            end = loop.time() + 3.0
            while loop.time() < end:
                try:
                    tail = await asyncio.wait_for(r.read(4096), timeout=end - loop.time())
                except asyncio.TimeoutError:
                    break
                if tail == b"":
                    eof = True
                    break
            break

    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert got_close, "server did not send a Close frame in response"
    assert eof, "server did not close the connection after Close"
