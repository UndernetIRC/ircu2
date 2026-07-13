"""Regression test: unmasked client WebSocket frames are rejected (RFC 6455 5.1).

Review finding #6 (LOW): the server processed client frames that were not
masked. RFC 6455 requires every client-to-server frame to be masked; an
unmasked frame must fail the connection. Previously the unmasked payload was
read verbatim as IRC input.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from ws_frame_helpers import (
    HOST,
    raw_ws_connect,
    register_over_raw_ws,
)

pytestmark = pytest.mark.websocket_stress

NORMAL_PORT = 6667


def _unmasked_text_frame(payload: bytes) -> bytes:
    """A client text frame with the mask bit cleared (RFC violation)."""
    assert len(payload) <= 125
    return bytes([0x81, len(payload)]) + payload


@pytest.mark.asyncio
async def test_ws_unmasked_frame_is_not_processed(ircd_hub):
    """An unmasked frame must not be delivered as IRC input."""
    recv = IRCClient()
    await recv.connect(HOST, NORMAL_PORT)
    await recv.register("maskrecv", "rx", "mask receiver")

    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "masksend", timeout=15.0)

    # Unmasked PRIVMSG: must be rejected, so the receiver never sees it.
    w.write(_unmasked_text_frame(b"PRIVMSG maskrecv :leaked via unmasked\r\n"))
    await w.drain()

    with pytest.raises(asyncio.TimeoutError):
        await recv.wait_for("PRIVMSG", timeout=4.0)

    await recv.disconnect()
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_ws_unmasked_frame_closes_connection(ircd_hub):
    """The server should fail (close) the connection on an unmasked frame."""
    r, w = await raw_ws_connect()
    assert await register_over_raw_ws(r, w, "maskclose", timeout=15.0)

    w.write(_unmasked_text_frame(b"PING :nope\r\n"))
    await w.drain()

    # Expect EOF (connection closed) rather than continued service. A read
    # timeout means the connection is still open (i.e. not closed) -> failure.
    closed = False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 6.0
    while loop.time() < deadline:
        try:
            chunk = await asyncio.wait_for(r.read(4096), timeout=deadline - loop.time())
        except asyncio.TimeoutError:
            break  # still open, no EOF
        except (asyncio.IncompleteReadError, ConnectionError):
            closed = True
            break
        if chunk == b"":
            closed = True
            break

    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    assert closed, "server did not close the connection after an unmasked frame"
