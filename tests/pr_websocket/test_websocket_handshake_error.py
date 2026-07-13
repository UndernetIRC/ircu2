"""Regression test: failed WebSocket handshake yields an HTTP error response.

Review finding #8 (LOW): a rejected handshake just dropped the socket with no
HTTP response. The fix sends a minimal HTTP 400 before closing.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from ws_frame_helpers import HOST, WS_PORT

pytestmark = pytest.mark.websocket_stress


@pytest.mark.asyncio
async def test_failed_handshake_returns_http_400(ircd_hub):
    """A completed HTTP request that is not a WS upgrade must get an HTTP 400."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    # Valid HTTP request terminator, but no Upgrade/Key headers -> not a WS upgrade.
    w.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n")
    await w.drain()

    try:
        resp = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5.0)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        resp = getattr(e, "partial", b"") if isinstance(e, asyncio.IncompleteReadError) else b""

    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass

    assert resp.startswith(b"HTTP/1.1 400"), (
        f"expected an HTTP 400 on failed handshake, got: {resp[:200]!r}"
    )
