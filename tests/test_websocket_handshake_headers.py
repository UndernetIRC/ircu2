"""Regression tests for robust WebSocket handshake header matching.

Review finding #7 (LOW): the handshake required exact header spellings
("Connection: Upgrade") and did not validate Sec-WebSocket-Version. The fix
matches Upgrade/Connection by token (so comma lists like
"Connection: keep-alive, Upgrade" work) and rejects unsupported versions.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from ws_frame_helpers import HOST, WS_PORT

pytestmark = pytest.mark.websocket_stress


async def _do_handshake(extra_headers: bytes) -> bytes:
    """Send a handshake with the given header block; return the HTTP response (or b'')."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n" + extra_headers + b"\r\n"
    )
    w.write(req)
    await w.drain()
    try:
        resp = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=4.0)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        resp = b""
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    return resp


@pytest.mark.asyncio
async def test_connection_header_token_list_is_accepted(ircd_hub):
    """'Connection: keep-alive, Upgrade' (comma list) must complete the handshake."""
    resp = await _do_handshake(
        b"Upgrade: websocket\r\n"
        b"Connection: keep-alive, Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
    )
    assert b"101" in resp, f"token-list Connection header not accepted: {resp[:200]!r}"


@pytest.mark.asyncio
async def test_unsupported_websocket_version_is_rejected(ircd_hub):
    """A non-13 Sec-WebSocket-Version must not yield a 101 upgrade."""
    resp = await _do_handshake(
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 8\r\n"
    )
    assert b"101" not in resp, f"unsupported version 8 was upgraded: {resp[:200]!r}"
