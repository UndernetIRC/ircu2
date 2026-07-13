"""Regression test for the opt-in WebSocket Origin allowlist.

Review finding #9 (LOW): the server did not enforce the Origin header, so any
web origin could open a socket. The fix adds an opt-in allowlist feature
(FEAT_WEBSOCKET_ALLOWED_ORIGINS); default (unset) allows all origins.

This test drives the feature at runtime via an oper SET/RESET, so it must
restore the default in a finally to avoid affecting other tests on the shared
hub.

Requires the Docker hub (``ircd_hub``). Marked ``websocket_stress``.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from ws_frame_helpers import HOST, WS_PORT

pytestmark = pytest.mark.websocket_stress

NORMAL_PORT = 6667


async def _handshake(origin: bytes | None) -> bytes:
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
    )
    if origin is not None:
        req += b"Origin: " + origin + b"\r\n"
    req += b"\r\n"
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
async def test_default_allows_any_origin(ircd_hub):
    """With no allowlist configured, any Origin is accepted (unchanged default)."""
    resp = await _handshake(b"https://anywhere.example")
    assert b"101" in resp, f"default should allow any origin, got {resp[:200]!r}"


@pytest.mark.asyncio
async def test_origin_allowlist_enforced(ircd_hub):
    oper = IRCClient()
    await oper.connect(HOST, NORMAL_PORT)
    await oper.register("originop", "op", "origin oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)

    try:
        await oper.send("SET WEBSOCKET_ALLOWED_ORIGINS https://good.example")
        await asyncio.sleep(0.5)

        allowed = await _handshake(b"https://good.example")
        assert b"101" in allowed, f"allowed origin was rejected: {allowed[:200]!r}"

        blocked = await _handshake(b"https://evil.example")
        assert b"101" not in blocked, f"disallowed origin was accepted: {blocked[:200]!r}"

        missing = await _handshake(None)
        assert b"101" not in missing, "missing Origin accepted despite allowlist"
    finally:
        await oper.send("RESET WEBSOCKET_ALLOWED_ORIGINS")
        await asyncio.sleep(0.5)
        # Confirm default (allow-all) is restored so other tests are unaffected.
        restored = await _handshake(None)
        await oper.disconnect()
        assert b"101" in restored, "allowlist not reset; shared hub left restricted"
