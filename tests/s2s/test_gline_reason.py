"""G-line updates from servers (commits 37a02bc, 8375a80).

A six-parameter GLINE for an existing G-line carries either a new lifetime
(all digits) or a new reason.  37a02bc fixed the trial conversion so a
textual reason is applied; 8375a80 makes gline_modify() ignore a reason
update without a reason.
"""

from __future__ import annotations

import asyncio
import time

import pytest

pytestmark = pytest.mark.single_server

MASK = "*@192.0.2.*"


async def _glist(oper, mask):
    await oper.send(f"GLINE {mask}")
    msgs = await oper.collect_until("281", timeout=5.0)
    return [m for m in msgs if m.command == "280"]


async def _reason(oper, mask):
    entries = await _glist(oper, mask)
    assert len(entries) == 1, [m.raw for m in entries]
    return entries[0].params[-1]


async def _lifetime(oper, mask):
    entries = await _glist(oper, mask)
    assert len(entries) == 1
    return int(entries[0].params[4])


async def test_server_gline_reason_update(oper, ulined_server):
    num = ulined_server.server_numnick
    lastmod = int(time.time())
    await ulined_server._send(f"{num} GL * +{MASK} 3600 {lastmod} :reason one")
    await asyncio.sleep(0.3)
    try:
        assert await _reason(oper, MASK) == "reason one"

        # Six parameters, non-numeric fifth => reason update.
        await ulined_server._send(f"{num} GL * +{MASK} 3600 {lastmod + 1} :reason two")
        await asyncio.sleep(0.3)
        assert await _reason(oper, MASK) == "reason two"

        # Six parameters, all-digit fifth => lifetime (absolute) update,
        # reason untouched.
        new_lifetime = lastmod + 7200
        await ulined_server._send(f"{num} GL * +{MASK} 3600 {lastmod + 2} {new_lifetime}")
        await asyncio.sleep(0.3)
        assert await _reason(oper, MASK) == "reason two"
        assert await _lifetime(oper, MASK) == new_lifetime

        # Numeric-looking reason must still be treated as a reason.
        await ulined_server._send(f"{num} GL * +{MASK} 3600 {lastmod + 3} :12345 not a lifetime")
        await asyncio.sleep(0.3)
        assert await _reason(oper, MASK) == "12345 not a lifetime"
    finally:
        await ulined_server._send(f"{num} GL * -{MASK} {lastmod + 10}")
        await asyncio.sleep(0.3)


async def test_stale_update_is_ignored(oper, ulined_server):
    """An update with an older lastmod does not change the reason."""
    num = ulined_server.server_numnick
    mask = "*@192.0.3.*"
    lastmod = int(time.time())
    await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod} :current")
    await asyncio.sleep(0.3)
    try:
        await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod - 100} :stale")
        await asyncio.sleep(0.3)
        assert await _reason(oper, mask) == "current"
    finally:
        await ulined_server._send(f"{num} GL * -{mask} {lastmod + 10}")
        await asyncio.sleep(0.3)
