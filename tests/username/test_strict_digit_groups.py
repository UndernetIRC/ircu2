"""STRICT_USERNAME two-digit-group rule (commit cbe68ab).

With STRICT_USERNAME on, a username with exactly two groups of digits is
allowed when one of the groups is at the start or the end.  The check used
to look at a stale loop variable, so "ab12cd34" was wrongly rejected.
"""

from __future__ import annotations

import asyncio

import pytest

from common import set_feature
from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def _try_register(host, port, nick, username) -> tuple[bool, str]:
    client = IRCClient()
    await client.connect(host, port)
    try:
        await client.send(f"NICK {nick}")
        await client.send(f"USER {username} 0 * :User {nick}")
        deadline = asyncio.get_running_loop().time() + 8.0
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False, "timeout"
            try:
                msg = await client.recv(timeout=remaining)
            except (asyncio.TimeoutError, ConnectionError) as exc:
                return False, f"disconnect:{exc}"
            if msg.command in ("376", "422"):
                await client.send("QUIT :done")
                return True, "registered"
            if msg.command == "468" or "invalid" in msg.raw.lower():
                return False, msg.raw
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


STRICT_ACCEPT = [
    ("ab12cd34", "two digit groups, one at the end"),
    ("12ab34cd", "two digit groups, one at the start"),
    ("ab12cd", "single digit group"),
    ("user99", "trailing digits"),
]
STRICT_REJECT = [
    ("ab12cd34x", "two digit groups, neither at start nor end"),
    ("a1b2c3", "three digit groups"),
]


@pytest.fixture
async def strict(oper):
    await set_feature(oper, "STRICT_USERNAME", "TRUE")
    yield
    await set_feature(oper, "STRICT_USERNAME", "FALSE")


async def test_strict_accepts_edge_digit_groups(ircd_hub, strict):
    for i, (username, why) in enumerate(STRICT_ACCEPT):
        ok, detail = await _try_register(ircd_hub["host"], ircd_hub["port"], f"sdok{i}", username)
        assert ok, f"{username!r} ({why}) should be accepted: {detail}"


async def test_strict_rejects_middle_digit_groups(ircd_hub, strict):
    for i, (username, why) in enumerate(STRICT_REJECT):
        ok, detail = await _try_register(ircd_hub["host"], ircd_hub["port"], f"sdbad{i}", username)
        assert not ok, f"{username!r} ({why}) should be rejected"


async def test_default_accepts_everything_above(ircd_hub):
    for i, (username, _) in enumerate(STRICT_ACCEPT + STRICT_REJECT):
        ok, detail = await _try_register(ircd_hub["host"], ircd_hub["port"], f"sddef{i}", username)
        assert ok, f"{username!r} should be accepted with STRICT_USERNAME off: {detail}"
