"""STRICT_USERNAME edge cases around the rules touched by 85c37ef/cbe68ab."""

from __future__ import annotations

import asyncio

import pytest

from common import set_feature
from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def _try_register(host, port, nick, username) -> bool:
    client = IRCClient()
    await client.connect(host, port)
    try:
        await client.send(f"NICK {nick}")
        await client.send(f"USER {username} 0 * :User {nick}")
        deadline = asyncio.get_running_loop().time() + 8.0
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False
            try:
                msg = await client.recv(timeout=remaining)
            except (asyncio.TimeoutError, ConnectionError):
                return False
            if msg.command in ("376", "422"):
                await client.send("QUIT :done")
                return True
            if msg.command == "468":
                return False
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


@pytest.fixture
async def strict(oper):
    await set_feature(oper, "STRICT_USERNAME", "TRUE")
    yield
    await set_feature(oper, "STRICT_USERNAME", "FALSE")


@pytest.mark.parametrize("username,ok", [
    ("ABCdef", True),     # up to three leading capitals
    ("Abcdef", True),
    ("ABCDef", False),    # four leading capitals
    ("aBcdef", False),    # capital not leading
    ("ABcDef", False),    # three capitals but not all leading
    ("ABCDEF", True),     # all caps is not "mixed case"
    ("abc_", False),      # trailing punctuation
    ("a.b.c", True),      # two punctuation characters, non-consecutive
    ("12abc", True),      # leading digit group only
    ("abc12", True),
])
async def test_strict_rules(ircd_hub, strict, username, ok):
    nick = "ste" + username.lower().replace(".", "").replace("_", "")[:6]
    got = await _try_register(ircd_hub["host"], ircd_hub["port"], nick, username)
    assert got == ok, f"{username!r}: expected {'accept' if ok else 'reject'}"


@pytest.mark.parametrize("username", ["a__b", "a-_b", "a.b.c.d", "-abc", "1234"])
async def test_always_rejected_even_when_lenient(ircd_hub, username):
    assert not await _try_register(ircd_hub["host"], ircd_hub["port"], "stalw", username)
