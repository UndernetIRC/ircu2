"""STRICT_USERNAME default FALSE (commit 85c37ef).

Always-enforced rules (letter required; limited ``-_.`` punctuation) vs
extra STRICT_USERNAME rules. Default is FALSE.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import make_cap_client, oper_up
from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def _try_register(host, port, nick, username) -> tuple[bool, str]:
    """Attempt registration; return (accepted, detail)."""
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
                return True, "registered"
            if (
                "invalid" in msg.raw.lower()
                or msg.command in ("468", "465", "464")
            ):
                return False, msg.raw
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


# Usernames that must be accepted with STRICT_USERNAME=FALSE (default).
_ACCEPT_DEFAULT = [
    ("user.", "trailing punctuation"),
    ("a1b2c3", "three digit groups"),
    ("AbCdEf", "mixed case"),
    ("user_name", "single underscore"),
    ("abc123", "trailing digits"),
]

# Usernames that must always be rejected (even with STRICT off).
_REJECT_ALWAYS = [
    ("12345", "no letter"),
    (".user", "leading punctuation"),
    ("user!!", "invalid punctuation"),
    ("a__b", "consecutive punctuation"),
    ("a_b_c_d", "more than two -_. chars"),
]

# Usernames accepted with STRICT off but rejected with STRICT on.
_REJECT_WHEN_STRICT = [
    ("user.", "trailing punctuation"),
    ("a1b2c3", "three digit groups"),
]


async def test_default_accepts_permitted_usernames(ircd_hub):
    """Default STRICT_USERNAME=FALSE accepts the loose-allowed set."""
    for i, (username, reason) in enumerate(_ACCEPT_DEFAULT):
        ok, detail = await _try_register(
            ircd_hub["host"], ircd_hub["port"], f"ok{i}", username
        )
        assert ok, f"expected accept {username!r} ({reason}), got {detail}"


async def test_default_rejects_always_illegal_usernames(ircd_hub):
    """Always-enforced rules still reject bad usernames when STRICT is off."""
    for i, (username, reason) in enumerate(_REJECT_ALWAYS):
        ok, detail = await _try_register(
            ircd_hub["host"], ircd_hub["port"], f"bad{i}", username
        )
        assert not ok, f"expected reject {username!r} ({reason}), but registered"


async def test_strict_rejects_extra_usernames(ircd_hub):
    """STRICT_USERNAME TRUE rejects usernames that the default allows."""
    oper = await make_cap_client(ircd_hub["host"], ircd_hub["port"], "strictop")
    await oper_up(oper)
    try:
        await oper.send("SET STRICT_USERNAME TRUE")
        await asyncio.sleep(0.3)

        for i, (username, reason) in enumerate(_REJECT_WHEN_STRICT):
            ok, detail = await _try_register(
                ircd_hub["host"], ircd_hub["port"], f"st{i}", username
            )
            assert not ok, (
                f"STRICT should reject {username!r} ({reason}), got {detail}"
            )

        ok, detail = await _try_register(
            ircd_hub["host"], ircd_hub["port"], "stok", "cleanuser"
        )
        assert ok, f"STRICT should still accept cleanuser, got {detail}"
    finally:
        await oper.send("SET STRICT_USERNAME FALSE")
        await asyncio.sleep(0.2)
        await oper.disconnect()
