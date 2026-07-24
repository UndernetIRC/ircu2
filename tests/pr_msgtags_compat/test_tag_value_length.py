"""Regression: relayed client-only tag values must not be truncated.

msg_tag_append() used to escape each tag value into a fixed 256-byte scratch
buffer, silently truncating any relayed value longer than 255 escaped bytes.
IRCv3 allows values up to the tag-data limit (TAGDATA_CLIENT_MAX, 4094 minus
key/separator overhead), so long values must round-trip intact.

The docker configs allow exactly one client-only tag through CLIENTTAGDENY:
`+example.com/foo`.
"""

import asyncio

import pytest

from irc_client import IRCClient

from .helpers import escape_tag_value, tag_value

pytestmark = pytest.mark.single_server

ALLOWED_TAG = "+example.com/foo"
CHANNEL = "#tagvallen"


async def _pair(hub, nick_prefix: str):
    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register(f"{nick_prefix}snd", "testuser", "Value Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags"])
    await observer.register(f"{nick_prefix}obs", "testuser", "Value Obs")

    await sender.send(f"JOIN {CHANNEL}")
    await observer.send(f"JOIN {CHANNEL}")
    await asyncio.sleep(0.3)
    return sender, observer


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        await c.disconnect()


async def test_long_plain_tag_value_relayed_intact(ircd_hub):
    """A 600-char tag value (no escapes) survives relay without truncation."""
    value = "x" * 600
    sender, observer = await _pair(ircd_hub, "tvplain")
    try:
        await sender.send(f"@{ALLOWED_TAG}={value} PRIVMSG {CHANNEL} :long value")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        got = tag_value(msg.tags, ALLOWED_TAG, unescape=True)
        assert got == value, f"len={len(got) if got else None} raw-tags={msg.tags[:400]}"
        assert msg.params[-1] == "long value"
    finally:
        await _cleanup(sender, observer)


async def test_long_escaped_tag_value_relayed_intact(ircd_hub):
    """A long value full of escape-needing chars round-trips past the old
    255-byte scratch-buffer boundary."""
    # 70 * 6 = 420 chars raw; spaces and semicolons escape to 2 bytes each,
    # so the escaped wire form is ~560 bytes -- well past the old cutoff.
    value = "ab cd;" * 70
    wire = escape_tag_value(value)
    sender, observer = await _pair(ircd_hub, "tvesc")
    try:
        await sender.send(f"@{ALLOWED_TAG}={wire} PRIVMSG {CHANNEL} :escaped value")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        got = tag_value(msg.tags, ALLOWED_TAG, unescape=True)
        assert got == value, f"len={len(got) if got else None} raw-tags={msg.tags[:400]}"
    finally:
        await _cleanup(sender, observer)


async def test_max_size_tag_value_relayed_intact(ircd_hub):
    """A single tag close to the full client tag-data budget round-trips.

    Tag section: '+example.com/foo=' (17) + 4000 = 4017 bytes, under the
    TAGDATA_CLIENT_MAX (4094) inbound cap; the outbound prefix (plus
    server-time) must still fit OUTBOUND_TAG_MAX without truncation.
    """
    value = "y" * 4000
    sender, observer = await _pair(ircd_hub, "tvmax")
    try:
        await sender.send(f"@{ALLOWED_TAG}={value} PRIVMSG {CHANNEL} :max value")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        got = tag_value(msg.tags, ALLOWED_TAG, unescape=True)
        assert got == value, f"len={len(got) if got else None}"
        assert msg.params[-1] == "max value"
    finally:
        await _cleanup(sender, observer)
