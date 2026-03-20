"""TDD tests for PR #61: userhost-in-names (UHNAMES) capability.

Feature: When a client negotiates the userhost-in-names CAP, the NAMES
reply (353) should include nick!user@host format instead of just nick.

These tests require PR #61 to be applied. They will fail on the base
branch where the userhost-in-names capability does not exist.
"""

import pytest

from tests.irc_client import IRCClient


pytestmark = pytest.mark.single_server


async def test_uhnames_cap_negotiation(ircd_hub):
    """The server should advertise and acknowledge userhost-in-names."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        acked = await client.negotiate_cap(["userhost-in-names"])
        assert "userhost-in-names" in acked, (
            f"userhost-in-names not acknowledged, got: {acked}"
        )
        await client.register("uhtest1", "testuser", "Test User")
    finally:
        await client.disconnect()


async def test_uhnames_names_reply_format(ircd_hub):
    """With UHNAMES, NAMES reply should include nick!user@host entries."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        acked = await client.negotiate_cap(["userhost-in-names"])
        assert "userhost-in-names" in acked

        await client.register("uhtest2", "myuser", "Test User")

        await client.send("JOIN #test_uh_fix1")
        # Collect messages until end of NAMES
        msgs = await client.collect_until("366", timeout=5.0)

        # Find the 353 (RPL_NAMREPLY) message
        names_msgs = [m for m in msgs if m.command == "353"]
        assert len(names_msgs) > 0, "No RPL_NAMREPLY received"

        # Parse the names list from the trailing parameter
        names_str = names_msgs[0].params[-1]
        names = names_str.split()

        for name in names:
            # Strip channel prefix (@, +)
            clean = name.lstrip("@+")
            assert "!" in clean and "@" in clean, (
                f"UHNAMES entry missing user@host format: {name}"
            )
            nick, rest = clean.split("!", 1)
            user, host = rest.split("@", 1)
            assert len(nick) > 0, "Empty nick in UHNAMES"
            assert len(user) > 0, "Empty user in UHNAMES"
            assert len(host) > 0, "Empty host in UHNAMES"
    finally:
        await client.disconnect()


async def test_no_uhnames_names_reply_format(ircd_hub, make_client):
    """Without UHNAMES cap, NAMES reply should be plain nicks."""
    client = await make_client("uhtest3")

    await client.send("JOIN #test_uh_fix2")
    msgs = await client.collect_until("366", timeout=5.0)

    names_msgs = [m for m in msgs if m.command == "353"]
    assert len(names_msgs) > 0

    names_str = names_msgs[0].params[-1]
    names = names_str.split()

    for name in names:
        clean = name.lstrip("@+")
        # Without UHNAMES, names should NOT contain ! or @
        assert "!" not in clean, (
            f"Non-UHNAMES client got user@host format: {name}"
        )
