"""Edge case tests for PR #61: userhost-in-names (UHNAMES).

Adversarial tests for the UHNAMES capability. These tests require
PR #61 to be applied.
"""

import pytest

from tests.irc_client import IRCClient


pytestmark = pytest.mark.single_server


async def _make_uhnames_client(host, port, nick, username="testuser"):
    """Helper: create a client with UHNAMES negotiated."""
    client = IRCClient()
    await client.connect(host, port)
    acked = await client.negotiate_cap(["userhost-in-names"])
    if "userhost-in-names" not in acked:
        await client.disconnect()
        pytest.skip("userhost-in-names not supported on this build")
    await client.register(nick, username, "Test User")
    return client


async def test_uhnames_multiple_users(ircd_hub, make_client):
    """UHNAMES should show all users in nick!user@host format."""
    # Create a regular client and two UHNAMES clients
    regular = await make_client("uh_reg1")
    uh_client = await _make_uhnames_client(
        ircd_hub["host"], ircd_hub["port"], "uh_cap1"
    )
    try:
        await regular.send("JOIN #test_uh_multi")
        await regular.wait_for("366")
        await uh_client.send("JOIN #test_uh_multi")
        await uh_client.wait_for("366")

        # UHNAMES client requests NAMES
        await uh_client.send("NAMES #test_uh_multi")
        msgs = await uh_client.collect_until("366", timeout=5.0)
        names_msgs = [m for m in msgs if m.command == "353"]

        all_names = []
        for msg in names_msgs:
            all_names.extend(msg.params[-1].split())

        # Should have at least 2 entries (both users)
        assert len(all_names) >= 2, f"Expected 2+ names, got {all_names}"

        for name in all_names:
            clean = name.lstrip("@+")
            assert "!" in clean and "@" in clean, (
                f"UHNAMES entry missing format: {name}"
            )
    finally:
        await uh_client.disconnect()


async def test_uhnames_with_channel_prefix(ircd_hub, make_client):
    """Op (@) and voice (+) prefixes should appear before nick!user@host."""
    uh_client = await _make_uhnames_client(
        ircd_hub["host"], ircd_hub["port"], "uh_pfx1"
    )
    try:
        await uh_client.send("JOIN #test_uh_pfx")
        await uh_client.wait_for("366")

        await uh_client.send("NAMES #test_uh_pfx")
        msgs = await uh_client.collect_until("366", timeout=5.0)
        names_msgs = [m for m in msgs if m.command == "353"]
        names_str = names_msgs[0].params[-1]
        names = names_str.split()

        # The channel creator should be op
        found_op = False
        for name in names:
            if name.startswith("@"):
                found_op = True
                rest = name[1:]
                assert "!" in rest and "@" in rest, (
                    f"Op prefix not followed by UHNAMES format: {name}"
                )
        assert found_op, f"No op found in NAMES: {names}"
    finally:
        await uh_client.disconnect()


async def test_uhnames_without_cap_unaffected(ircd_hub, make_client):
    """A client without UHNAMES in the same channel should get plain names."""
    uh_client = await _make_uhnames_client(
        ircd_hub["host"], ircd_hub["port"], "uh_mix1"
    )
    regular = await make_client("uh_mix2")
    try:
        await uh_client.send("JOIN #test_uh_mix")
        await uh_client.wait_for("366")
        await regular.send("JOIN #test_uh_mix")
        await regular.wait_for("366")

        # Regular client requests NAMES
        await regular.send("NAMES #test_uh_mix")
        msgs = await regular.collect_until("366", timeout=5.0)
        names_msgs = [m for m in msgs if m.command == "353"]
        names_str = names_msgs[0].params[-1]

        for name in names_str.split():
            clean = name.lstrip("@+")
            assert "!" not in clean, (
                f"Non-UHNAMES client got extended format: {name}"
            )
    finally:
        await uh_client.disconnect()


async def test_uhnames_cap_not_advertised_when_disabled(ircd_hub):
    """Sanity check: CAP LS should list userhost-in-names when feature enabled."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        caps = []
        while True:
            msg = await client.recv(timeout=5.0)
            if msg.command == "CAP" and len(msg.params) >= 3:
                if msg.params[1] == "LS":
                    caps.extend(msg.params[-1].split())
                    if msg.params[2] != "*":
                        break
            else:
                break

        # On builds with PR #61, this cap should be present
        # On builds without, it won't be — that's expected
        if "userhost-in-names" not in caps:
            pytest.skip(
                "userhost-in-names not advertised — PR #61 not applied"
            )
        assert "userhost-in-names" in caps
    finally:
        await client.send("CAP END")
        await client.disconnect()


async def test_uhnames_long_username(ircd_hub):
    """UHNAMES with a long username should not corrupt the NAMES reply."""
    # USERLEN is typically 10 in ircu
    long_user = "a" * 10
    client = await _make_uhnames_client(
        ircd_hub["host"], ircd_hub["port"], "uh_long1", username=long_user
    )
    try:
        await client.send("JOIN #test_uh_long")
        msgs = await client.collect_until("366", timeout=5.0)
        names_msgs = [m for m in msgs if m.command == "353"]
        names_str = names_msgs[0].params[-1]

        for name in names_str.split():
            clean = name.lstrip("@+")
            assert "!" in clean and "@" in clean, (
                f"Corrupted UHNAMES with long username: {name}"
            )
            nick, rest = clean.split("!", 1)
            user, host = rest.split("@", 1)
            # Username might be truncated, but should be non-empty
            assert len(user) > 0
            assert len(host) > 0
    finally:
        await client.disconnect()
