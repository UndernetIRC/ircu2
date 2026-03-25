"""TDD tests for PR #59: Part message suppression for banned users.

Bug: When a banned user parts a channel, their part message text is
propagated to other servers even though it should be suppressed. The
old code checked CHFL_BANNED inline in the format string selection for
the local send, but did not clear jb_comment before the server-to-server
propagation — so users on remote servers could still see the part text.

Fix: channel.c now clears jb_comment when CHFL_BANNED is set BEFORE
any send, ensuring the suppression applies both locally and across
the network.

These tests require the multi-server topology (hub + leaves) to verify
that part messages are suppressed on remote servers.
"""

import asyncio
import pytest

from tests.irc_client import IRCClient


pytestmark = pytest.mark.multi_server


async def test_banned_user_part_message_hidden_remote(ircd_network):
    """A banned user's part message must not be visible on remote servers.

    This is the core bug PR #59 fixes: the part message text leaks
    across server-to-server links for banned users.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    # chanop connects to hub
    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("chanop59", "testuser", "Test User")

    # observer connects to leaf1 (different server)
    observer = IRCClient()
    await observer.connect(leaf1["host"], leaf1["port"])
    await observer.register("obsrv59", "testuser", "Test User")

    # banned user connects to hub
    banned = IRCClient()
    await banned.connect(hub["host"], hub["port"])
    await banned.register("banned59", "testuser", "Test User")

    try:
        # chanop creates channel and observer joins from remote
        await chanop.send("JOIN #test_pr59_s2s")
        await chanop.wait_for("366")

        await observer.send("JOIN #test_pr59_s2s")
        await observer.wait_for("366")
        # Wait for the remote JOIN to propagate
        await chanop.wait_for("JOIN")

        # banned user joins
        await banned.send("JOIN #test_pr59_s2s")
        await banned.wait_for("366")
        await chanop.wait_for("JOIN")
        await observer.wait_for("JOIN")

        # chanop bans the user
        await chanop.send("MODE #test_pr59_s2s +b banned59!*@*")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.5)  # Let mode propagate across servers

        # banned user parts with a message
        await banned.send("PART #test_pr59_s2s :secret leaving message")
        await banned.wait_for("PART")

        # Observer on leaf1 should see PART but WITHOUT the message text
        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
            f"Banned user's part message leaked to remote server: {part_msg.params}"
        )
    finally:
        for client in (chanop, observer, banned):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_unbanned_user_part_message_visible_remote(ircd_network):
    """A non-banned user's part message should be visible on remote servers."""
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    user1 = IRCClient()
    await user1.connect(hub["host"], hub["port"])
    await user1.register("usr59a", "testuser", "Test User")

    user2 = IRCClient()
    await user2.connect(leaf1["host"], leaf1["port"])
    await user2.register("usr59b", "testuser", "Test User")

    try:
        await user1.send("JOIN #test_pr59_s2s2")
        await user1.wait_for("366")

        await user2.send("JOIN #test_pr59_s2s2")
        await user2.wait_for("366")
        await user1.wait_for("JOIN")

        # user1 parts with a message (no ban)
        await user1.send("PART #test_pr59_s2s2 :goodbye everyone")
        await user1.wait_for("PART")

        # user2 on remote server should see the full part message
        part_msg = await user2.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) >= 2, "Part message should have text"
        assert "goodbye everyone" in part_msg.params[-1], (
            f"Part message text not visible on remote: {part_msg.params}"
        )
    finally:
        for client in (user1, user2):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
