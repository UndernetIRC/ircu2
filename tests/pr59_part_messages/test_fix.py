"""TDD tests for PR #59: Part message suppression for banned users.

Bug: When a banned user parts a channel, their part message (the text
after PART) is visible to other channel members. It should be suppressed
so banned users cannot use PART messages to send text to the channel.

Fix: channel.c clears jb_comment when CHFL_BANNED flag is set, before
sending the PART notification.
"""

import asyncio
import pytest


pytestmark = pytest.mark.single_server


async def test_banned_user_part_message_hidden(ircd_hub, make_client):
    """A banned user's part message text must not be visible to channel members."""
    chanop = await make_client("chanop59")
    banned = await make_client("banned59")

    # chanop joins and creates channel
    await chanop.send("JOIN #test_pr59_fix1")
    await chanop.wait_for("366")  # end of NAMES

    # banned user joins
    await banned.send("JOIN #test_pr59_fix1")
    await banned.wait_for("366")

    # Consume the JOIN notification on chanop side
    await chanop.wait_for("JOIN")

    # chanop bans the user
    await chanop.send("MODE #test_pr59_fix1 +b banned59!*@*")
    await chanop.wait_for("MODE")

    # Small delay to let mode propagate
    await asyncio.sleep(0.2)

    # banned user parts with a message
    await banned.send("PART #test_pr59_fix1 :secret leaving message")
    await banned.wait_for("PART")

    # chanop should see a PART but without the message text
    part_msg = await chanop.wait_for("PART", timeout=3.0)
    # The part message text should be suppressed (not present in params)
    assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
        f"Banned user's part message was not suppressed: {part_msg.params}"
    )


async def test_unbanned_user_part_message_visible(ircd_hub, make_client):
    """A non-banned user's part message should be visible to channel members."""
    user1 = await make_client("user59a")
    user2 = await make_client("user59b")

    await user1.send("JOIN #test_pr59_fix2")
    await user1.wait_for("366")

    await user2.send("JOIN #test_pr59_fix2")
    await user2.wait_for("366")

    # Consume JOIN on user1 side
    await user1.wait_for("JOIN")

    # user2 parts with a message (no ban)
    await user2.send("PART #test_pr59_fix2 :goodbye everyone")
    await user2.wait_for("PART")

    # user1 should see the PART with the message text
    part_msg = await user1.wait_for("PART", timeout=3.0)
    assert len(part_msg.params) >= 2, "Part message should have text"
    assert "goodbye everyone" in part_msg.params[-1], (
        f"Part message text not visible: {part_msg.params}"
    )
