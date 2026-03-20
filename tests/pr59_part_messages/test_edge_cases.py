"""Edge case tests for PR #59: Part message suppression.

Adversarial tests trying to break the part message suppression logic.
"""

import asyncio
import pytest


pytestmark = pytest.mark.single_server


async def test_banned_user_part_no_message(ircd_hub, make_client):
    """Banned user parts with no message at all — should work cleanly."""
    chanop = await make_client("op59e1")
    banned = await make_client("bn59e1")

    await chanop.send("JOIN #test_e1")
    await chanop.wait_for("366")
    await banned.send("JOIN #test_e1")
    await banned.wait_for("366")
    await chanop.wait_for("JOIN")

    await chanop.send("MODE #test_e1 +b bn59e1!*@*")
    await chanop.wait_for("MODE")
    await asyncio.sleep(0.2)

    await banned.send("PART #test_e1")
    await banned.wait_for("PART")

    part_msg = await chanop.wait_for("PART", timeout=3.0)
    assert part_msg.params == ["#test_e1"] or part_msg.params[-1] == ""


async def test_banned_user_part_empty_message(ircd_hub, make_client):
    """Banned user parts with empty message — should be suppressed."""
    chanop = await make_client("op59e2")
    banned = await make_client("bn59e2")

    await chanop.send("JOIN #test_e2")
    await chanop.wait_for("366")
    await banned.send("JOIN #test_e2")
    await banned.wait_for("366")
    await chanop.wait_for("JOIN")

    await chanop.send("MODE #test_e2 +b bn59e2!*@*")
    await chanop.wait_for("MODE")
    await asyncio.sleep(0.2)

    await banned.send("PART #test_e2 :")
    await banned.wait_for("PART")

    part_msg = await chanop.wait_for("PART", timeout=3.0)
    assert len(part_msg.params) == 1 or part_msg.params[-1] == ""


async def test_ban_by_host_part_message_hidden(ircd_hub, make_client):
    """Ban by wildcard hostmask — part message should still be suppressed."""
    chanop = await make_client("op59e3")
    banned = await make_client("bn59e3")

    await chanop.send("JOIN #test_e3")
    await chanop.wait_for("366")
    await banned.send("JOIN #test_e3")
    await banned.wait_for("366")
    await chanop.wait_for("JOIN")

    # Ban by wildcard host
    await chanop.send("MODE #test_e3 +b *!*@*")
    await chanop.wait_for("MODE")
    await asyncio.sleep(0.2)

    await banned.send("PART #test_e3 :hidden message")
    await banned.wait_for("PART")

    part_msg = await chanop.wait_for("PART", timeout=3.0)
    assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
        f"Part message visible with host ban: {part_msg.params}"
    )


async def test_ban_then_unban_part_message_visible(ircd_hub, make_client):
    """After unbanning, the user's part message should be visible again."""
    chanop = await make_client("op59e5")
    user = await make_client("us59e5")

    await chanop.send("JOIN #test_e5")
    await chanop.wait_for("366")
    await user.send("JOIN #test_e5")
    await user.wait_for("366")
    await chanop.wait_for("JOIN")

    # Ban then unban
    await chanop.send("MODE #test_e5 +b us59e5!*@*")
    await chanop.wait_for("MODE")
    await asyncio.sleep(0.1)
    await chanop.send("MODE #test_e5 -b us59e5!*@*")
    await chanop.wait_for("MODE")
    await asyncio.sleep(0.2)

    await user.send("PART #test_e5 :visible message")
    await user.wait_for("PART")

    part_msg = await chanop.wait_for("PART", timeout=3.0)
    assert len(part_msg.params) >= 2, "Part message should have text after unban"
    assert "visible message" in part_msg.params[-1]


async def test_part_message_visible_to_parting_user(ircd_hub, make_client):
    """Even when banned, the parting user should see their own PART."""
    chanop = await make_client("op59e6")
    banned = await make_client("bn59e6")

    await chanop.send("JOIN #test_e6")
    await chanop.wait_for("366")
    await banned.send("JOIN #test_e6")
    await banned.wait_for("366")
    await chanop.wait_for("JOIN")

    await chanop.send("MODE #test_e6 +b bn59e6!*@*")
    await chanop.wait_for("MODE")
    await asyncio.sleep(0.2)

    await banned.send("PART #test_e6 :my farewell")
    part_msg = await banned.wait_for("PART", timeout=3.0)
    # The parting user should see their own PART
    assert "#test_e6" in part_msg.params[0]
