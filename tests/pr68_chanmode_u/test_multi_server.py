"""Multi-server tests for channel mode +u: s2s propagation."""

import asyncio
import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.multi_server


async def test_part_reason_suppressed_remote(ircd_network):
    """+u suppression holds for a user parting from a remote server."""
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]

    op = IRCClient()
    await op.connect(hub["host"], hub["port"])
    await op.register("op68rem", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(leaf1["host"], leaf1["port"])
    await observer.register("obs68rem", "testuser", "Test User")

    try:
        await op.send("JOIN #pr68rem")
        await op.wait_for("366")
        await op.send("MODE #pr68rem +u")
        await op.wait_for("MODE")

        await observer.send("JOIN #pr68rem")
        await observer.wait_for("366")
        await op.wait_for("JOIN")
        await asyncio.sleep(0.5)

        await observer.send("PART #pr68rem :secret leaving message")
        part = await op.wait_for("PART", timeout=5.0)
        assert len(part.params) == 1 or part.params[-1] == "", (
            f"remote part reason leaked despite +u: {part.params}"
        )
    finally:
        for c in (op, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
