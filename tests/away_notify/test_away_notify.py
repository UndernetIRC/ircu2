"""away-notify CAP and AWAY on JOIN (commit d4109f5).

Clients with away-notify see ``AWAY`` when a peer joins while away, and
on live AWAY changes. Clients without the CAP see neither. Covers local
and hub→leaf join paths.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import drain_briefly, make_cap_client

pytestmark = pytest.mark.multi_server


async def test_away_notify_on_join_with_and_without_cap(ircd_network):
    """When an away user joins, only away-notify clients see AWAY."""
    hub = ircd_network["hub"]
    chan = "#away_join"

    cap = await make_cap_client(hub["host"], hub["port"], "awaycap1", ["away-notify"])
    nocap = await make_cap_client(hub["host"], hub["port"], "awaynoc1")
    joiner = await make_cap_client(hub["host"], hub["port"], "awayjoin1")

    try:
        await cap.send(f"JOIN {chan}")
        await cap.wait_for("JOIN")
        await nocap.send(f"JOIN {chan}")
        await nocap.wait_for("JOIN")
        await drain_briefly(cap)
        await drain_briefly(nocap)

        await joiner.send("AWAY :gone fishing")
        await asyncio.sleep(0.2)
        await joiner.send(f"JOIN {chan}")
        await joiner.wait_for("JOIN")

        away_msg = await cap.wait_for_user_msg("AWAY", timeout=3.0)
        assert away_msg.prefix and away_msg.prefix.lower().startswith("awayjoin1!")
        assert away_msg.params[-1] == "gone fishing"

        await nocap.assert_no_message("AWAY", timeout=1.5)
    finally:
        for c in (cap, nocap, joiner):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_live_away_with_and_without_cap(ircd_network):
    """Live AWAY while sharing a channel is CAP-gated the same way."""
    hub = ircd_network["hub"]
    chan = "#away_live"

    cap = await make_cap_client(hub["host"], hub["port"], "awaycap2", ["away-notify"])
    nocap = await make_cap_client(hub["host"], hub["port"], "awaynoc2")
    user = await make_cap_client(hub["host"], hub["port"], "awayuser2")

    try:
        for c in (cap, nocap, user):
            await c.send(f"JOIN {chan}")
            await c.wait_for("JOIN")
        await drain_briefly(cap)
        await drain_briefly(nocap)

        await user.send("AWAY :brb")
        away_msg = await cap.wait_for_user_msg("AWAY", timeout=3.0)
        assert away_msg.params[-1] == "brb"
        await nocap.assert_no_message("AWAY", timeout=1.5)

        await user.send("AWAY")
        unaway = await cap.wait_for_user_msg("AWAY", timeout=3.0)
        assert not unaway.params or unaway.params[-1] == ""
        await nocap.assert_no_message("AWAY", timeout=1.0)
    finally:
        for c in (cap, nocap, user):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_away_notify_across_servers_on_join(ircd_network):
    """Away user on hub joining a shared channel notifies leaf CAP clients."""
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    chan = "#away_s2s"

    leaf_cap = await make_cap_client(
        leaf["host"], leaf["port"], "lawaycap", ["away-notify"]
    )
    leaf_nocap = await make_cap_client(leaf["host"], leaf["port"], "lawaynoc")
    hub_user = await make_cap_client(hub["host"], hub["port"], "hawayusr")

    try:
        await leaf_cap.send(f"JOIN {chan}")
        await leaf_cap.wait_for("JOIN")
        await leaf_nocap.send(f"JOIN {chan}")
        await leaf_nocap.wait_for("JOIN")
        await asyncio.sleep(0.3)
        await drain_briefly(leaf_cap)
        await drain_briefly(leaf_nocap)

        await hub_user.send("AWAY :cross-server")
        await asyncio.sleep(0.2)
        await hub_user.send(f"JOIN {chan}")
        await hub_user.wait_for("JOIN")

        join_msg = await leaf_cap.wait_for_user_msg("JOIN", timeout=5.0)
        assert join_msg.prefix and join_msg.prefix.lower().startswith("hawayusr!")
        away_msg = await leaf_cap.wait_for_user_msg("AWAY", timeout=5.0)
        assert away_msg.prefix and away_msg.prefix.lower().startswith("hawayusr!")
        assert away_msg.params[-1] == "cross-server"

        await leaf_nocap.assert_no_message("AWAY", timeout=1.5)
    finally:
        for c in (leaf_cap, leaf_nocap, hub_user):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
