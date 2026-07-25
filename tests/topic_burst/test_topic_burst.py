"""TOPIC_BURST / topic who (commit d0757a1).

Topic setter nick is preserved on S2S TOPIC burst and shown to clients
via RPL_TOPICWHOTIME (333) after JOIN.

Prod rolling-upgrade parse tolerance for TOPIC-with-who lives in
``pr_network_features_compat/``.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import burst_lines, connect_services, make_cap_client
from p10_server import strip_msg_tags

pytestmark = pytest.mark.multi_server


async def test_topic_who_visible_to_clients_across_servers(ircd_network):
    """Leaf JOIN sees 332/333 with the hub setter's nick."""
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    chan = "#topic_who"

    setter = await make_cap_client(hub["host"], hub["port"], "topicstr")
    leaf_user = await make_cap_client(leaf["host"], leaf["port"], "topiclf")

    try:
        await setter.send(f"JOIN {chan}")
        await setter.wait_for("JOIN")
        await setter.send(f"TOPIC {chan} :hello from hub")
        await asyncio.sleep(0.5)

        await leaf_user.send(f"JOIN {chan}")
        msgs = await leaf_user.collect_until("366", timeout=5.0)
        topic_msgs = [m for m in msgs if m.command == "332"]
        who_msgs = [m for m in msgs if m.command == "333"]
        assert topic_msgs, f"Expected RPL_TOPIC on join, got {[m.command for m in msgs]}"
        assert topic_msgs[0].params[-1] == "hello from hub"
        assert who_msgs, f"Expected RPL_TOPICWHOTIME (333), got {[m.command for m in msgs]}"
        assert who_msgs[0].params[2] == "topicstr", (
            f"TOPIC who should be topicstr, got {who_msgs[0].params!r}"
        )
    finally:
        for c in (setter, leaf_user):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_topic_burst_includes_who(ircd_network):
    """New server link receives TOPIC with topic_nick during channel burst."""
    hub = ircd_network["hub"]
    chan = "#topic_burst"

    setter = await make_cap_client(hub["host"], hub["port"], "tburst")
    await setter.send(f"JOIN {chan}")
    await setter.wait_for("JOIN")
    await setter.send(f"TOPIC {chan} :burst topic text")
    await asyncio.sleep(0.4)

    srv = await connect_services(hub)
    try:
        topic_lines = burst_lines(srv, "T")
        matched = [
            line for line in topic_lines
            if chan.lower() in line.lower() and "burst topic text" in line
        ]
        assert matched, f"Expected TOPIC burst for {chan}, got: {topic_lines!r}"
        parts = strip_msg_tags(matched[0]).split()
        assert len(parts) >= 6, f"TOPIC burst too short: {matched[0]!r}"
        who = parts[5]
        assert who == "tburst", (
            f"TOPIC burst who should be tburst, got {who!r} in {matched[0]!r}"
        )
    finally:
        await srv.disconnect()
        await setter.disconnect()
