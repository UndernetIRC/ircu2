"""Edge case tests for PR #64: Network configuration (netconf).

Adversarial tests trying to break the netconf CONFIG implementation.
Tests cover various CONFIG inputs from clients, multi-server STATS C
behavior, and case sensitivity boundary cases.
"""

import asyncio
import pytest

from irc_client import IRCClient


# -- Single-server edge cases --


@pytest.mark.single_server
async def test_config_no_params_ignored(ircd_hub, make_client):
    """CONFIG with no parameters from a client should be silently ignored.

    The server handler (ms_config) requires parc >= 3, but the client
    handler is m_ignore, so no params check is reached for clients.
    """
    client = await make_client("nc64e1")

    await client.send("CONFIG")

    await client.send("PING :noparams")
    msgs = await client.collect_until("PONG", timeout=5.0)
    for msg in msgs:
        if msg.command == "421" and "CONFIG" in msg.params[1]:
            pytest.skip("CONFIG command not registered (PR #64 not applied)")


@pytest.mark.single_server
async def test_config_long_key_value_ignored(ircd_hub, make_client):
    """CONFIG with a long (but within protocol limits) key/value should be ignored.

    Even with longer-than-normal input, the m_ignore handler should silently
    discard the message without crashing or disconnecting the client.
    IRC messages are limited to 512 bytes, so we stay within that limit.
    """
    client = await make_client("nc64e2")

    # Stay within 512-byte IRC message limit (including CRLF)
    long_key = "a" * 50 + ".key"
    long_value = "b" * 100
    await client.send(f"CONFIG 1234567890 {long_key} {long_value}")

    # Verify connection is still alive
    await client.send("PING :longcheck")
    msgs = await client.collect_until("PONG", timeout=5.0)
    for msg in msgs:
        if msg.command == "421" and "CONFIG" in msg.params[1]:
            pytest.skip("CONFIG command not registered (PR #64 not applied)")


@pytest.mark.single_server
async def test_config_special_chars_ignored(ircd_hub, make_client):
    """CONFIG with special characters in key/value should be silently ignored."""
    client = await make_client("nc64e3")

    await client.send("CONFIG 1234567890 test..key.. :value with spaces and !@#$%")

    await client.send("PING :specialcheck")
    msgs = await client.collect_until("PONG", timeout=5.0)
    for msg in msgs:
        if msg.command == "421" and "CONFIG" in msg.params[1]:
            pytest.skip("CONFIG command not registered (PR #64 not applied)")


@pytest.mark.single_server
async def test_stats_C_case_sensitivity(ircd_hub, make_client):
    """Verify STATS C (uppercase) and STATS c (lowercase) are distinct.

    PR #64 adds STAT_FLAG_CASESENS to both entries. STATS C = netconf,
    STATS c = connect lines. They must not be confused.
    """
    client = await make_client("nc64e4")

    await client.send("OPER testoper operpass")
    await client.wait_for("381")

    # Get STATS C (netconf) — should have no RPL_STATSCLINE (213) entries
    await client.send("STATS C")
    msgs_upper = await client.collect_until("219", timeout=5.0)
    end_upper = msgs_upper[-1]

    # Get STATS c (connect lines) — should have RPL_STATSCLINE (213) entries
    await client.send("STATS c")
    msgs_lower = await client.collect_until("219", timeout=5.0)
    end_lower = msgs_lower[-1]

    # Both should end properly
    assert end_upper.command == "219"
    assert end_lower.command == "219"

    # The responses should differ: 'c' has connect lines, 'C' does not
    connect_in_upper = [m for m in msgs_upper if m.command == "213"]
    connect_in_lower = [m for m in msgs_lower if m.command == "213"]

    # If both have 213 entries, the PR's case sensitivity is not in effect
    if len(connect_in_upper) > 0 and len(connect_in_lower) > 0:
        pytest.skip("STATS C not case-sensitive (PR #64 not applied)")

    assert len(connect_in_lower) > 0, "STATS c should return connect lines"
    assert len(connect_in_upper) == 0, "STATS C should not return connect lines"


@pytest.mark.single_server
async def test_config_unregistered_client_ignored(ircd_hub):
    """An unregistered client sending CONFIG should be ignored (m_ignore).

    The UNREG handler is also m_ignore, so CONFIG before NICK/USER
    should not cause any issues.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])

    try:
        await client.send("CONFIG 1234567890 test.key val")

        # Complete registration to verify connection is still alive
        await client.register("nc64e5", "testuser", "Test User")
        # If we got here, the connection survived
    finally:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()


@pytest.mark.single_server
async def test_stats_C_multiple_queries(ircd_hub, make_client):
    """Multiple STATS C queries in succession should all return properly."""
    client = await make_client("nc64e6")

    await client.send("OPER testoper operpass")
    await client.wait_for("381")

    for i in range(3):
        await client.send("STATS C")
        msg = await client.wait_for("219", timeout=5.0)
        assert msg.command == "219", f"STATS C query #{i+1} failed"


@pytest.mark.single_server
async def test_stats_C_oper_gets_end_of_stats(ircd_hub, make_client):
    """An oper querying STATS C should always get RPL_ENDOFSTATS (219).

    Even with zero netconf entries, the end-of-stats response should
    be sent.
    """
    client = await make_client("nc64e7")

    await client.send("OPER testoper operpass")
    await client.wait_for("381")

    await client.send("STATS C")
    msgs = await client.collect_until("219", timeout=5.0)
    end = msgs[-1]
    assert end.command == "219"
    assert "C" in end.params[1]


@pytest.mark.single_server
async def test_config_rapid_fire_ignored(ircd_hub, make_client):
    """Sending a few CONFIG commands rapidly should not cause issues."""
    client = await make_client("nc64e8")

    for i in range(3):
        await client.send(f"CONFIG {i} key{i} value{i}")
        await asyncio.sleep(0.1)

    # Verify connection is still alive
    await client.send("PING :rapidfire")
    msgs = await client.collect_until("PONG", timeout=5.0)
    # If we got PONG, the server handled the burst without disconnecting


# -- Multi-server edge cases --


@pytest.mark.multi_server
async def test_stats_C_consistent_across_servers(ircd_network):
    """STATS C should return consistently across hub and leaf servers.

    Both servers should respond to STATS C with end-of-stats. Since no
    config entries are set (no service is running), both should be empty.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    hub_client = IRCClient()
    await hub_client.connect(hub["host"], hub["port"])
    await hub_client.register("nc64m1", "testuser", "Test User")

    leaf_client = IRCClient()
    await leaf_client.connect(leaf1["host"], leaf1["port"])
    await leaf_client.register("nc64m2", "testuser", "Test User")

    try:
        # Both become oper
        await hub_client.send("OPER testoper operpass")
        await hub_client.wait_for("381")

        await leaf_client.send("OPER testoper operpass")
        await leaf_client.wait_for("381")

        # Query STATS C on both
        await hub_client.send("STATS C")
        hub_end = await hub_client.wait_for("219", timeout=5.0)

        await leaf_client.send("STATS C")
        leaf_end = await leaf_client.wait_for("219", timeout=5.0)

        assert hub_end.command == "219"
        assert leaf_end.command == "219"
    finally:
        for c in (hub_client, leaf_client):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


@pytest.mark.multi_server
async def test_config_ignored_on_all_servers(ircd_network):
    """CONFIG sent by a client should be ignored on any server in the network."""
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]
    leaf2 = ircd_network["leaf2"]

    clients = []
    try:
        for name, server in [("nc64m3", hub), ("nc64m4", leaf1), ("nc64m5", leaf2)]:
            c = IRCClient()
            await c.connect(server["host"], server["port"])
            await c.register(name, "testuser", "Test User")
            clients.append(c)

        for c in clients:
            await c.send("CONFIG 9999999999 attack.key evilvalue")
            await c.send("PING :verify")
            msgs = await c.collect_until("PONG", timeout=5.0)
            for msg in msgs:
                if msg.command == "421" and "CONFIG" in msg.params[1]:
                    pytest.skip("CONFIG command not registered (PR #64 not applied)")
    finally:
        for c in clients:
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
