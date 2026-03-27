"""Tests for PR #62: privilege check logic for OPMODE user modes.

PR #62 splits the U:line privilege check in ms_opmode into two tiers:
1. Basic CONF_UWORLD — required for any OPMODE. Without it, the command
   is rejected via protocol_violation().
2. CONF_UWORLD_OPER — additionally required for +o/-o only. The +x mode
   intentionally only needs basic CONF_UWORLD, since it's a less
   privileged operation than granting/revoking oper status.

These tests verify:
- A non-oper U:lined server CAN send +x (only needs CONF_UWORLD)
- A non-oper U:lined server CANNOT send +o or -o (needs CONF_UWORLD_OPER)
- Unknown modes are silently ignored (no crash, no error)
- A completely non-U:lined server cannot send any OPMODE
"""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.multi_server


@pytest.fixture
async def uworld_nooper(ircd_network):
    """Connect a U:lined server WITHOUT the oper flag.

    This server has UWorld { name = "uworldonly.test.net"; } in the hub
    config, but NOT UWorld { oper = "..."; }. So it has CONF_UWORLD
    but NOT CONF_UWORLD_OPER.
    """
    hub = ircd_network["hub"]
    srv = P10Server(
        name="uworldonly.test.net",
        numeric=6,
        password="testpass",
        description="UWorld-only (no oper) Test Server",
    )
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


@pytest.fixture
async def services(ircd_network):
    """Connect the fully-privileged U:lined services server (has oper flag)."""
    hub = ircd_network["hub"]
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


async def test_nooper_uworld_can_send_plus_x(ircd_network, uworld_nooper, services):
    """A U:lined server WITHOUT oper flag CAN send OPMODE +x.

    PR #62 intentionally only gates +o/-o behind CONF_UWORLD_OPER.
    The +x mode only requires basic CONF_UWORLD, since setting a
    hidden host is a less privileged operation than granting oper.
    A non-oper U:lined server (e.g. a channel service) should be
    able to set +x on users.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("privusr1", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("obspr1", "testuser", "Test User")

    try:
        numnick = await uworld_nooper.wait_for_user("privusr1")

        # Get original host
        await observer.send("WHOIS privusr1")
        whois_before = await observer.collect_until("318", timeout=5.0)
        original_host = [m for m in whois_before if m.command == "311"][0].params[3]

        # Need account first (use the oper-privileged services for ACCOUNT,
        # since we're testing OPMODE privilege, not ACCOUNT privilege)
        await services.send_account(numnick, "PrivTestAcct")
        await asyncio.sleep(0.3)

        # Non-oper U:lined server sends +x — should SUCCEED
        await uworld_nooper.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        # User should get MODE +x
        try:
            mode_msg = await user.wait_for("MODE", timeout=3.0)
            assert "x" in mode_msg.params[-1], (
                f"Expected +x in mode change: {mode_msg.params}"
            )
        except asyncio.TimeoutError:
            pytest.fail(
                "User did not receive MODE +x from non-oper U:lined server — "
                "+x should only require basic CONF_UWORLD, not CONF_UWORLD_OPER"
            )

        # Verify host is now hidden
        await observer.send("WHOIS privusr1")
        whois_after = await observer.collect_until("318", timeout=5.0)
        new_host = [m for m in whois_after if m.command == "311"][0].params[3]
        assert new_host != original_host, (
            f"Host should be hidden after ACCOUNT + OPMODE +x: still {original_host!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_nooper_uworld_cannot_send_plus_o(ircd_network, uworld_nooper):
    """A U:lined server WITHOUT oper flag CANNOT send OPMODE +o.

    This confirms the oper check works correctly for +o — only the
    +x bypass exists, not a total privilege escalation.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("privusr2", "testuser", "Test User")

    try:
        numnick = await uworld_nooper.wait_for_user("privusr2")

        # Non-oper U:lined server tries +o — should be denied
        await uworld_nooper.send_opmode(numnick, "+o")
        await asyncio.sleep(0.5)

        # User should NOT become oper
        try:
            mode_msg = await user.wait_for("MODE", timeout=2.0)
            has_o = "o" in mode_msg.params[-1]
            assert not has_o, (
                "Non-oper U:lined server was able to set +o — "
                "CONF_UWORLD_OPER check is broken!"
            )
        except asyncio.TimeoutError:
            pass  # Expected: no MODE sent, +o was denied

        # Double-check: query user mode
        await user.send("MODE privusr2")
        umode = await user.wait_for("221", timeout=3.0)
        assert "o" not in umode.params[-1], (
            f"User should NOT be oper: {umode.params}"
        )
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_nooper_uworld_cannot_send_minus_o(ircd_network, uworld_nooper, services):
    """A U:lined server WITHOUT oper flag CANNOT send OPMODE -o.

    Even if someone else opered the user, a non-oper U:lined server
    should not be able to de-oper them.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("privusr3", "testuser", "Test User")

    try:
        numnick_svc = await services.wait_for_user("privusr3")

        # Oper the user via the privileged services server
        await services.send_opmode(numnick_svc, "+o")
        await asyncio.sleep(0.5)
        mode_msg = await user.wait_for("MODE", timeout=3.0)
        assert "o" in mode_msg.params[-1]

        # Now the non-oper server tries to de-oper
        numnick_uw = await uworld_nooper.wait_for_user("privusr3")
        await uworld_nooper.send_opmode(numnick_uw, "-o")
        await asyncio.sleep(0.5)

        # User should still be oper
        await user.send("MODE privusr3")
        umode = await user.wait_for("221", timeout=3.0)
        assert "o" in umode.params[-1], (
            f"User should still be oper — non-oper U:line should not "
            f"be able to de-oper: {umode.params}"
        )
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_nooper_uworld_unknown_mode_silently_ignored(ircd_network, uworld_nooper):
    """A U:lined server sending an unknown mode (e.g. +W) has it silently ignored.

    Unknown modes fall through the if/else chain in ms_opmode without
    matching +o, -o, or +x, so nothing happens and the function returns 0.
    No error is sent back. This is the expected behavior — the server
    should remain stable and the user unaffected.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("privusr4", "testuser", "Test User")

    try:
        numnick = await uworld_nooper.wait_for_user("privusr4")

        # Send an unknown mode — should be silently ignored
        await uworld_nooper.send_opmode(numnick, "+W")
        await asyncio.sleep(0.5)

        # User should NOT receive any MODE notification
        try:
            mode_msg = await user.wait_for("MODE", timeout=2.0)
            pytest.fail(
                f"User should not receive MODE for unknown mode +W: {mode_msg.params}"
            )
        except asyncio.TimeoutError:
            pass  # Expected: no MODE sent

        # User should still be connected and functional
        await user.send("PING :alive")
        pong = await user.wait_for("PONG", timeout=3.0)
        assert pong is not None, "Server should still respond after unknown OPMODE"
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_notulined_server_cannot_send_plus_x(ircd_network):
    """A server with NO UWorld entry at all cannot send OPMODE +x.

    This is the baseline: the !conf check catches servers without
    any U:line, regardless of mode string.
    """
    hub = ircd_network["hub"]

    rogue = P10Server(
        name="notulined.test.net",
        numeric=5,
        password="testpass",
        description="Not U:lined at all",
    )
    await rogue.connect(hub["host"], hub["server_port"])
    await rogue.handshake()

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("privusr5", "testuser", "Test User")

    try:
        numnick = await rogue.wait_for_user("privusr5")

        # Non-U:lined server sends +x — should be denied
        await rogue.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        # User should NOT get a MODE notification
        try:
            mode_msg = await user.wait_for("MODE", timeout=2.0)
            has_x = "x" in mode_msg.params[-1]
            assert not has_x, (
                "Non-U:lined server was able to set +x — "
                "the !conf check is broken!"
            )
        except asyncio.TimeoutError:
            pass  # Expected: no MODE sent

    finally:
        await rogue.disconnect()
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()
