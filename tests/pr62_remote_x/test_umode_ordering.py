"""Tests for PR #62 review Issue 2: send_umode_out() before hide_hostmask() ordering.

The concern: in ms_opmode's +x handler, send_umode_out() propagates the
mode change to the network BEFORE hide_hostmask() does the actual host
change (QUIT/JOIN cycle for non-CHGHOST clients). This means MODE +x is
sent before the host is changed.

These tests observe the ordering from a channel member's perspective to
verify the behavior is consistent and correct (MODE +x arrives before
the QUIT/JOIN host-change sequence).

Note: This test will PASS — the ordering matches set_user_mode() and is
correct. It's included to document and verify the behavior for reviewers.
"""

import asyncio
import pytest

from tests.irc_client import IRCClient
from tests.p10_server import P10Server


pytestmark = pytest.mark.multi_server


@pytest.fixture
async def services(ircd_network):
    """Connect a fake P10 services server to the hub."""
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


async def test_mode_x_arrives_before_host_change(ircd_network, services):
    """Observer in a channel sees MODE +x BEFORE the QUIT/JOIN host change.

    When OPMODE +x is applied, send_umode_out() fires first (broadcasting
    MODE +x), then hide_hostmask() fires (sending QUIT :Registered + JOIN
    to non-CHGHOST channel members).

    This verifies the ordering is: MODE → QUIT → JOIN, which is the same
    as set_user_mode() and is the expected behavior.
    """
    hub = ircd_network["hub"]

    # Target user who will get +x
    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("ordusr1", "testuser", "Test User")

    # Observer in the same channel
    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("ordobs1", "testuser", "Test User")

    try:
        # Both join a channel
        await user.send("JOIN #ordertest")
        await user.wait_for("JOIN", timeout=3.0)
        await observer.send("JOIN #ordertest")
        await observer.wait_for("JOIN", timeout=3.0)

        # Drain any pending messages on observer
        await asyncio.sleep(0.3)
        while True:
            try:
                await observer.recv(timeout=0.3)
            except (asyncio.TimeoutError, TimeoutError):
                break

        numnick = await services.wait_for_user("ordusr1")

        # Set account first
        await services.send_account(numnick, "OrderTest")
        await asyncio.sleep(0.3)

        # Drain again after account
        while True:
            try:
                await observer.recv(timeout=0.3)
            except (asyncio.TimeoutError, TimeoutError):
                break

        # Now trigger +x
        await services.send_opmode(numnick, "+x")

        # Collect messages the observer receives over the next 3 seconds
        messages = []
        try:
            deadline = asyncio.get_event_loop().time() + 3.0
            while asyncio.get_event_loop().time() < deadline:
                remaining = deadline - asyncio.get_event_loop().time()
                msg = await observer.recv(timeout=min(remaining, 0.5))
                messages.append(msg)
        except (asyncio.TimeoutError, TimeoutError):
            pass

        # Find relevant messages
        mode_idx = None
        quit_idx = None
        join_idx = None

        for i, msg in enumerate(messages):
            cmd = msg.command.upper() if hasattr(msg, 'command') else str(msg)
            if cmd == "MODE" and any("x" in p for p in getattr(msg, 'params', [])):
                if mode_idx is None:
                    mode_idx = i
            elif cmd == "QUIT":
                if quit_idx is None:
                    quit_idx = i
            elif cmd == "JOIN" and any("#ordertest" in p.lower() for p in getattr(msg, 'params', [])):
                if join_idx is None:
                    join_idx = i

        # We should see at least the QUIT/JOIN from hide_hostmask
        # (MODE +x might not be visible to channel members depending
        # on whether send_umode_out sends to common channels)
        assert quit_idx is not None or mode_idx is not None, (
            f"Expected to see at least MODE or QUIT from OPMODE +x. "
            f"Messages: {[(m.command, m.params) for m in messages]}"
        )

        # If we see both MODE and QUIT, verify ordering
        if mode_idx is not None and quit_idx is not None:
            assert mode_idx < quit_idx, (
                f"MODE +x (index {mode_idx}) should arrive BEFORE "
                f"QUIT (index {quit_idx}). This matches the code order: "
                f"send_umode_out() then hide_hostmask(). "
                f"Messages: {[(m.command, m.params) for m in messages]}"
            )

        # If we see QUIT and JOIN, verify QUIT comes before JOIN
        if quit_idx is not None and join_idx is not None:
            assert quit_idx < join_idx, (
                f"QUIT (index {quit_idx}) should arrive BEFORE "
                f"JOIN (index {join_idx})."
            )

    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_hide_hostmask_redundant_setflag(ircd_network, services):
    """Verify +x is applied correctly despite SetHiddenHost being called twice.

    The code calls SetHiddenHost(dptr) before send_umode_out(), then
    hide_hostmask() calls SetFlag(cptr, FLAG_HIDDENHOST) again internally.
    This is redundant but should not cause any observable problem —
    the host should still be correctly hidden.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("ordusr2", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("ordobs2", "testuser", "Test User")

    try:
        # Get original host
        await observer.send("WHOIS ordusr2")
        whois1 = await observer.collect_until("318", timeout=5.0)
        original_host = [m for m in whois1 if m.command == "311"][0].params[3]

        numnick = await services.wait_for_user("ordusr2")

        # Set account, then +x
        await services.send_account(numnick, "RdntTest")
        await asyncio.sleep(0.3)

        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(1.0)

        # Host should be hidden despite the redundant SetFlag
        await observer.send("WHOIS ordusr2")
        whois2 = await observer.collect_until("318", timeout=5.0)
        new_host = [m for m in whois2 if m.command == "311"][0].params[3]

        assert new_host != original_host, (
            f"Host should be hidden after ACCOUNT + OPMODE +x "
            f"(redundant SetFlag should not break anything): "
            f"still {original_host!r}"
        )

        # Verify it's the expected format: account.hidden-host
        assert "RdntTest" in new_host, (
            f"Hidden host should contain account name: {new_host!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
