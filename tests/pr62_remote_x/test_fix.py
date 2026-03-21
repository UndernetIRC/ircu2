"""TDD tests for PR #62: Remote +x and ACCOUNT restriction.

PR #62 makes two changes to server-to-server message handlers:
1. ms_opmode: Allow U:lined servers to set user mode +x remotely via
   OPMODE (previously only +o/-o were supported).
2. ms_account: Only accept ACCOUNT messages from U:lined servers.

These tests use a fake P10 server (services.test.net) that connects
to the hub as a U:lined service, then sends OPMODE and ACCOUNT
messages to verify the behavior.

Tests should FAIL on the base branch and PASS with the PR applied:
- OPMODE +x: base code ignores +x (only handles +o/-o); PR adds +x.
- ACCOUNT restriction: base code accepts ACCOUNT from any server;
  PR restricts to U:lined servers only (tested in edge cases).
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


async def test_remote_opmode_x_sets_hidden_host(ircd_network, services):
    """U:lined server sending OPMODE +x should set the user's hidden host.

    This is the core feature PR #62 adds. Before the PR, ms_opmode
    only handles +o/-o and ignores +x. With the PR, +x is handled
    and the user gets FLAG_HIDDENHOST set.

    We also need to set the user's account (via ACCOUNT) for the
    hidden host to actually activate (ircu2 requires both +x AND
    account for host hiding).
    """
    hub = ircd_network["hub"]

    # Connect a user to the hub
    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62a", "testuser", "Test User")

    # Observer on hub to WHOIS
    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("obs62a", "testuser", "Test User")

    try:
        # Get user's numnick from the services server's user table
        numnick = await services.wait_for_user("usr62a")

        # Get the user's host before any changes
        await observer.send("WHOIS usr62a")
        whois_before = await observer.collect_until("318", timeout=5.0)
        host_before = [m for m in whois_before if m.command == "311"]
        assert len(host_before) == 1
        original_host = host_before[0].params[3]

        # Services sets the user's account via ACCOUNT
        await services.send_account(numnick, "TestAccount")
        await asyncio.sleep(0.3)

        # Services sets +x on the user via OPMODE
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        # Check user received mode change notification
        # The user should see a MODE message with +x
        try:
            mode_msg = await user.wait_for("MODE", timeout=3.0)
            assert "x" in mode_msg.params[-1], (
                f"Expected +x in mode change: {mode_msg.params}"
            )
        except asyncio.TimeoutError:
            pytest.fail(
                "User did not receive MODE +x — OPMODE +x was likely "
                "ignored (base branch behavior, PR #62 not applied)"
            )

        # WHOIS should now show a hidden host
        await observer.send("WHOIS usr62a")
        whois_after = await observer.collect_until("318", timeout=5.0)
        host_after = [m for m in whois_after if m.command == "311"]
        assert len(host_after) == 1
        new_host = host_after[0].params[3]

        assert new_host != original_host, (
            f"Host should have changed after ACCOUNT + OPMODE +x: "
            f"still {original_host!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_remote_opmode_x_without_account(ircd_network, services):
    """OPMODE +x should be ignored without account, then work once account is set.

    The PR #62 implementation requires IsAccount(dptr) before applying +x.
    This test verifies both sides: first +x is silently ignored (no account),
    then after ACCOUNT is set, the same +x succeeds.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62b", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("obs62b", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62b")

        # Get original host
        await observer.send("WHOIS usr62b")
        whois_before = await observer.collect_until("318", timeout=5.0)
        host_before = [m for m in whois_before if m.command == "311"]
        original_host = host_before[0].params[3]

        # --- Phase 1: +x WITHOUT account should be ignored ---
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        # User should NOT get a MODE notification (no account = +x ignored)
        try:
            mode_msg = await user.wait_for("MODE", timeout=2.0)
            has_x = "x" in mode_msg.params[-1]
            assert not has_x, (
                f"User got MODE +x without account — should be ignored: "
                f"{mode_msg.params}"
            )
        except asyncio.TimeoutError:
            pass  # Expected: no MODE sent

        # Host should remain unchanged
        await observer.send("WHOIS usr62b")
        whois_after = await observer.collect_until("318", timeout=5.0)
        host_after = [m for m in whois_after if m.command == "311"]
        new_host = host_after[0].params[3]

        assert new_host == original_host, (
            f"Host should NOT change without account: "
            f"{original_host!r} -> {new_host!r}"
        )

        # --- Phase 2: set account, then +x should succeed ---
        await services.send_account(numnick, "TestAcct62b")
        await asyncio.sleep(0.3)

        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        try:
            mode_msg = await user.wait_for("MODE", timeout=3.0)
            assert "x" in mode_msg.params[-1], (
                f"Expected +x after account was set: {mode_msg.params}"
            )
        except asyncio.TimeoutError:
            pytest.fail(
                "User did not receive MODE +x after account was set — "
                "OPMODE +x should work once IsAccount is true"
            )

        # Host should now be hidden
        await observer.send("WHOIS usr62b")
        whois_final = await observer.collect_until("318", timeout=5.0)
        host_final = [m for m in whois_final if m.command == "311"]
        final_host = host_final[0].params[3]

        assert final_host != original_host, (
            f"Host should be hidden after ACCOUNT + OPMODE +x: "
            f"still {original_host!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_account_rejected_from_non_ulined_server(ircd_network):
    """ACCOUNT from a non-U:lined server should be rejected with ERR_NOPRIVILEGES.

    This is the second change in PR #62: ms_account now checks for a
    CONF_UWORLD entry before accepting ACCOUNT. A server without a
    UWorld block should get 481 back and the user's account should
    not be set.
    """
    hub = ircd_network["hub"]

    # Connect a non-U:lined fake server (has Connect block but no UWorld)
    rogue = P10Server(
        name="notulined.test.net",
        numeric=5,
        password="testpass",
    )
    await rogue.connect(hub["host"], hub["server_port"])
    await rogue.handshake()

    # Connect a user to the hub
    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62d", "testuser", "Test User")

    # Observer to check WHOIS
    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("obs62d", "testuser", "Test User")

    try:
        numnick = await rogue.wait_for_user("usr62d")

        # Non-U:lined server tries to set ACCOUNT
        await rogue.send_account(numnick, "HackedAcct")
        await asyncio.sleep(0.5)

        # Drain messages from the rogue server — should see 481
        await rogue.drain_messages(timeout=1.0)
        got_denied = any("481" in line for line in rogue.received)

        assert got_denied, (
            "Non-U:lined server did not get ERR_NOPRIVILEGES for ACCOUNT — "
            "the U:line restriction from PR #62 may not be applied"
        )

        # Verify the user does NOT have an account set
        await observer.send("WHOIS usr62d")
        whois = await observer.collect_until("318", timeout=5.0)
        acct_replies = [m for m in whois if m.command == "330"]
        assert len(acct_replies) == 0, (
            f"User should NOT have an account from non-U:lined server: "
            f"{acct_replies[0].params if acct_replies else 'none'}"
        )
    finally:
        await rogue.disconnect()
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_remote_opmode_o_still_works(ircd_network, services):
    """OPMODE +o from U:lined server should still work (regression test).

    The existing +o functionality must not break when +x support is added.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62c", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62c")

        # Services opers the user via OPMODE +o
        await services.send_opmode(numnick, "+o")
        await asyncio.sleep(0.5)

        # User should see the mode change
        mode_msg = await user.wait_for("MODE", timeout=3.0)
        assert "o" in mode_msg.params[-1], (
            f"Expected +o in mode change: {mode_msg.params}"
        )

        # Verify user is now an oper by checking MODE response
        await user.send(f"MODE usr62c")
        umode = await user.wait_for("221", timeout=3.0)
        assert "o" in umode.params[-1], (
            f"User should be oper after OPMODE +o: {umode.params}"
        )
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()
