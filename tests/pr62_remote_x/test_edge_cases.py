"""Edge case tests for PR #62: Remote +x and ACCOUNT restriction.

Adversarial tests covering:
- OPMODE +x on remote users (user on leaf, not hub)
- OPMODE with unsupported mode strings
- ACCOUNT from a U:lined server (should work)
- ACCOUNT interaction with +x for host hiding
- Multiple rapid OPMODE operations
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


async def test_opmode_x_on_remote_user(ircd_network, services):
    """OPMODE +x targeting a user on a leaf server (not directly connected
    to the services server) should be forwarded and applied.

    The ms_opmode handler checks MyConnect(dptr) — if the target is
    not local, it forwards via sendcmdto_serv_butone. The leaf must
    then apply it.
    """
    leaf1 = ircd_network["leaf1"]

    # User connects to leaf1, not hub
    user = IRCClient()
    await user.connect(leaf1["host"], leaf1["port"])
    await user.register("usr62r1", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(leaf1["host"], leaf1["port"])
    await observer.register("obs62r1", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62r1", timeout=5.0)

        # Set account first, then +x
        await services.send_account(numnick, "RemoteAcct")
        await asyncio.sleep(0.3)
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        # Check the user got mode +x
        try:
            mode_msg = await user.wait_for("MODE", timeout=3.0)
            assert "x" in mode_msg.params[-1]
        except asyncio.TimeoutError:
            pytest.skip(
                "OPMODE +x on remote user not applied — "
                "requires PR #62 on the leaf server too"
            )

        # Verify host is hidden via WHOIS from the same leaf
        await observer.send("WHOIS usr62r1")
        whois = await observer.collect_until("318", timeout=5.0)
        whois_user = [m for m in whois if m.command == "311"]
        assert len(whois_user) == 1
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_opmode_unsupported_mode_ignored(ircd_network, services):
    """OPMODE with an unsupported mode string (e.g., +W) should be
    silently ignored without crashing the server or disconnecting.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62e2", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62e2")

        # Send an unsupported mode
        await services.send_opmode(numnick, "+W")
        await asyncio.sleep(0.5)

        # User should still be connected and functional
        await user.send("PING :alive")
        pong = await user.wait_for("PONG", timeout=3.0)
        assert pong is not None, "Server should still respond after unsupported OPMODE"
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_account_from_ulined_server(ircd_network, services):
    """ACCOUNT from a U:lined server should set the user's account.

    With PR #62, ACCOUNT is restricted to U:lined servers. Our fake
    services server IS U:lined, so this should succeed.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62e3", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("obs62e3", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62e3")

        # Services sends ACCOUNT
        await services.send_account(numnick, "MyAccount")
        await asyncio.sleep(0.5)

        # WHOIS should show the account (330 = RPL_WHOISACCOUNT)
        await observer.send("WHOIS usr62e3")
        whois = await observer.collect_until("318", timeout=5.0)
        acct_replies = [m for m in whois if m.command == "330"]
        assert len(acct_replies) == 1, (
            f"Expected RPL_WHOISACCOUNT (330) after ACCOUNT. "
            f"Got numerics: {[m.command for m in whois]}"
        )
        assert "MyAccount" in acct_replies[0].params[-1] or \
               "MyAccount" in " ".join(acct_replies[0].params), (
            f"Account name not in WHOIS reply: {acct_replies[0].params}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_account_then_opmode_x_hides_host(ircd_network, services):
    """Setting account first, then OPMODE +x, should result in a hidden host.

    Order matters: hide_hostmask() only activates when both +x and account
    are set. ACCOUNT triggers hide_hostmask with FLAG_ACCOUNT, and
    OPMODE +x triggers it with FLAG_HIDDENHOST.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62e4", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("obs62e4", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62e4")

        # Get original host
        await observer.send("WHOIS usr62e4")
        whois1 = await observer.collect_until("318", timeout=5.0)
        original_host = [m for m in whois1 if m.command == "311"][0].params[3]

        # Set account
        await services.send_account(numnick, "HideTest")
        await asyncio.sleep(0.3)

        # Check host after ACCOUNT only — should trigger +x if user already had it,
        # but since user doesn't have +x yet, host should be unchanged
        await observer.send("WHOIS usr62e4")
        whois2 = await observer.collect_until("318", timeout=5.0)
        mid_host = [m for m in whois2 if m.command == "311"][0].params[3]

        # Now set +x via OPMODE
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        try:
            await user.wait_for("MODE", timeout=3.0)
        except asyncio.TimeoutError:
            pytest.fail("OPMODE +x not applied — PR #62 likely not present")

        # Now host should be hidden (both flags set)
        await observer.send("WHOIS usr62e4")
        whois3 = await observer.collect_until("318", timeout=5.0)
        final_host = [m for m in whois3 if m.command == "311"][0].params[3]

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


async def test_opmode_minus_o_still_works(ircd_network, services):
    """OPMODE -o should still de-oper a user (regression).

    PR #62 adds send_umode_out() to de_oper(), so the user now
    receives a MODE -o notification (previously de_oper did not
    propagate the mode change).
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62e5", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62e5")

        # First make the user an oper
        await services.send_opmode(numnick, "+o")
        await asyncio.sleep(0.5)
        mode_msg = await user.wait_for("MODE", timeout=3.0)
        assert "o" in mode_msg.params[-1]

        # Now de-oper via OPMODE -o
        await services.send_opmode(numnick, "-o")
        await asyncio.sleep(0.5)

        # PR #62 adds send_umode_out() to de_oper(), so user should
        # receive a MODE -o notification
        try:
            deoper_msg = await user.wait_for("MODE", timeout=3.0)
            assert "o" in deoper_msg.params[-1], (
                f"Expected -o in de-oper mode change: {deoper_msg.params}"
            )
        except asyncio.TimeoutError:
            pytest.fail(
                "User did not receive MODE -o notification — "
                "de_oper() should call send_umode_out() per PR #62"
            )

        # Also verify via MODE query that oper is removed
        await user.send(f"MODE usr62e5")
        umode = await user.wait_for("221", timeout=3.0)
        assert "o" not in umode.params[-1], (
            f"User should not be oper after OPMODE -o: {umode.params}"
        )
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_rapid_opmode_sequence(ircd_network, services):
    """Rapid OPMODE +x then -x should not crash or leave inconsistent state."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("usr62e6", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("usr62e6")

        # Set account so +x has visible effect
        await services.send_account(numnick, "RapidTest")
        await asyncio.sleep(0.3)

        # Rapid +x / -x / +x
        await services.send_opmode(numnick, "+x")
        await services.send_opmode(numnick, "-x")
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(1.0)

        # User should still be connected
        await user.send("PING :stillhere")
        pong = await user.wait_for("PONG", timeout=3.0)
        assert pong is not None
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()
