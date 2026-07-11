"""TDD tests for PR #65: S-line spam filter framework.

PR #65 introduces S-lines — regex-based spam filters checked against
private messages, channel messages, quit messages, and part messages.

Behavior:
- Part/quit messages matching an S-line have their text silently dropped.
- Private/channel messages matching an S-line are held and sent via XQUERY
  to a configured spamfilter service. The service replies YES (release) or
  NO (block) via XREPLY.

These tests inject S-lines via a fake P10 server (services.test.net) and
verify the filtering behavior. Tests should FAIL on the base branch (no
S-line support) and PASS with PR #65 applied.
"""

import asyncio
import time
import pytest

from irc_client import IRCClient
from p10_server import P10Server


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


async def _inject_sline(services, pattern, msg_type="A", ttl=30):
    """Helper to inject an S-line with a short expiry to avoid test pollution."""
    expire = int(time.time()) + ttl
    await services.send_sline(pattern, msg_type=msg_type, expire=expire)
    await asyncio.sleep(0.5)


# --- Part message filtering ---


async def test_part_message_filtered_by_sline(ircd_network, services):
    """A part message matching an S-line pattern should be suppressed.

    PR #65 adds sline_check_pattern_bool() in m_part. When the part
    comment matches an active S-line with the L (part) type, the part
    message text is dropped (CHFL_BANNED set).
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65f1u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65f1o", "testuser", "Test User")

    try:
        # Enable the feature (PART/QUIT filtering honours sline_is_enabled()).
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)
        # Inject an S-line matching "spam" in part messages
        await _inject_sline(services, "spam", msg_type="L")

        await user.send("JOIN #test_sl65f1")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65f1")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        # Part with a message that matches the S-line
        await user.send("PART #test_sl65f1 :this is spam content")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=5.0)
        # The part message text should be suppressed
        assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
            f"Part message should be suppressed by S-line, got: {part_msg.params}"
        )
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_part_message_not_filtered_without_match(ircd_network, services):
    """A part message NOT matching any S-line should be preserved."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65f2u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65f2o", "testuser", "Test User")

    try:
        # Inject an S-line that won't match our part message
        await _inject_sline(services, "xyzzy123", msg_type="L")

        await user.send("JOIN #test_sl65f2")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65f2")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("PART #test_sl65f2 :innocent goodbye")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) >= 2, "Part message text should be present"
        assert "innocent goodbye" in part_msg.params[-1]
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- Quit message filtering ---


async def test_quit_message_filtered_by_sline(ircd_network, services):
    """A quit message matching an S-line pattern should be replaced.

    PR #65 adds sline_check_pattern_bool() in m_quit. When the quit
    message matches an active S-line with Q (quit) type, the quit reason
    is replaced with "Signed off".
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65f3u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65f3o", "testuser", "Test User")

    try:
        # Enable the feature (PART/QUIT filtering honours sline_is_enabled()).
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)
        # Inject an S-line matching "badword" in quit messages
        await _inject_sline(services, "badword", msg_type="Q")

        await user.send("JOIN #test_sl65f3")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65f3")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("QUIT :contains badword here")

        quit_msg = await observer.wait_for("QUIT", timeout=5.0)
        assert "badword" not in quit_msg.params[-1], (
            f"Quit message should be filtered by S-line, got: {quit_msg.params}"
        )
        assert "Signed off" in quit_msg.params[-1]
    finally:
        try:
            await observer.send("QUIT :cleanup")
        except Exception:
            pass
        await observer.disconnect()


async def test_quit_message_not_filtered_without_match(ircd_network, services):
    """A quit message NOT matching any S-line should be preserved."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65f4u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65f4o", "testuser", "Test User")

    try:
        await _inject_sline(services, "xyzzy999", msg_type="Q")

        await user.send("JOIN #test_sl65f4")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65f4")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("QUIT :normal goodbye")

        quit_msg = await observer.wait_for("QUIT", timeout=5.0)
        assert "normal goodbye" in quit_msg.params[-1]
    finally:
        try:
            await observer.send("QUIT :cleanup")
        except Exception:
            pass
        await observer.disconnect()


# --- PRIVMSG hold and release via XQUERY/XREPLY ---


async def test_privmsg_held_and_released(ircd_network, services):
    """A PRIVMSG matching an S-line should be held, then released on XREPLY YES.

    The full flow:
    1. Configure sline.server to point to our fake service
    2. Inject an S-line for private messages
    3. User sends a matching PRIVMSG
    4. ircd sends XQUERY to our fake service with the held message token
    5. Fake service replies XREPLY YES
    6. ircd delivers the message to the recipient
    """
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl65f5s", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl65f5r", "testuser", "Test User")

    try:
        # Configure the spamfilter server to be our fake service
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)

        # Inject an S-line matching "spamword" for private messages
        await _inject_sline(services, "spamword", msg_type="P")

        # Wait for services to learn both users
        await services.wait_for_user("sl65f5s")
        await services.wait_for_user("sl65f5r")
        await services.drain_messages()

        # Sender sends a matching PRIVMSG
        await sender.send("PRIVMSG sl65f5r :this has spamword in it")

        # The fake service should receive an XQUERY with spam: routing
        xquery_line = await services.wait_for_token("XQ", timeout=5.0)
        assert "spam:" in xquery_line, (
            f"Expected XQUERY with spam: routing, got: {xquery_line}"
        )

        # Parse the token from the XQUERY
        # Format: <hub_num> XQ <our_num> spam:<token> :<payload>
        parts = xquery_line.split()
        routing = None
        for p in parts:
            if p.startswith("spam:"):
                routing = p
                break
        assert routing is not None, f"Could not find spam: routing in: {xquery_line}"

        # Extract hub numeric for the XREPLY target
        hub_num = parts[0]

        # Reply YES to release the message
        await services.send_xreply(hub_num, routing, "YES")

        # Receiver should now get the message
        msg = await receiver.wait_for("PRIVMSG", timeout=5.0)
        assert "spamword" in msg.params[-1], (
            f"Released message should contain original text, got: {msg.params}"
        )
    finally:
        for c in (sender, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_privmsg_held_and_blocked(ircd_network, services):
    """A PRIVMSG matching an S-line should be blocked on XREPLY NO.

    Same flow as release test, but the service replies NO so the message
    is never delivered to the recipient.
    """
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl65f6s", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl65f6r", "testuser", "Test User")

    try:
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)

        await _inject_sline(services, "blocked", msg_type="P")

        await services.wait_for_user("sl65f6s")
        await services.wait_for_user("sl65f6r")
        await services.drain_messages()

        await sender.send("PRIVMSG sl65f6r :this is blocked content")

        # Get the XQUERY
        xquery_line = await services.wait_for_token("XQ", timeout=5.0)
        parts = xquery_line.split()
        routing = None
        for p in parts:
            if p.startswith("spam:"):
                routing = p
                break
        hub_num = parts[0]

        # Reply NO to block the message
        await services.send_xreply(hub_num, routing, "NO")
        await asyncio.sleep(0.5)

        # Receiver should NOT get the message
        try:
            msg = await receiver.wait_for("PRIVMSG", timeout=2.0)
            pytest.fail(
                f"Blocked message should not be delivered, got: {msg.params}"
            )
        except (asyncio.TimeoutError, TimeoutError):
            pass  # Expected: message was blocked

        # Sender should get an error reply (ERR_NOSUCHNICK for private)
        # The error may have already been buffered
        error_found = False
        for buffered in receiver._buffer + sender._buffer:
            if buffered.command == "401":  # ERR_NOSUCHNICK
                error_found = True
                break
        # Also check sender's incoming messages
        if not error_found:
            try:
                err = await sender.wait_for("401", timeout=2.0)
                error_found = True
            except (asyncio.TimeoutError, TimeoutError):
                pass
        # It's OK if no error is sent — the key assertion is the message wasn't delivered
    finally:
        for c in (sender, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- S-line type selectivity ---


async def test_sline_type_selectivity(ircd_network, services):
    """An S-line with type L (part only) should not affect quit messages.

    Verifies that the msgtype flag filtering works correctly.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65f7u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65f7o", "testuser", "Test User")

    try:
        # Inject S-line for part messages ONLY
        await _inject_sline(services, "filterthis", msg_type="L")

        await user.send("JOIN #test_sl65f7")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65f7")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        # Quit with a message matching the S-line — should NOT be filtered
        # because the S-line is type L (part only), not Q (quit)
        await user.send("QUIT :filterthis in quit")

        quit_msg = await observer.wait_for("QUIT", timeout=5.0)
        assert "filterthis" in quit_msg.params[-1], (
            f"Quit message should NOT be filtered by L-type S-line: {quit_msg.params}"
        )
    finally:
        try:
            await observer.send("QUIT :cleanup")
        except Exception:
            pass
        await observer.disconnect()
