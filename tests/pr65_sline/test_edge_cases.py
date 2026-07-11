"""Edge case tests for PR #65: S-line spam filter framework.

Adversarial tests that try to break the S-line implementation by testing
boundary conditions, interactions with other features, and unusual inputs.
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


# --- Part message edge cases ---


async def test_part_no_message_with_sline_active(ircd_network, services):
    """Part with no message should not crash when S-lines are active.

    sline_check_pattern_bool is called with jb_comment which may be NULL
    when no part message is provided.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65e1u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e1o", "testuser", "Test User")

    try:
        await _inject_sline(services, "nullsafety1", msg_type="L")

        await user.send("JOIN #test_sl65e1")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65e1")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        # Part with no message at all
        await user.send("PART #test_sl65e1")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=3.0)
        assert "#test_sl65e1" in part_msg.params[0]
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_part_empty_message_with_sline_active(ircd_network, services):
    """Part with empty message should not crash with S-lines active."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65e2u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e2o", "testuser", "Test User")

    try:
        await _inject_sline(services, "nullsafety2", msg_type="L")

        await user.send("JOIN #test_sl65e2")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65e2")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("PART #test_sl65e2 :")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=3.0)
        assert "#test_sl65e2" in part_msg.params[0]
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_part_regex_metacharacters_in_message(ircd_network, services):
    """Part message with regex metacharacters should be handled safely.

    The S-line uses POSIX extended regex. A part message full of
    metacharacters should not cause regex errors or crashes.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65e3u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e3o", "testuser", "Test User")

    try:
        # A simple S-line that shouldn't match metacharacters literally
        await _inject_sline(services, "^exactmatch$", msg_type="L")

        await user.send("JOIN #test_sl65e3")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65e3")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        # Part with regex metacharacters — should NOT match ^exactmatch$
        await user.send("PART #test_sl65e3 :test.*+?[]{}()\\^$|end")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=3.0)
        assert len(part_msg.params) >= 2, "Non-matching part should keep text"
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_part_multi_channel_with_sline(ircd_network, services):
    """Multi-channel PART should filter message for all channels.

    m_part checks sline_check_pattern_bool once before the channel loop.
    If it matches, all channels in the PART should have text suppressed.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65e4u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e4o", "testuser", "Test User")

    try:
        await _inject_sline(services, "filtermulti", msg_type="L")

        for chan in ("#test_sl65e4a", "#test_sl65e4b"):
            await user.send(f"JOIN {chan}")
            await user.wait_for("366")
            await observer.send(f"JOIN {chan}")
            await observer.wait_for("366")
            await user.wait_for("JOIN")

        await user.send("PART #test_sl65e4a,#test_sl65e4b :filtermulti msg")

        part1 = await observer.wait_for("PART", timeout=5.0)
        part2 = await observer.wait_for("PART", timeout=5.0)

        for p in (part1, part2):
            assert len(p.params) == 1 or p.params[-1] == "", (
                f"Part msg should be filtered for {p.params[0]}: {p.params}"
            )
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- Quit message edge cases ---


async def test_quit_no_message_with_sline_active(ircd_network, services):
    """Quit with no message should be safe with S-lines active.

    m_quit guards with parc > 1 before calling sline_check_pattern_bool.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65e5u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e5o", "testuser", "Test User")

    try:
        await _inject_sline(services, "nullsafety3", msg_type="Q")

        await user.send("JOIN #test_sl65e5")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65e5")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("QUIT")

        quit_msg = await observer.wait_for("QUIT", timeout=5.0)
        assert quit_msg is not None
    finally:
        try:
            await observer.send("QUIT :cleanup")
        except Exception:
            pass
        await observer.disconnect()


# --- S-line deactivation ---


async def test_deactivated_sline_does_not_filter(ircd_network, services):
    """A deactivated S-line (sent with -) should not filter messages.

    The SLINE protocol supports + (activate) and - (deactivate).
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65e6u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e6o", "testuser", "Test User")

    try:
        # First activate, then deactivate (newer lastmod)
        now = int(time.time())
        await services.send_sline("deacttest", msg_type="L", active=True, lastmod=now)
        await asyncio.sleep(0.3)
        await services.send_sline("deacttest", msg_type="L", active=False, lastmod=now + 1)
        await asyncio.sleep(0.3)

        await user.send("JOIN #test_sl65e6")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65e6")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("PART #test_sl65e6 :deacttest in message")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) >= 2, (
            "Part msg should NOT be filtered by deactivated S-line"
        )
        assert "deacttest" in part_msg.params[-1]
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- Oper exemption ---


async def test_oper_exempt_from_privmsg_sline(ircd_network, services):
    """Opers should be exempt from S-line PRIVMSG filtering.

    sline_check_privmsg returns 0 (no filter) when IsAnOper(sender).
    """
    hub = ircd_network["hub"]

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("sl65e7o", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl65e7r", "testuser", "Test User")

    try:
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)
        await _inject_sline(services, "operspam", msg_type="P")

        # Oper up
        await oper.send("OPER testoper operpass")
        await oper.wait_for("381", timeout=5.0)
        await asyncio.sleep(0.5)

        await services.wait_for_user("sl65e7r")
        await services.drain_messages()

        # Oper sends a matching PRIVMSG — should NOT be held
        await oper.send("PRIVMSG sl65e7r :this has operspam in it")

        msg = await receiver.wait_for("PRIVMSG", timeout=5.0)
        assert "operspam" in msg.params[-1], (
            f"Oper message should bypass S-line filter: {msg.params}"
        )
    finally:
        for c in (oper, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- Channel message hold and release ---


async def test_channel_msg_held_and_released(ircd_network, services):
    """A channel PRIVMSG matching an S-line should be held then released.

    Same XQUERY/XREPLY flow as private messages but for channel messages.
    """
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl65e8s", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl65e8r", "testuser", "Test User")

    try:
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)
        await _inject_sline(services, "chanspam", msg_type="C")

        await sender.send("JOIN #test_sl65e8")
        await sender.wait_for("366")
        await receiver.send("JOIN #test_sl65e8")
        await receiver.wait_for("366")
        await sender.wait_for("JOIN")

        await services.wait_for_user("sl65e8s")
        await services.drain_messages()

        await sender.send("PRIVMSG #test_sl65e8 :this is chanspam yo")

        # Fake service receives XQUERY
        xquery_line = await services.wait_for_token("XQ", timeout=5.0)
        assert "spam:" in xquery_line

        parts = xquery_line.split()
        routing = next(p for p in parts if p.startswith("spam:"))
        hub_num = parts[0]

        # Release the message
        await services.send_xreply(hub_num, routing, "YES")

        msg = await receiver.wait_for("PRIVMSG", timeout=5.0)
        assert "chanspam" in msg.params[-1]
    finally:
        for c in (sender, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- S-line propagation across servers ---


async def test_sline_propagates_to_leaf(ircd_network, services):
    """S-lines injected via hub should propagate to leaf servers.

    sline_burst() sends all S-lines to newly connecting servers,
    and ms_sline propagates via sendcmdto_serv_butone.

    We verify by checking that a part message on leaf1 is also filtered
    by an S-line injected through the hub.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    # User on leaf1
    user = IRCClient()
    await user.connect(leaf1["host"], leaf1["port"])
    await user.register("sl65e9u", "testuser", "Test User")

    # Observer on hub (different server)
    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65e9o", "testuser", "Test User")

    try:
        await _inject_sline(services, "crossfilter", msg_type="L")

        await user.send("JOIN #test_sl65e9")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65e9")
        await observer.wait_for("366")
        # Wait for cross-server JOIN propagation
        await asyncio.sleep(1.0)

        await user.send("PART #test_sl65e9 :crossfilter in part msg")
        await user.wait_for("PART")

        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
            f"S-line should propagate to leaf and filter part: {part_msg.params}"
        )
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --- STATS s ---


async def test_sline_removed_by_short_expiry(ircd_network, services):
    """A .* S-line with no expiry can be removed by re-sending with a short expiry.

    This is the only way to clean up a rogue S-line in production:
    re-activate the same pattern with a newer lastmod and a short expire.
    Once the expire passes, sline_free() removes it from GlobalSlineList.

    The test:
    1. Inject .* with expire=0 (permanent) — part messages are filtered
    2. Re-send .* with expire=now+2 and newer lastmod — updates the expire
    3. Wait for expiry
    4. Verify part messages flow normally again (S-line was freed)
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65eBu", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65eBo", "testuser", "Test User")

    try:
        now = int(time.time())

        # Step 1: Inject permanent .* S-line
        await services.send_sline(".*", msg_type="L", active=True,
                                  expire=0, lastmod=now)
        await asyncio.sleep(0.5)

        await user.send("JOIN #test_sl65eB")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65eB")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        # Confirm it's filtering
        await user.send("PART #test_sl65eB :should be filtered")
        await user.wait_for("PART")
        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
            f"Permanent .* should filter part text: {part_msg.params}"
        )

        # Step 2: Re-send with short expiry (2 seconds) and newer lastmod
        await services.send_sline(".*", msg_type="L", active=True,
                                  expire=now + 2, lastmod=now + 1)

        # Step 3: Wait for expiry
        await asyncio.sleep(3)

        # Step 4: Rejoin and verify part messages flow again
        await user.send("JOIN #test_sl65eB")
        await user.wait_for("366")
        await observer.wait_for("JOIN")

        await user.send("PART #test_sl65eB :should be visible now")
        await user.wait_for("PART")
        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) >= 2, (
            "After S-line expiry, part text should be visible again"
        )
        assert "should be visible now" in part_msg.params[-1], (
            f"Part text not restored after expiry: {part_msg.params}"
        )
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_permanent_sline_can_be_expired(ircd_network, services):
    """A .* S-line with expire=0 (permanent) must be removable.

    The only way to delete a permanent S-line is to re-send the same
    pattern with a newer lastmod and a short expire. This updates
    sl_expire from 0 to a real timestamp, and once it passes,
    sline_free() removes it from GlobalSlineList.

    If this test fails, there is NO way to recover from a rogue
    permanent .* S-line — it filters all messages forever.
    """
    hub = ircd_network["hub"]
    now = int(time.time())

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl65dlu", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl65dlo", "testuser", "Test User")

    try:
        # Inject permanent .* S-line (expire=0)
        await services.send_sline(".*", msg_type="L", active=True,
                                  expire=0, lastmod=now)
        await asyncio.sleep(0.5)

        await user.send("JOIN #test_sl65dl")
        await user.wait_for("366")
        await observer.send("JOIN #test_sl65dl")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        # Confirm it's filtering
        await user.send("PART #test_sl65dl :filtered")
        await user.wait_for("PART")
        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) == 1 or part_msg.params[-1] == "", (
            f"Permanent .* should filter part text: {part_msg.params}"
        )

        # Re-send same pattern with newer lastmod and expire=2s from now
        await services.send_sline(".*", msg_type="L", active=True,
                                  expire=int(time.time()) + 2, lastmod=now + 1)
        await asyncio.sleep(3)

        # Rejoin and verify the S-line is gone
        await user.send("JOIN #test_sl65dl")
        await user.wait_for("366")
        await observer.wait_for("JOIN")

        await user.send("PART #test_sl65dl :visible again")
        await user.wait_for("PART")
        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) >= 2 and "visible again" in part_msg.params[-1], (
            f"After expiry, .* should be gone and part text visible: {part_msg.params}"
        )
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_redos_pattern_does_not_hang_server(ircd_network, services):
    """A pathological regex like (a+)+$ must not hang the IRC server.

    POSIX regexec with REG_EXTENDED can use backtracking on some libc
    implementations. The pattern (a+)+$ causes exponential backtracking
    when matched against "aaa...ab". If the server doesn't reject or
    timeout this pattern, a single message can freeze the event loop.

    NOTE: glibc >= 2.30 uses a DFA-based engine that handles these
    patterns in constant time. This test serves as a regression guard
    in case the build environment changes to a vulnerable libc.
    """
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl65rds", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl65rdr", "testuser", "Test User")

    # A third client to probe server liveness
    probe = IRCClient()
    await probe.connect(hub["host"], hub["port"])
    await probe.register("sl65rdp", "testuser", "Test User")

    try:
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)

        # Inject the classic ReDoS pattern for PART messages (L type).
        # Using L type because it goes through sline_check_pattern_bool
        # which calls regexec inline — no XQUERY indirection.
        await _inject_sline(services, "(a+)+$", msg_type="L")

        await sender.send("JOIN #test_sl65rd")
        await sender.wait_for("366")
        await receiver.send("JOIN #test_sl65rd")
        await receiver.wait_for("366")
        await sender.wait_for("JOIN")

        # First, measure baseline latency with a PRIVMSG
        await probe.send("PRIVMSG sl65rdr :baseline")
        t0 = asyncio.get_event_loop().time()
        await receiver.wait_for("PRIVMSG", timeout=5.0)
        baseline = asyncio.get_event_loop().time() - t0

        # Send the poison string as a PART message — worst case for (a+)+$
        # With glibc's backtracking engine this is O(2^n).
        poison = "a" * 35 + "b"
        await sender.send(f"PART #test_sl65rd :{poison}")

        # Now immediately test if the server is still alive.
        # If regexec is hung on backtracking, this will timeout or be very slow.
        await probe.send("PRIVMSG sl65rdr :still alive?")
        t0 = asyncio.get_event_loop().time()
        msg = await receiver.wait_for("PRIVMSG", timeout=10.0)
        elapsed = asyncio.get_event_loop().time() - t0

        assert msg is not None, "Server became unresponsive after ReDoS pattern"
        assert elapsed < baseline + 2.0, (
            f"Server took {elapsed:.1f}s to respond after ReDoS payload "
            f"(baseline {baseline:.3f}s) — regexec is likely backtracking"
        )

    finally:
        for c in (sender, receiver, probe):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_hold_queue_flood(ircd_network, services):
    """Flooding matching messages should not cause unbounded queue growth.

    Without a hold queue size limit, an attacker can exhaust server memory.
    Each held message allocates a HoldQueueEntry + DupString of the text.
    The timeout timer fires every 10s, hold timeout defaults to 60s, so
    entries accumulate with no cap.

    ircd has per-client target throttling that limits one client to ~3
    messages before being rate-limited. But an attacker can use many
    clients — each gets a fresh target budget. This test uses 20 senders,
    each sending a few matching PRIVMSGs, to bypass the per-client limit
    and demonstrate unbounded queue growth.
    """
    hub = ircd_network["hub"]
    num_senders = 20
    msgs_per_sender = 3  # stay within target limit per client

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl65flr", "testuser", "Test User")

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("sl65flo", "testuser", "Test User")

    senders = []
    try:
        await services.send_config("sline.server", "services.test.net")
        await asyncio.sleep(0.3)
        await _inject_sline(services, "floodme", msg_type="P")

        await services.wait_for_user("sl65flr")

        # Oper up to read STATS s
        await oper.send("OPER testoper operpass")
        await oper.wait_for("381", timeout=5.0)
        await asyncio.sleep(0.5)
        while oper._buffer:
            oper._buffer.pop(0)

        # Get baseline held count
        await oper.send("STATS s")
        baseline_msgs = await oper.collect_until("219", timeout=5.0)
        baseline_held = 0
        for m in baseline_msgs:
            if m.command == "240":
                text = " ".join(m.params)
                if "Messages Held" in text:
                    try:
                        baseline_held = int(text.split("Messages Held:")[-1].strip())
                    except ValueError:
                        pass

        # Spawn many senders, each sends a few matching messages
        total_sent = 0
        for s in range(num_senders):
            sender = IRCClient()
            await sender.connect(hub["host"], hub["port"])
            await sender.register(f"sl65f{s:02d}", "testuser", "Test User")
            senders.append(sender)

            await services.wait_for_user(f"sl65f{s:02d}")

            for m in range(msgs_per_sender):
                try:
                    await sender.send(f"PRIVMSG sl65flr :floodme msg {s}-{m}")
                    total_sent += 1
                except ConnectionResetError:
                    break
            await asyncio.sleep(0.1)

        # Drain XQUERY messages (we never reply — simulating dead spamfilter)
        await services.drain_messages(timeout=1.0)

        # Server should still be responsive
        await oper.send("PING :alive")
        pong = await oper.wait_for("PONG", timeout=5.0)
        assert pong is not None, "Server became unresponsive after flood"

        # Check held count after flood
        while oper._buffer:
            oper._buffer.pop(0)
        await oper.send("STATS s")
        flood_msgs = await oper.collect_until("219", timeout=5.0)
        flood_held = 0
        for m in flood_msgs:
            if m.command == "240":
                text = " ".join(m.params)
                if "Messages Held" in text:
                    try:
                        flood_held = int(text.split("Messages Held:")[-1].strip())
                    except ValueError:
                        pass

        new_held = flood_held - baseline_held

        # We expect all messages to be queued — proving no limit exists.
        # If a queue limit is added, new_held will plateau below total_sent,
        # and this assertion should be changed to verify the cap works.
        assert total_sent >= num_senders, f"Flood underperformed: only sent {total_sent}"
        assert new_held >= total_sent * 0.8, (
            f"Expected ~{total_sent} messages held, got {new_held}. "
            f"If significantly less, a queue limit may exist (good!) — "
            f"update this test to verify the cap."
        )

    finally:
        for c in senders + [receiver, oper]:
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_stats_s_shows_active_slines(ircd_network, services):
    """STATS s should show active S-lines to opers."""
    hub = ircd_network["hub"]

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("sl65eAo", "testuser", "Test User")

    try:
        await _inject_sline(services, "visible_pattern", msg_type="PC")

        await oper.send("OPER testoper operpass")
        await oper.wait_for("381", timeout=5.0)
        await asyncio.sleep(0.5)
        # Drain oper notices
        while oper._buffer:
            oper._buffer.pop(0)

        await oper.send("STATS s")
        msgs = await oper.collect_until("219", timeout=5.0)

        sline_replies = [m for m in msgs if m.command == "240"]
        assert len(sline_replies) > 0, (
            f"Oper should see S-line stats, got: {[m.command for m in msgs]}"
        )

        # The pattern should appear in one of the replies
        all_text = " ".join(str(m.params) for m in sline_replies)
        assert "visible_pattern" in all_text, (
            f"S-line pattern not found in stats output: {all_text}"
        )
    finally:
        try:
            await oper.send("QUIT :cleanup")
        except Exception:
            pass
        await oper.disconnect()
