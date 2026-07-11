"""Regression tests for bugs found in the PR #65 S-line review.

Each test targets a specific defect from the security/code review. They are
written to FAIL against the unfixed branch and PASS once the corresponding
fix is applied.

Covered:
- H1: double-free in the hold-timeout release path (crash).
- M1: message held for the full timeout when the spam server is unlinked
      (should fail open and deliver immediately).
- M4: PART/QUIT filtering ignores the feature kill-switch and the oper
      exemption that the message paths apply.
- M5: an approved held NOTICE is delivered with a broken verb because the
      two-argument CMD_NOTICE/CMD_PRIVATE macros are misused inside a ternary.

All tests drive the daemon through a fake P10 services server
(services.test.net), which is U-lined in the docker hub config.
"""

import asyncio
import time

import pytest

from irc_client import IRCClient
from p10_server import P10Server

pytestmark = pytest.mark.multi_server

SLINE_SERVER = "services.test.net"


@pytest.fixture
async def services(ircd_network):
    """Connect a fake P10 services server to the hub."""
    hub = ircd_network["hub"]
    srv = P10Server(name=SLINE_SERVER, numeric=4, password="testpass")
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


async def _enable_sline(services, server_name=SLINE_SERVER):
    """Point the network's spamfilter at server_name and let it propagate."""
    await services.send_config("sline.server", server_name)
    await asyncio.sleep(0.3)


def _routing_from_xquery(xquery_line):
    """Pull the 'spam:<token>' routing token and hub numeric from an XQUERY."""
    parts = xquery_line.split()
    routing = next((p for p in parts if p.startswith("spam:")), None)
    return parts[0], routing


async def _wait_command_containing(client, command, needle, timeout=5.0):
    """Wait for a <command> message whose last param contains needle.

    Unrelated server notices may arrive first, so scan rather than taking
    the first matching command.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError(f"no {command} containing {needle!r}")
        msg = await client.wait_for(command, timeout=remaining)
        if msg.params and needle in msg.params[-1]:
            return msg


# --------------------------------------------------------------------------
# M5 - approved held NOTICE must be delivered as a NOTICE, not a broken verb
# --------------------------------------------------------------------------


async def test_held_notice_released_as_notice(ircd_network, services):
    """A held NOTICE released via XREPLY YES must arrive as a real NOTICE.

    Bug M5: sline_release_privmsg uses the two-arg macros CMD_NOTICE /
    CMD_PRIVATE inside a ternary, which expands so the NOTICE branch sends
    the P10 token "O" as the client-facing verb. Pre-fix the recipient
    never sees a NOTICE; post-fix it does.
    """
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl_m5s", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl_m5r", "testuser", "Test User")

    try:
        await _enable_sline(services)
        await services.send_sline("noticespam", msg_type="P",
                                  expire=int(time.time()) + 30)
        await asyncio.sleep(0.5)

        await services.wait_for_user("sl_m5s")
        await services.wait_for_user("sl_m5r")
        await services.drain_messages()

        # Send a NOTICE (not PRIVMSG) that matches the S-line.
        await sender.send("NOTICE sl_m5r :this noticespam should be held")

        xquery_line = await services.wait_for_token("XQ", timeout=5.0)
        hub_num, routing = _routing_from_xquery(xquery_line)
        assert routing is not None, f"no spam: routing in {xquery_line!r}"

        await services.send_xreply(hub_num, routing, "YES")

        # Must arrive as a NOTICE (pre-fix the verb was the bare token "O").
        msg = await _wait_command_containing(receiver, "NOTICE", "noticespam",
                                             timeout=5.0)
        assert "noticespam" in msg.params[-1], (
            f"released NOTICE should carry original text, got {msg.params}"
        )
    finally:
        for c in (sender, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --------------------------------------------------------------------------
# M1 - fail open when the configured spam server is not linked
# --------------------------------------------------------------------------


async def test_message_delivered_when_spamserver_unlinked(ircd_network, services):
    """If the spamfilter server is configured but not linked, a matching
    message must be delivered immediately rather than held.

    Bug/improvement M1: with an unlinked spam server the message is queued
    and (default policy) blocked only after the full hold timeout. Post-fix
    it fails open and is delivered right away.
    """
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl_m1s", "testuser", "Test User")

    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl_m1r", "testuser", "Test User")

    try:
        # Point the spamfilter at a server name that is NOT linked.
        await _enable_sline(services, server_name="ghost.unlinked.test")
        await services.send_sline("orphanspam", msg_type="P",
                                  expire=int(time.time()) + 30)
        await asyncio.sleep(0.5)

        await sender.send("PRIVMSG sl_m1r :this orphanspam has nowhere to go")

        # Post-fix the message is delivered promptly (fail open).
        msg = await receiver.wait_for("PRIVMSG", timeout=5.0)
        assert "orphanspam" in msg.params[-1], (
            f"message should be delivered when spam server is unlinked, "
            f"got {msg.params}"
        )
    finally:
        # Restore a linked spam server for subsequent tests.
        try:
            await services.send_config("sline.server", SLINE_SERVER)
        except Exception:
            pass
        for c in (sender, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


# --------------------------------------------------------------------------
# M4 - PART/QUIT filtering must honour the kill-switch and oper exemption
# --------------------------------------------------------------------------


async def test_part_not_filtered_when_feature_disabled(ircd_network, services):
    """With no spam server configured the feature is disabled, so a PART
    comment matching an S-line must NOT be suppressed.

    Bug M4: sline_check_pattern_bool (PART/QUIT) skips sline_is_enabled(),
    so filtering happened even with the feature off.
    """
    hub = ircd_network["hub"]

    # Disable the feature network-wide (delete the spam server setting).
    await services.send_config("sline.server", "")
    await asyncio.sleep(0.3)
    await services.send_sline("disabledpart", msg_type="L",
                              expire=int(time.time()) + 30)
    await asyncio.sleep(0.5)

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("sl_m4a", "testuser", "Test User")
    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl_m4b", "testuser", "Test User")

    try:
        await user.send("JOIN #m4disabled")
        await user.wait_for("366")
        await observer.send("JOIN #m4disabled")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await user.send("PART #m4disabled :leaving with disabledpart text")
        part_msg = await observer.wait_for("PART", timeout=5.0)
        assert len(part_msg.params) >= 2 and "disabledpart" in part_msg.params[-1], (
            f"PART must not be filtered when feature disabled, got {part_msg.params}"
        )
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_oper_quit_not_filtered(ircd_network, services):
    """An oper's QUIT matching an S-line must NOT be filtered.

    Bug M4: the message paths exempt opers (IsAnOper) but the PART/QUIT
    path did not, so an oper's quit reason was replaced with "Signed off".
    """
    hub = ircd_network["hub"]
    await _enable_sline(services)
    await services.send_sline("operquitword", msg_type="Q",
                              expire=int(time.time()) + 30)
    await asyncio.sleep(0.5)

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("sl_m4op", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("sl_m4ob", "testuser", "Test User")

    try:
        # Oper up (see docker/ircd-hub.conf Operator block).
        await oper.send("OPER testoper operpass")
        await oper.wait_for("381", timeout=5.0)  # RPL_YOUREOPER

        await oper.send("JOIN #m4oper")
        await oper.wait_for("366")
        await observer.send("JOIN #m4oper")
        await observer.wait_for("366")
        await oper.wait_for("JOIN")

        await oper.send("QUIT :bye with operquitword inside")
        quit_msg = await observer.wait_for("QUIT", timeout=5.0)
        assert "operquitword" in quit_msg.params[-1], (
            f"oper QUIT must be exempt from S-line filtering, got {quit_msg.params}"
        )
    finally:
        try:
            await observer.send("QUIT :cleanup")
        except Exception:
            pass
        await observer.disconnect()
        await oper.disconnect()


# --------------------------------------------------------------------------
# H1 - double free in the hold-timeout release path must not crash the server
# --------------------------------------------------------------------------


async def test_no_crash_on_timeout_release_delivery_failure(ircd_network, services):
    """With release-on-timeout enabled, a held message whose delivery fails
    at release time must not crash the server.

    Bug H1: sline_release_hold() frees the entry unconditionally, then the
    timeout callback frees it again when release returns 0 (delivery failed,
    e.g. the recipient silenced the sender) -> double free / heap corruption.
    """
    hub = ircd_network["hub"]

    # Release (not block) on timeout, and a short hold so the periodic
    # 10s timer expires it well within the test budget.
    await _enable_sline(services)
    await services.send_config("sline.hold_timeout_block", "0")
    await services.send_config("sline.hold_timeout", "1")
    await asyncio.sleep(0.3)
    await services.send_sline("timeoutspam", msg_type="P",
                              expire=int(time.time()) + 60)
    await asyncio.sleep(0.5)

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("sl_h1s", "testuser", "Test User")
    receiver = IRCClient()
    await receiver.connect(hub["host"], hub["port"])
    await receiver.register("sl_h1r", "testuser", "Test User")

    try:
        await services.wait_for_user("sl_h1s")
        await services.wait_for_user("sl_h1r")
        await services.drain_messages()

        # Send a matching message: it is held and an XQUERY is issued.
        await sender.send("PRIVMSG sl_h1r :here is some timeoutspam")
        await services.wait_for_token("XQ", timeout=5.0)

        # Make delivery fail at release time: recipient silences the sender.
        await receiver.send("SILENCE +sl_h1s!*@*")
        await asyncio.sleep(0.5)

        # Never reply; wait for the release-on-timeout path to run.
        await asyncio.sleep(13)

        # The server must still be alive: a fresh client can register and PING.
        probe = IRCClient()
        await probe.connect(hub["host"], hub["port"])
        await probe.register("sl_h1p", "testuser", "Test User")
        await probe.send("PING :alive?")
        await probe.wait_for("PONG", timeout=5.0)
        await probe.disconnect()
    finally:
        # Restore defaults for later tests.
        try:
            await services.send_config("sline.hold_timeout_block", "1")
            await services.send_config("sline.hold_timeout", "60")
        except Exception:
            pass
        for c in (sender, receiver):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
