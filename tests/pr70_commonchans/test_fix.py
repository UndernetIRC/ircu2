"""TDD tests for PR #70: usermode +c (common channels).

Usermode +c makes a user accept private messages, notices and CTCPs
only from users that share at least one channel with them. Services
(+k) and IRC operators are exempt. Blocked messages are dropped
silently (no numeric to the sender, by design).

Issues found in review and reproduced here (these tests FAIL on the
unfixed PR branch):

1. Messages injected over a server-to-server link bypass +c entirely.
   The check was only added to the local-client relay paths
   (relay_private_message/relay_private_notice), not to
   server_relay_private_message/server_relay_private_notice. Any
   message whose origin server does not itself enforce +c (services
   packages, older/unpatched servers) is delivered straight to the +c
   user. Note the contrast with SILENCE: is_silenced() runs in BOTH
   the client and the server relay paths.

2. Self-messages are dropped: a +c user who PRIVMSGs their own nick
   never receives it unless they are in a visible channel (they always
   "share a channel" with themselves conceptually, but the delayed-join
   skip can even break that).

The remaining tests verify the feature as described by the PR and pass
both before and after the fix.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.multi_server


async def make_hub_client(ircd_network, nick):
    client = IRCClient()
    hub = ircd_network["hub"]
    await client.connect(hub["host"], hub["port"])
    await client.register(nick, "testuser", "Test User")
    return client


async def make_leaf1_client(ircd_network, nick):
    client = IRCClient()
    leaf1 = ircd_network["leaf1"]
    await client.connect(leaf1["host"], leaf1["port"])
    await client.register(nick, "testuser", "Test User")
    return client


async def set_umode_c(client, nick):
    """Set +c on a client and wait for the MODE echo."""
    await client.send(f"MODE {nick} +c")
    await client.wait_for("MODE")
    # Give the umode a moment to propagate across servers
    await asyncio.sleep(0.5)


def is_server_msg(msg):
    """True if the message originates from a server, not a user.

    Server messages have a plain server-name prefix (no user!ident@host),
    e.g. the "on 1 ca 2(4) ft 10(10)" target-throttle NOTICE sent after
    registration. Those must not be mistaken for delivered messages.
    """
    return msg.prefix is None or "!" not in msg.prefix


async def wait_for_user_msg(client, command="PRIVMSG", timeout=5.0):
    """Wait for a PRIVMSG/NOTICE that comes from a user, skipping server notices."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"no user-originated {command}")
        msg = await client.wait_for(command, timeout=remaining)
        if not is_server_msg(msg):
            return msg


async def assert_no_privmsg(client, timeout=2.0, command="PRIVMSG"):
    """Assert that no user-originated PRIVMSG/NOTICE arrives within timeout."""
    try:
        msg = await wait_for_user_msg(client, command=command, timeout=timeout)
    except asyncio.TimeoutError:
        return
    pytest.fail(f"Unexpected {command} delivered: {msg}")


async def cleanup(*clients):
    for client in clients:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()


@pytest.fixture
async def fakesrv(ircd_network):
    """A fake, non-U:lined P10 server linked to the hub.

    Used to inject PRIVMSG/NOTICE over the S2S link, simulating a
    message whose origin server does not enforce +c.
    """
    hub = ircd_network["hub"]
    srv = P10Server(name="notulined.test.net", numeric=5, password="testpass")
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


# --------------------------------------------------------------------
# Basic feature verification
# --------------------------------------------------------------------

async def test_umode_c_set_and_unset(ircd_network):
    """+c can be set and unset, and shows up in the umode reply (221)."""
    user = await make_hub_client(ircd_network, "tgt70m")
    try:
        await user.send("MODE tgt70m +c")
        mode = await user.wait_for("MODE")
        assert "c" in mode.params[-1], f"MODE echo missing +c: {mode}"

        msg = await user.send_and_expect("MODE tgt70m", "221")
        assert "c" in msg.params[-1], f"umode reply missing c: {msg}"

        await user.send("MODE tgt70m -c")
        await user.wait_for("MODE")
        msg = await user.send_and_expect("MODE tgt70m", "221")
        assert "c" not in msg.params[-1], f"umode reply still has c: {msg}"
    finally:
        await cleanup(user)


async def test_local_sender_blocked_without_common_channel(ircd_network):
    """A local sender with no common channel is silently dropped."""
    target = await make_hub_client(ircd_network, "tgt70a")
    sender = await make_hub_client(ircd_network, "snd70a")
    try:
        await set_umode_c(target, "tgt70a")
        await sender.send("PRIVMSG tgt70a :should be dropped")
        await assert_no_privmsg(target)
    finally:
        await cleanup(target, sender)


async def test_local_sender_allowed_with_common_channel(ircd_network):
    """A local sender sharing a channel with the +c target gets through."""
    target = await make_hub_client(ircd_network, "tgt70b")
    sender = await make_hub_client(ircd_network, "snd70b")
    try:
        await set_umode_c(target, "tgt70b")
        await target.send("JOIN #t70_local")
        await target.wait_for("366")
        await sender.send("JOIN #t70_local")
        await sender.wait_for("366")
        await target.wait_for("JOIN")

        await sender.send("PRIVMSG tgt70b :hello friend")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "hello friend"
    finally:
        await cleanup(target, sender)


async def test_remote_client_sender_blocked(ircd_network):
    """A client on another server with no common channel is dropped.

    +c is a global umode, so the sender's server already knows the
    target's mode and blocks at the origin; the target's server must
    also enforce it (see the S2S injection tests).
    """
    target = await make_hub_client(ircd_network, "tgt70c")
    sender = await make_leaf1_client(ircd_network, "snd70c")
    try:
        await set_umode_c(target, "tgt70c")
        await sender.send("PRIVMSG tgt70c :cross-server drop")
        await assert_no_privmsg(target)
    finally:
        await cleanup(target, sender)


async def test_remote_client_sender_allowed_with_common_channel(ircd_network):
    """A remote client sharing a channel with the +c target gets through."""
    target = await make_hub_client(ircd_network, "tgt70d")
    sender = await make_leaf1_client(ircd_network, "snd70d")
    try:
        await set_umode_c(target, "tgt70d")
        await target.send("JOIN #t70_rem")
        await target.wait_for("366")
        await sender.send("JOIN #t70_rem")
        await sender.wait_for("366")
        await target.wait_for("JOIN")
        await asyncio.sleep(0.3)

        await sender.send("PRIVMSG tgt70d :hello across the link")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "hello across the link"
    finally:
        await cleanup(target, sender)


# --------------------------------------------------------------------
# Bug 1: S2S-injected messages bypass +c (server_relay_* unchecked)
# --------------------------------------------------------------------

async def test_s2s_injected_privmsg_blocked(ircd_network, fakesrv):
    """A PRIVMSG arriving over the server link must honor +c.

    The fake server introduces a user that is in no channels and sends
    a PRIVMSG directly over the S2S link, as a services package or an
    unpatched server would. The target's server must drop it; before
    the fix server_relay_private_message() had no +c check and the
    message was delivered.
    """
    control = await make_hub_client(ircd_network, "ctl70e")
    target = await make_hub_client(ircd_network, "tgt70e")
    try:
        await set_umode_c(target, "tgt70e")

        control_num = await fakesrv.wait_for_user("ctl70e")
        target_num = await fakesrv.wait_for_user("tgt70e")
        fake = await fakesrv.introduce_user("fake70a")
        await asyncio.sleep(0.3)

        # Control: the injection path itself works for a non-+c target
        await fakesrv.send_privmsg(fake, control_num, "control message")
        msg = await wait_for_user_msg(control, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "control message"

        # The +c target must not receive the injected message
        await fakesrv.send_privmsg(fake, target_num, "s2s bypass attempt")
        await assert_no_privmsg(target)
    finally:
        await cleanup(control, target)


async def test_s2s_injected_notice_blocked(ircd_network, fakesrv):
    """A NOTICE arriving over the server link must honor +c.

    Same as above for server_relay_private_notice().
    """
    control = await make_hub_client(ircd_network, "ctl70f")
    target = await make_hub_client(ircd_network, "tgt70f")
    try:
        await set_umode_c(target, "tgt70f")

        control_num = await fakesrv.wait_for_user("ctl70f")
        target_num = await fakesrv.wait_for_user("tgt70f")
        fake = await fakesrv.introduce_user("fake70b")
        await asyncio.sleep(0.3)

        await fakesrv.send_notice(fake, control_num, "control notice")
        msg = await wait_for_user_msg(control, "NOTICE", timeout=5.0)
        assert msg.params[-1] == "control notice"

        await fakesrv.send_notice(fake, target_num, "s2s notice bypass")
        await assert_no_privmsg(target, command="NOTICE")
    finally:
        await cleanup(control, target)


# --------------------------------------------------------------------
# Bug 2: self-messages dropped
# --------------------------------------------------------------------

async def test_self_message_delivered(ircd_network):
    """A +c user PRIVMSGing their own nick must receive the message.

    Before the fix a +c user in no channels could not message
    themselves: sptr == acptr was not exempted and the common-channel
    walk found nothing.
    """
    user = await make_hub_client(ircd_network, "slf70a")
    try:
        await set_umode_c(user, "slf70a")
        await user.send("PRIVMSG slf70a :note to self")
        msg = await wait_for_user_msg(user, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "note to self"
    finally:
        await cleanup(user)
