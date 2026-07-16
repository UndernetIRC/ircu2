"""Adversarial / edge-case tests for PR #70: usermode +c (common channels).

Covers exemptions (opers, services), interactions with other features
(AWAY, +D delayed joins, multi-target PRIVMSG), toggling the mode, and
the documented silent-drop behavior.

Tests that reproduce review findings (FAIL on the unfixed PR branch):

- test_delayed_join_target_accepts_channel_mates: the common-channel
  walk skipped the *target's* own delayed-join membership, so a +c
  user hidden in a +D channel rejected messages from visible members
  of that very channel. Only the *sender's* hidden membership should
  be ignored (joining +D channels invisibly must not grant access).
- test_s2s_service_user_exempt: exercises the +k exemption on the
  server-relay path, which did not exist before the fix.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.multi_server


async def make_client_on(server, nick):
    client = IRCClient()
    await client.connect(server["host"], server["port"])
    await client.register(nick, "testuser", "Test User")
    return client


async def set_umode_c(client, nick):
    await client.send(f"MODE {nick} +c")
    await client.wait_for("MODE")
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


async def assert_not_delivered(client, timeout=2.0, command="PRIVMSG"):
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
    hub = ircd_network["hub"]
    srv = P10Server(name="notulined.test.net", numeric=5, password="testpass")
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


async def test_notice_blocked_local(ircd_network):
    """NOTICE from a non-channel-mate is dropped just like PRIVMSG."""
    target = await make_client_on(ircd_network["hub"], "tgt70g")
    sender = await make_client_on(ircd_network["hub"], "snd70g")
    try:
        await set_umode_c(target, "tgt70g")
        await sender.send("NOTICE tgt70g :dropped notice")
        await assert_not_delivered(target, command="NOTICE")
    finally:
        await cleanup(target, sender)


async def test_ctcp_privmsg_blocked(ircd_network):
    """CTCP (PRIVMSG with \\x01) from a non-channel-mate is dropped."""
    target = await make_client_on(ircd_network["hub"], "tgt70h")
    sender = await make_client_on(ircd_network["hub"], "snd70h")
    try:
        await set_umode_c(target, "tgt70h")
        await sender.send("PRIVMSG tgt70h :\x01VERSION\x01")
        await assert_not_delivered(target)
    finally:
        await cleanup(target, sender)


async def test_oper_exempt_local(ircd_network):
    """A local IRC operator bypasses +c."""
    target = await make_client_on(ircd_network["hub"], "tgt70i")
    sender = await make_client_on(ircd_network["hub"], "snd70i")
    try:
        await set_umode_c(target, "tgt70i")
        await sender.send_and_expect("OPER testoper operpass", "381")
        await sender.send("PRIVMSG tgt70i :oper message")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "oper message"
    finally:
        await cleanup(target, sender)


async def test_oper_exempt_remote(ircd_network):
    """An oper on another server bypasses +c (oper flag is global)."""
    target = await make_client_on(ircd_network["hub"], "tgt70j")
    sender = await make_client_on(ircd_network["leaf1"], "snd70j")
    try:
        await set_umode_c(target, "tgt70j")
        await sender.send_and_expect("OPER testoper operpass", "381")
        await asyncio.sleep(0.3)
        await sender.send("PRIVMSG tgt70j :remote oper message")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "remote oper message"
    finally:
        await cleanup(target, sender)


async def test_unset_c_restores_delivery(ircd_network):
    """After -c, previously blocked senders get through again."""
    target = await make_client_on(ircd_network["hub"], "tgt70k")
    sender = await make_client_on(ircd_network["hub"], "snd70k")
    try:
        await set_umode_c(target, "tgt70k")
        await sender.send("PRIVMSG tgt70k :blocked")
        await assert_not_delivered(target)

        await target.send("MODE tgt70k -c")
        await target.wait_for("MODE")
        await sender.send("PRIVMSG tgt70k :unblocked")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "unblocked"
    finally:
        await cleanup(target, sender)


async def test_part_common_channel_blocks_again(ircd_network):
    """Once the only common channel is parted, messages are blocked."""
    target = await make_client_on(ircd_network["hub"], "tgt70l")
    sender = await make_client_on(ircd_network["hub"], "snd70l")
    try:
        await set_umode_c(target, "tgt70l")
        await target.send("JOIN #t70_part")
        await target.wait_for("366")
        await sender.send("JOIN #t70_part")
        await sender.wait_for("366")
        await target.wait_for("JOIN")

        await sender.send("PRIVMSG tgt70l :while joined")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "while joined"

        await sender.send("PART #t70_part")
        await sender.wait_for("PART")
        await target.wait_for("PART")

        await sender.send("PRIVMSG tgt70l :after part")
        await assert_not_delivered(target)
    finally:
        await cleanup(target, sender)


async def test_silent_drop_no_error_numeric(ircd_network):
    """The sender gets no numeric when the message is dropped (by design).

    Documents the intended silent-drop behavior; a sender cannot probe
    whether delivery happened.
    """
    target = await make_client_on(ircd_network["hub"], "tgt70n")
    sender = await make_client_on(ircd_network["hub"], "snd70n")
    try:
        await set_umode_c(target, "tgt70n")
        await sender.send("PRIVMSG tgt70n :dropped")
        # No error numeric (4xx/5xx) and no echoed PRIVMSG — informational
        # server notices (e.g. the target-throttle NOTICE) are ignored.
        deadline = asyncio.get_running_loop().time() + 2.0
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                msg = await sender.recv(timeout=remaining)
            except asyncio.TimeoutError:
                break
            if msg.command.isdigit() and 400 <= int(msg.command) < 600:
                pytest.fail(f"Sender received error numeric: {msg}")
            if msg.command == "PRIVMSG":
                pytest.fail(f"Sender received unexpected echo: {msg}")
    finally:
        await cleanup(target, sender)


async def test_away_status_not_leaked_when_blocked(ircd_network):
    """A blocked sender must not receive the +c target's AWAY message (301).

    Guards the check ordering in relay_private_message(): the +c drop
    happens before the RPL_AWAY reply, so away text does not leak to
    senders the target cannot hear.
    """
    target = await make_client_on(ircd_network["hub"], "tgt70o")
    sender = await make_client_on(ircd_network["hub"], "snd70o")
    try:
        await set_umode_c(target, "tgt70o")
        await target.send("AWAY :secret away message")
        await target.wait_for("306")

        await sender.send("PRIVMSG tgt70o :anyone there?")
        # RPL_AWAY is server-originated, so check it with a raw wait_for
        try:
            msg = await sender.wait_for("301", timeout=2.0)
            pytest.fail(f"AWAY text leaked to blocked sender: {msg}")
        except asyncio.TimeoutError:
            pass
        await assert_not_delivered(target, timeout=0.5)
    finally:
        await cleanup(target, sender)


async def test_multiple_targets_mixed(ircd_network):
    """PRIVMSG to a +c and a normal target delivers only to the latter."""
    blocked = await make_client_on(ircd_network["hub"], "tgt70p")
    normal = await make_client_on(ircd_network["hub"], "ctl70p")
    sender = await make_client_on(ircd_network["hub"], "snd70p")
    try:
        await set_umode_c(blocked, "tgt70p")
        await sender.send("PRIVMSG tgt70p,ctl70p :multi target")
        msg = await wait_for_user_msg(normal, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "multi target"
        await assert_not_delivered(blocked)
    finally:
        await cleanup(blocked, normal, sender)


async def test_delayed_join_sender_still_blocked(ircd_network):
    """A sender hidden by delayed join (+D) does not count as sharing.

    Joining a +D channel invisibly must not grant access to a +c user
    in that channel: the sender's hidden membership is ignored by the
    common-channel walk.
    """
    op = await make_client_on(ircd_network["hub"], "op70q")
    target = await make_client_on(ircd_network["hub"], "tgt70q")
    sender = await make_client_on(ircd_network["hub"], "snd70q")
    try:
        await op.send("JOIN #t70_dj1")
        await op.wait_for("366")
        await op.send("MODE #t70_dj1 +D")
        await op.wait_for("MODE")

        # Target joins and speaks so their membership is visible
        await target.send("JOIN #t70_dj1")
        await target.wait_for("366")
        await target.send("PRIVMSG #t70_dj1 :hello")
        await set_umode_c(target, "tgt70q")

        # Sender joins but stays silent: membership stays hidden
        await sender.send("JOIN #t70_dj1")
        await sender.wait_for("366")

        await sender.send("PRIVMSG tgt70q :from the shadows")
        await assert_not_delivered(target)
    finally:
        await cleanup(op, target, sender)


async def test_delayed_join_target_accepts_channel_mates(ircd_network):
    """A +c user hidden by delayed join still hears visible channel mates.

    Review finding: the common-channel walk also skipped the *target's*
    delayed-join membership, so a +c user who was hidden in a +D
    channel rejected messages from members they can plainly see. The
    target knows their own channels; only the sender's hidden
    membership should be ignored.
    """
    op = await make_client_on(ircd_network["hub"], "op70r")
    target = await make_client_on(ircd_network["hub"], "tgt70r")
    sender = await make_client_on(ircd_network["hub"], "snd70r")
    try:
        await op.send("JOIN #t70_dj2")
        await op.wait_for("366")
        await op.send("MODE #t70_dj2 +D")
        await op.wait_for("MODE")

        # Sender joins and speaks: visible member. Wait until the op has
        # seen the channel message so the server has definitely processed
        # it before the target joins (avoids a cross-connection race).
        await sender.send("JOIN #t70_dj2")
        await sender.wait_for("366")
        await sender.send("PRIVMSG #t70_dj2 :hi all")
        msg = await wait_for_user_msg(op, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "hi all"

        # Target joins and stays silent: hidden member
        await target.send("JOIN #t70_dj2")
        await target.wait_for("366")
        await set_umode_c(target, "tgt70r")

        await sender.send("PRIVMSG tgt70r :you can see me")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "you can see me"
    finally:
        await cleanup(op, target, sender)


async def test_s2s_service_user_exempt(ircd_network, fakesrv):
    """A +k (channel service) user injected over S2S bypasses +c.

    Exercises the IsChannelService exemption on the server-relay path.
    """
    target = await make_client_on(ircd_network["hub"], "tgt70s")
    try:
        await set_umode_c(target, "tgt70s")
        target_num = await fakesrv.wait_for_user("tgt70s")
        svc = await fakesrv.introduce_user("svc70a", modes="+ik")
        await asyncio.sleep(0.3)

        await fakesrv.send_privmsg(svc, target_num, "service message")
        msg = await wait_for_user_msg(target, "PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "service message"
    finally:
        await cleanup(target)
