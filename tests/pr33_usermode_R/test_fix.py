"""Tests for PR #33: usermode +R (block unauthenticated user messages).

Usermode +R makes a client reject PRIVMSG, NOTICE and INVITE from
senders that are not authenticated to a registered account
(IsAccount() false). Blocked senders get ERR_NEEDREGGEDNICK (477).
Servers and channel services (+k) are always exempt.

See ircd/s_user.c: should_block_unauth_user() / send_reply_blocked_unauth_user(),
and its call sites in ircd/ircd_relay.c and ircd/m_invite.c.
"""

import asyncio

import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.single_server


# --------------------------------------------------------------------
# Basic feature verification
# --------------------------------------------------------------------

async def test_myinfo_advertises_blockunauth(ircd_hub):
    """The +R usermode must be advertised in RPL_MYINFO (004)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("NICK myinfo33")
        await client.send("USER testuser 0 * :Test User")
        msg = await client.wait_for("004", timeout=10.0)
        # 004 params: <nick> <servername> <version> <usermodes> <chanmodes>
        usermodes = msg.params[3]
        assert "R" in usermodes, f"usermode R not advertised in 004: {usermodes!r}"
    finally:
        await client.disconnect()


async def test_umode_R_can_be_set_and_unset(make_client):
    """A user can set and unset umode +R on themselves.

    set_umode() already asserts the requested mode was applied (from
    the MODE echo), so there's nothing further to check here.
    """
    user = await make_client("setter33")
    await user.set_umode("+R")
    await user.set_umode("-R")


async def test_unauth_privmsg_allowed_after_unset_R(make_client):
    """Unsetting +R restores normal delivery from unauthenticated senders."""
    target = await make_client("tgt33f")
    sender = await make_client("snd33f")
    await target.set_umode("+R")

    await sender.send(f"PRIVMSG {target.nick} :should be blocked")
    await sender.wait_for("477", timeout=5.0)

    await target.set_umode("-R")

    await sender.send(f"PRIVMSG {target.nick} :should get through now")
    msg = await target.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "should get through now"


async def test_silenced_sender_still_dropped_after_unset_R(make_client):
    """Unsetting +R does not also clear SILENCE.

    Once +R no longer applies, a still-silenced sender goes back to the
    plain SILENCE behavior: dropped with no reply at all (no more 477,
    since should_block_unauth_user() no longer fires).
    """
    target = await make_client("tgt33g")
    sender = await make_client("snd33g")
    await target.set_umode("+R")
    await target.silence(f"{sender.nick}!*@*")

    await target.set_umode("-R")

    await sender.send(f"PRIVMSG {target.nick} :should be silently dropped")
    await sender.assert_no_message(command="477", timeout=2.0)
    await target.assert_no_message(command="PRIVMSG")


async def test_unauth_sender_allowed_without_R(make_client):
    """Control: without +R, an unauthenticated sender's PRIVMSG gets through.

    If this fails, the blocked-delivery tests below prove nothing.
    """
    target = await make_client("tgt33a")
    sender = await make_client("snd33a")

    await sender.send(f"PRIVMSG {target.nick} :hello there")
    msg = await target.wait_for("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "hello there"


async def test_unauth_privmsg_blocked_with_477(make_client):
    """Core feature: PRIVMSG from an unauthenticated sender to a +R user
    is rejected with ERR_NEEDREGGEDNICK (477) and never delivered.
    """
    target = await make_client("tgt33b")
    sender = await make_client("snd33b")
    await target.set_umode("+R")

    await sender.send(f"PRIVMSG {target.nick} :should be blocked")
    msg = await sender.wait_for("477", timeout=5.0)
    assert target.nick in msg.params, f"477 missing target nick: {msg}"
    assert "identified to a registered account" in msg.params[-1], msg

    await target.assert_no_message(command="PRIVMSG")


async def test_unauth_notice_blocked_with_477(make_client):
    """Core feature: NOTICE from an unauthenticated sender to a +R user
    is rejected the same way as PRIVMSG.
    """
    target = await make_client("tgt33c")
    sender = await make_client("snd33c")
    await target.set_umode("+R")

    await sender.send(f"NOTICE {target.nick} :should be blocked")
    msg = await sender.wait_for("477", timeout=5.0)
    assert target.nick in msg.params, f"477 missing target nick: {msg}"

    await target.assert_no_message(command="NOTICE")


async def test_unauth_notice_allowed_after_unset_R(make_client):
    """Unsetting +R restores normal NOTICE delivery from unauthenticated senders."""
    target = await make_client("tgt33h")
    sender = await make_client("snd33h")
    await target.set_umode("+R")

    await sender.send(f"NOTICE {target.nick} :should be blocked")
    await sender.wait_for("477", timeout=5.0)

    await target.set_umode("-R")

    await sender.send(f"NOTICE {target.nick} :should get through now")
    msg = await target.wait_for_user_msg("NOTICE", timeout=5.0)
    assert msg.params[-1] == "should get through now"


async def test_silenced_sender_still_dropped_after_unset_R_notice(make_client):
    """NOTICE counterpart of test_silenced_sender_still_dropped_after_unset_R."""
    target = await make_client("tgt33i")
    sender = await make_client("snd33i")
    await target.set_umode("+R")
    await target.silence(f"{sender.nick}!*@*")

    await target.set_umode("-R")

    await sender.send(f"NOTICE {target.nick} :should be silently dropped")
    await sender.assert_no_message(command="477", timeout=2.0)
    await target.assert_no_message(command="NOTICE")


async def test_unauth_invite_blocked(make_client):
    """INVITE to a +R user from an unauthenticated sender is blocked.

    should_block_unauth_user() is also enforced in m_invite.c.
    """
    target = await make_client("tgt33d")
    sender = await make_client("snd33d")
    await target.set_umode("+R")

    await sender.send("JOIN #t33invite")
    await sender.wait_for("366")  # sender is auto-opped as channel founder

    await sender.send(f"INVITE {target.nick} #t33invite")
    msg = await sender.wait_for("477", timeout=5.0)
    assert target.nick in msg.params, f"477 missing target nick: {msg}"

    await target.assert_no_message(command="INVITE")


async def test_unauth_invite_allowed_after_unset_R(make_client):
    """Unsetting +R restores normal INVITE delivery from unauthenticated senders."""
    target = await make_client("tgt33j")
    sender = await make_client("snd33j")
    await target.set_umode("+R")

    await sender.send("JOIN #t33unsetinvite")
    await sender.wait_for("366")  # sender is auto-opped as channel founder

    await sender.send(f"INVITE {target.nick} #t33unsetinvite")
    await sender.wait_for("477", timeout=5.0)

    await target.set_umode("-R")

    await sender.send(f"INVITE {target.nick} #t33unsetinvite")
    msg = await sender.wait_for("341", timeout=5.0)  # RPL_INVITING
    assert target.nick in msg.params, f"RPL_INVITING missing target nick: {msg}"

    invite_msg = await target.wait_for_user_msg("INVITE", timeout=5.0)
    assert invite_msg.params[-1] == "#t33unsetinvite"


async def test_silenced_sender_still_dropped_after_unset_R_invite(make_client):
    """INVITE counterpart of test_silenced_sender_still_dropped_after_unset_R.

    Once +R no longer applies, a still-silenced sender's INVITE goes back
    to being dropped with no reply at all (not even RPL_INVITING).
    """
    target = await make_client("tgt33k")
    sender = await make_client("snd33k")
    await target.set_umode("+R")
    await target.silence(f"{sender.nick}!*@*")

    await target.set_umode("-R")

    await sender.send("JOIN #t33unsetinvite2")
    await sender.wait_for("366")

    await sender.send(f"INVITE {target.nick} #t33unsetinvite2")
    await sender.assert_no_message(command="477", timeout=2.0)
    await sender.assert_no_message(command="341", timeout=2.0)
    await target.assert_no_message(command="INVITE")


async def test_authenticated_sender_allowed(make_client, ulined_server):
    """A sender authenticated to an account (IsAccount() true) bypasses +R."""
    target = await make_client("tgt33e")
    await target.set_umode("+R")

    fake = await ulined_server.introduce_user("acctsnd33")
    await ulined_server.send_account(fake, "someaccount")
    target_num = await ulined_server.wait_for_user("tgt33e")
    await asyncio.sleep(0.3)

    await ulined_server.send_privmsg(fake, target_num, "authenticated hello")
    msg = await target.wait_for("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "authenticated hello"


# --------------------------------------------------------------------
# should_block_unauth_user() exemption: IRC operators
# --------------------------------------------------------------------
#
# Mirrors the umode +c precedent (commonchans_drop() in ircd_relay.c):
# IsAnOper(sptr) is exempt, so +R cannot be used to dodge oper contact.
# The testoper O-line comes from tests/docker/ircd-hub.conf.


@pytest.mark.parametrize("command", ["PRIVMSG", "NOTICE"])
async def test_unauth_oper_sender_allowed(make_client, command):
    """An IRC operator without an account bypasses +R for PRIVMSG/NOTICE."""
    target = await make_client("tgt33r")
    oper = await make_client("opr33r")
    await target.set_umode("+R")

    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)

    await oper.send(f"{command} {target.nick} :oper calling")
    msg = await target.wait_for_user_msg(command, timeout=5.0)
    assert msg.params[-1] == "oper calling"


async def test_unauth_oper_invite_allowed(make_client):
    """An IRC operator without an account bypasses +R for INVITE."""
    target = await make_client("tgt33s")
    oper = await make_client("opr33s")
    await target.set_umode("+R")

    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)

    await oper.send("JOIN #t33oper")
    await oper.wait_for("366")  # oper is auto-opped as channel founder

    await oper.send(f"INVITE {target.nick} #t33oper")
    msg = await oper.wait_for("341", timeout=5.0)  # RPL_INVITING
    assert target.nick in msg.params, f"RPL_INVITING missing target nick: {msg}"

    invite_msg = await target.wait_for_user_msg("INVITE", timeout=5.0)
    assert invite_msg.params[-1] == "#t33oper"


# --------------------------------------------------------------------
# should_block_unauth_user() exemptions: channel services and servers
# --------------------------------------------------------------------
#
# return IsBlockUnauthUsers(dest) &&
#     !(IsAccount(source) || IsChannelService(source) || IsServer(source));
#
# IsAccount() is covered by test_authenticated_sender_allowed above.
# IsChannelService() and IsServer() are exercised below by injecting
# raw P10 traffic from a fake server: a +k pseudo-client for the
# service case, and the fake server's own numeric (no user at all) for
# the server case.
#
# Note: there is no IsServer(source)-bypasses-+R test for INVITE.
# ms_invite() rejects a server-sourced INVITE outright with a protocol
# violation before should_block_unauth_user() is ever reached ("this
# will blow up if we get an invite from a server" -- ircd/m_invite.c),
# so that exemption is unreachable via INVITE.


async def test_channel_service_sender_allowed(make_client, ulined_server):
    """A channel service (+k) bypasses +R even without an account."""
    target = await make_client("tgt33l")
    await target.set_umode("+R")

    service = await ulined_server.introduce_user("service33p", modes="+k")
    target_num = await ulined_server.wait_for_user("tgt33l")
    await asyncio.sleep(0.3)

    await ulined_server.send_privmsg(service, target_num, "service hello")
    msg = await target.wait_for("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "service hello"


async def test_channel_service_sender_allowed_notice(make_client, ulined_server):
    """NOTICE counterpart of test_channel_service_sender_allowed."""
    target = await make_client("tgt33m")
    await target.set_umode("+R")

    service = await ulined_server.introduce_user("service33n", modes="+k")
    target_num = await ulined_server.wait_for_user("tgt33m")
    await asyncio.sleep(0.3)

    await ulined_server.send_notice(service, target_num, "service notice")
    msg = await target.wait_for_user_msg("NOTICE", timeout=5.0)
    assert msg.params[-1] == "service notice"


async def test_channel_service_sender_allowed_invite(make_client, ulined_server):
    """INVITE counterpart of test_channel_service_sender_allowed.

    A channel service also bypasses the channel-membership requirement
    (the `!IsChannelService(sptr) && !find_channel_member(...)` check in
    ms_invite()), so it can invite without having joined the channel.
    """
    target = await make_client("tgt33o")
    creator = await make_client("crt33o")
    await target.set_umode("+R")

    await creator.send("JOIN #t33service")
    await creator.wait_for("366")

    service = await ulined_server.introduce_user("service33i", modes="+k")
    await asyncio.sleep(0.3)

    await ulined_server.send_invite(service, target.nick, "#t33service")
    invite_msg = await target.wait_for_user_msg("INVITE", timeout=5.0)
    assert invite_msg.params[-1] == "#t33service"


async def test_server_sourced_privmsg_allowed(make_client, ulined_server):
    """A message sourced from the server itself (not a user) bypasses +R.

    Injects a raw PRIVMSG whose P10 prefix is the fake server's own
    numeric rather than a user numnick, so sptr resolves to a Server
    Client (IsServer(source) true) in server_relay_private_message().
    """
    target = await make_client("tgt33p")
    await target.set_umode("+R")

    target_num = await ulined_server.wait_for_user("tgt33p")
    await asyncio.sleep(0.3)

    await ulined_server.send_privmsg(ulined_server.server_numnick, target_num, "server hello")
    msg = await target.wait_for("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "server hello"


async def test_server_sourced_notice_allowed(make_client, ulined_server):
    """NOTICE counterpart of test_server_sourced_privmsg_allowed."""
    target = await make_client("tgt33q")
    await target.set_umode("+R")

    target_num = await ulined_server.wait_for_user("tgt33q")
    await asyncio.sleep(0.3)

    await ulined_server.send_notice(ulined_server.server_numnick, target_num, "server notice")
    msg = await target.wait_for_message_with_text("NOTICE", "server notice", timeout=5.0)
    assert msg.params[-1] == "server notice"
