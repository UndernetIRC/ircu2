"""Edge case: +R block must be checked before SILENCE, or it leaks the
recipient's silence list.

should_block_unauth_user() sends an explicit error (477
ERR_NEEDREGGEDNICK) back to the sender. is_silenced() drops the message
with no reply at all. In every call site (ircd/ircd_relay.c,
ircd/m_invite.c) the +R check runs first:

    if (should_block_unauth_user(sptr, acptr)) {
      send_reply_blocked_unauth_user(sptr, acptr);
      return;
    }
    if (is_silenced(sptr, acptr))
      return;

If that order were reversed, an unauthenticated sender could
distinguish "target has +R and I'm not silenced" (gets 477) from
"target has +R and I *am* silenced" (gets nothing) -- turning the +R
error into an oracle for the target's SILENCE list, which is otherwise
never exposed to anyone but the target. These tests pin the correct
order: a silenced, unauthenticated sender must still get 477, exactly
as an unsilenced one would.
"""

import asyncio

import pytest


pytestmark = pytest.mark.single_server


@pytest.mark.parametrize("command", ["PRIVMSG", "NOTICE"])
async def test_silenced_unauth_sender_still_gets_477(make_client, command):
    """A silenced AND unauthenticated sender must still receive 477.

    If SILENCE were checked first, this message would be dropped
    silently instead -- letting the sender infer they're on the
    target's silence list just from the absence of an error.
    """
    target = await make_client(f"tgtR{command[0]}a")
    sender = await make_client(f"sndR{command[0]}a")
    await target.set_umode("+R")
    await target.silence(f"{sender.nick}!*@*")

    await sender.send(f"{command} {target.nick} :leak check")
    msg = await sender.wait_for("477", timeout=5.0)
    assert target.nick in msg.params, (
        f"silenced+unauth sender did not get 477 (info leak via silent drop): {msg}"
    )

    await target.assert_no_message(command)


@pytest.mark.parametrize("command", ["PRIVMSG", "NOTICE"])
async def test_silence_alone_still_drops_silently(make_client, command):
    """Control: without +R, SILENCE alone still drops with no reply to sender.

    Confirms plain SILENCE behavior is untouched, so the contrast in
    the previous test is meaningful: it's specifically +R's error that
    must win the ordering, not that errors always fire now.
    """
    target = await make_client(f"tgtR{command[0]}b")
    sender = await make_client(f"sndR{command[0]}b")
    await target.silence(f"{sender.nick}!*@*")

    await sender.send(f"{command} {target.nick} :should be silently dropped")
    await sender.assert_no_message("477", timeout=2.0)
    await target.assert_no_message(command)


@pytest.mark.parametrize("command", ["PRIVMSG", "NOTICE"])
async def test_silenced_authenticated_sender_dropped_silently(
    make_client, ulined_server, command
):
    """An authenticated sender bypasses +R, so a normal, silent SILENCE
    drop applies -- no 477 leaks anything about the +R check either.
    """
    target = await make_client(f"tgtR{command[0]}c")
    await target.set_umode("+R")

    fake = await ulined_server.introduce_user(f"acctsndR{command[0]}")
    await ulined_server.send_account(fake, "someaccount")
    target_num = await ulined_server.wait_for_user(target.nick)
    await asyncio.sleep(0.3)

    await target.silence(f"acctsndR{command[0]}!*@*")

    if command == "PRIVMSG":
        await ulined_server.send_privmsg(fake, target_num, "authed but silenced")
    else:
        await ulined_server.send_notice(fake, target_num, "authed but silenced")

    await target.assert_no_message(command)


async def test_invite_silenced_unauth_sender_still_gets_477(make_client):
    """Same ordering guarantee for INVITE (m_invite.c), not just PRIVMSG/NOTICE."""
    target = await make_client("tgtRinv")
    sender = await make_client("sndRinv")
    await target.set_umode("+R")
    await target.silence(f"{sender.nick}!*@*")

    await sender.send("JOIN #t33leakcheck")
    await sender.wait_for("366")

    await sender.send(f"INVITE {target.nick} #t33leakcheck")
    msg = await sender.wait_for("477", timeout=5.0)
    assert target.nick in msg.params, (
        f"silenced+unauth inviter did not get 477 (info leak via silent drop): {msg}"
    )

    await target.assert_no_message("INVITE")
