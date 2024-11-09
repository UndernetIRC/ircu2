"""Tests for PR #69: exempt raised-maxflood clients from input throttling.

ircu throttles how fast it processes commands *from* a local client: after a
client's accumulated command penalty (cli_since) runs ~10s ahead of the clock,
the read loop stops draining its recvQ and defers the rest to a 2-second timer
(ircd/s_bsd.c). A connection class whose `maxflood` exceeds the CLIENT_FLOOD
default (1024) marks its clients FLAG_EXEMPT_THROTTLE, which bypasses that gate
so their commands are processed as fast as they arrive.

The throttle governs the *sender's* input processing, so the observable effect
is downstream: a throttled sender's PRIVMSGs are processed slowly, so a
recipient sees them dribble in; an exempt sender's are processed all at once,
so the recipient sees them immediately.

Test setup (see tests/docker/ircd-leaf1.conf):
  - Class "Exempt" has maxflood = 262144 (> 1024) -> flood-exempt.
  - A Client block routes connections on the dedicated exempt port (6690)
    into that class. Listener port is chosen (rather than username) because it
    is known at accept time; Client-block username matching keys off the
    *ident* username, which is empty without an identd (as in this harness).

The 2-second deferral is a hard floor. With 15 penalty-incurring messages a 
non-exempt sender can only clear ~5 in the first drain (5 * ~2s penalty reaches 
the ~10s gate), then ~1 per 2s timer tick -- so it CANNOT deliver all 15 within 
the short window. An exempt sender clears all 15 in a single drain. We assert 
the withholding, not an exact eventual total, so no long waits and no dependence 
on machine speed (localhost delivery is sub-millisecond).
"""

import asyncio

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.multi_server

# Number of back-to-back messages in the burst. Large enough that a throttled
# sender is guaranteed to have unprocessed messages left inside FAST_WINDOW.
BURST = 15
# Window in which an exempt sender delivers everything and a throttled one does
# not. Comfortably above localhost delivery time, well below the throttle's
# multi-second deferral, so both directions hold with margin.
FAST_WINDOW = 4.0


async def make_client_on(server, nick, port=None):
    client = IRCClient()
    await client.connect(server["host"], port or server["port"])
    await client.register(nick, "testuser", "Test User")
    return client


async def burst_privmsgs(sender, target_nick, count):
    """Fire `count` PRIVMSGs at target_nick as fast as the socket accepts them."""
    for i in range(count):
        await sender.send(f"PRIVMSG {target_nick} :flood {i}")


async def count_privmsgs_within(recipient, sender_nick, expected, window):
    """Count PRIVMSGs from sender_nick that arrive within `window` seconds.

    Stops early once `expected` have arrived. Returns the count reached.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + window
    count = 0
    while count < expected:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            msg = await recipient.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            break
        if (
            msg.command == "PRIVMSG"
            and msg.prefix
            and msg.prefix.split("!", 1)[0] == sender_nick
        ):
            count += 1
    return count


async def cleanup(*clients):
    for client in clients:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()


async def test_exempt_client_not_throttled(ircd_network):
    """A raised-maxflood (Exempt class) sender's whole burst lands immediately."""
    leaf = ircd_network["leaf1"]
    recipient = await make_client_on(leaf, "rcpt69a")
    # Connect on the exempt port -> routed into the Exempt class on leaf1.
    sender = await make_client_on(leaf, "exsnd69a", port=leaf["exempt_port"])
    try:
        await burst_privmsgs(sender, "rcpt69a", BURST)
        got = await count_privmsgs_within(recipient, "exsnd69a", BURST, FAST_WINDOW)
        assert got == BURST, (
            f"exempt sender should not be throttled, but recipient only got "
            f"{got}/{BURST} messages within {FAST_WINDOW}s"
        )
    finally:
        await cleanup(recipient, sender)


async def test_normal_client_is_throttled(ircd_network):
    """Control: a default-class sender is throttled, so the burst is withheld.

    Proves the exempt test above is actually exercising the throttle -- the
    same burst from a normal (Local class) sender must NOT all arrive in the
    window, because the 2-second deferral holds the tail back.
    """
    leaf = ircd_network["leaf1"]
    recipient = await make_client_on(leaf, "rcpt69b")
    # Default port -> Local class (normal throttling applies).
    sender = await make_client_on(leaf, "nrmsnd69b")
    try:
        await burst_privmsgs(sender, "rcpt69b", BURST)
        got = await count_privmsgs_within(recipient, "nrmsnd69b", BURST, FAST_WINDOW)
        assert got < BURST, (
            f"normal sender should be throttled, but recipient got all "
            f"{got}/{BURST} messages within {FAST_WINDOW}s (throttle not applied?)"
        )
    finally:
        await cleanup(recipient, sender)
