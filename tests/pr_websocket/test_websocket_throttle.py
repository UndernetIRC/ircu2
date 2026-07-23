"""WebSocket input throttling: normal clients are throttled, exempt are not.

The line-based reader has always throttled how fast it processes a client's
commands (the cli_since penalty gate); the WebSocket reader now shares that
same drain path. A raised-maxflood class (FLAG_EXEMPT_THROTTLE) bypasses it.

A WS sender fires a burst of PRIVMSGs at a plain recipient on the same hub;
we count how many arrive in a short window. A normal sender is throttled so
only the first few land; an exempt sender (connected on the exempt WS port,
7002) is not, so all of them land. See tests/docker/ircd-hub.conf.
"""

import asyncio

import pytest

from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient
from ws_frame_helpers import HOST, WS_PORT, WS_EXEMPT_PORT

NORMAL_PORT = 6667
BURST = 15
# Window for the throttled test: short relative to the ~2s/command penalty so
# the tail of the burst cannot drain within it.
FAST_WINDOW = 4.0
# Window for the exempt test: generous, since a loaded CI host can delay even
# an unthrottled burst. count_within() returns as soon as the full burst has
# arrived, so a passing run never waits this long.
EXEMPT_WINDOW = 10.0


async def recipient_client(nick):
    c = IRCClient()
    await c.connect(HOST, NORMAL_PORT)
    await c.register(nick, "testuser", "Test User")
    return c


async def ws_sender(nick, port):
    c = IRCWebSocketClient()
    await c.connect(f"ws://{HOST}:{port}")
    await c.register(nick, "testuser", "Test User")
    return c


async def burst_privmsgs(sender, target, count):
    for i in range(count):
        await sender.send(f"PRIVMSG {target} :flood {i}")


async def count_within(recipient, sender_nick, expected, window):
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
        if (msg.command == "PRIVMSG" and msg.prefix
                and msg.prefix.split("!", 1)[0] == sender_nick):
            count += 1
    return count


async def cleanup(*clients):
    for c in clients:
        try:
            await c.disconnect()
        except Exception:
            pass


async def test_exempt_ws_client_not_throttled(ircd_hub):
    """A WS sender on the exempt port delivers its whole burst immediately."""
    recipient = await recipient_client("wsrcpt_e")
    sender = await ws_sender("wssnd_e", WS_EXEMPT_PORT)
    try:
        await burst_privmsgs(sender, "wsrcpt_e", BURST)
        got = await count_within(recipient, "wssnd_e", BURST, EXEMPT_WINDOW)
        assert got == BURST, (
            f"exempt WS sender should not be throttled, but recipient got "
            f"{got}/{BURST} within {EXEMPT_WINDOW}s"
        )
    finally:
        await cleanup(recipient, sender)


async def test_normal_ws_client_is_throttled(ircd_hub):
    """Control: a WS sender on the normal port is throttled, withholding the tail."""
    recipient = await recipient_client("wsrcpt_n")
    sender = await ws_sender("wssnd_n", WS_PORT)
    try:
        await burst_privmsgs(sender, "wsrcpt_n", BURST)
        got = await count_within(recipient, "wssnd_n", BURST, FAST_WINDOW)
        # Lower bound: some of the burst must arrive (zero would mean delivery
        # is broken, not that throttling works). Upper bound: the tail must be
        # withheld by the throttle.
        assert 0 < got < BURST, (
            f"normal WS sender should be throttled but still deliver the head "
            f"of the burst; recipient got {got}/{BURST} within {FAST_WINDOW}s"
        )
    finally:
        await cleanup(recipient, sender)
