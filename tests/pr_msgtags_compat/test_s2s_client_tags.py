"""Client-only (+) tags must cross server links to clients on other servers.

The S2S formatter used to drop every client-only tag, so a TAGMSG relayed
to another server arrived as a bare ``TM #chan`` and a PRIVMSG lost its
client tags at the first hop.  All earlier tag tests observed two clients
on the same server, which is why this went unnoticed.

The docker configs set ``CLIENTTAGDENY = "*,-example.com/foo"`` on hub and
leaf, so ``+example.com/foo`` is the one client tag allowed end to end and
``+blockedtag`` must be filtered at the sender's edge.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server

from .helpers import join_synced, tag_has, tag_value

pytestmark = pytest.mark.multi_server

ALLOWED = "+example.com/foo"


async def _client(host: str, port: int, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(host, port)
    await c.negotiate_cap(["message-tags"])
    await c.register(nick, "testuser", f"User {nick}")
    return c


async def _cleanup(*clients: IRCClient) -> None:
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        await c.disconnect()


async def test_client_tags_reach_clients_on_other_servers(ircd_network):
    """PRIVMSG, TAGMSG and private PRIVMSG keep +tags across hub -> leaf."""
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    channel = "#ctagleaf"

    sender = await _client(hub["host"], hub["port"], "ctagsnd")
    leaf_obs = await _client(leaf["host"], leaf["port"], "ctagleaf")

    try:
        await join_synced(channel, sender, leaf_obs)
        # Let the leaf learn about the hub-side member before speaking.
        await asyncio.sleep(0.5)

        await sender.send(f"@{ALLOWED}=chan PRIVMSG {channel} :tagged privmsg")
        msg = await leaf_obs.wait_for_message_with_text(
            "PRIVMSG", "tagged privmsg", timeout=10.0)
        assert tag_value(msg.tags, ALLOWED) == "chan", msg.raw
        assert tag_has(msg.tags, "time"), msg.raw

        await sender.send(f"@{ALLOWED}=tm TAGMSG {channel}")
        msg = await leaf_obs.wait_for("TAGMSG", timeout=10.0)
        assert msg.params[0] == channel, msg.raw
        assert tag_value(msg.tags, ALLOWED) == "tm", msg.raw

        # A tag denied on the sender's server never leaves it; an allowed
        # one on the same line still arrives.
        await sender.send(
            f"@+blockedtag=1;{ALLOWED}=mixed PRIVMSG {channel} :mixed tags")
        msg = await leaf_obs.wait_for_message_with_text(
            "PRIVMSG", "mixed tags", timeout=10.0)
        assert not tag_has(msg.tags, "+blockedtag"), msg.raw
        assert tag_value(msg.tags, ALLOWED) == "mixed", msg.raw

        await sender.send(f"@{ALLOWED}=pm PRIVMSG ctagleaf :direct tagged")
        msg = await leaf_obs.wait_for_message_with_text(
            "PRIVMSG", "direct tagged", timeout=10.0)
        assert tag_value(msg.tags, ALLOWED) == "pm", msg.raw
    finally:
        await _cleanup(sender, leaf_obs)


async def test_client_tags_on_s2s_wire(ircd_network):
    """The allowed client tag is present on the P10 line leaving the hub."""
    hub = ircd_network["hub"]
    channel = "#ctagwire"

    peer = P10Server(name="services.test.net", numeric=4, password="testpass")
    await peer.connect(hub["host"], hub["server_port"])
    await peer.handshake()

    sender = await _client(hub["host"], hub["port"], "ctagwire")
    try:
        bot = await peer.introduce_user("ctagbot")
        await peer.send_join(bot, channel)
        await join_synced(channel, sender)
        await asyncio.sleep(0.3)

        await sender.send(
            f"@+blockedtag=1;{ALLOWED}=wire PRIVMSG {channel} :on the wire")

        deadline = asyncio.get_event_loop().time() + 8.0
        line = None
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            candidate = await peer._recv(timeout=max(remaining, 0.1))
            if peer._get_token(candidate) == "P" and "on the wire" in candidate:
                line = candidate
                break
        assert line, "S2S PRIVMSG never reached the peer"
        assert line.startswith("@"), f"no tag prefix on S2S line: {line}"
        prefix = line.split(" ", 1)[0]
        assert f"{ALLOWED}=wire" in prefix.split(";"), line
        assert "+blockedtag" not in prefix, line
        assert prefix.startswith("@time="), line
    finally:
        await _cleanup(sender)
        await peer.disconnect()
