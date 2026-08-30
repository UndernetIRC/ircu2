"""Username handling at registration.

* adcd438 — ident lookups happen only when some Client block carries a
  username mask (DoIdentLookups): the server announces "Checking Ident"
  and prefixes ~ when the lookup fails.  leaf1 has no username mask (no
  lookup); the hub and leaf2 have one.
* 85f4db0 — a WEBIRC-spoofed client's USER name is trusted verbatim even
  though ident lookups are on (leaf2, WebIRC port).

The hub and leaf1 run iauth-tilded.pl, which forces a ~ regardless, so the
~ assertions for the ident path use leaf2 (non-forcing IAuth stub).
"""

from __future__ import annotations

import asyncio

import pytest

from common import whois
from irc_client import IRCClient

pytestmark = pytest.mark.multi_server


async def _register(server, nick, username, port=None, pre=None):
    client = IRCClient()
    await client.connect(server["host"], port or server["port"])
    if pre:
        await client.send(pre)
    await client.register(nick, username, "Ident Test")
    return client


async def _auth_notices(server, port=None, wait=1.5) -> list[str]:
    """Collect the NOTICE AUTH lines sent while a connection is pending."""
    client = IRCClient()
    await client.connect(server["host"], port or server["port"])
    out = []
    deadline = asyncio.get_running_loop().time() + wait
    try:
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                msg = await client.recv(timeout=remaining)
            except (asyncio.TimeoutError, ConnectionError):
                break
            if msg.command == "NOTICE" and msg.params[0] == "AUTH":
                out.append(msg.params[-1])
    finally:
        await client.disconnect()
    return out


async def test_ident_is_queried_only_with_username_mask(ircd_network):
    """DoIdentLookups is set by a Client block with a username (adcd438)."""
    assert any("Checking Ident" in n for n in await _auth_notices(ircd_network["hub"]))
    assert any("Checking Ident" in n for n in await _auth_notices(ircd_network["leaf2"]))
    assert not any("Ident" in n for n in await _auth_notices(ircd_network["leaf1"]))


async def test_failed_ident_gets_tilde_with_username_mask(ircd_network):
    """leaf2: Client { username = "*" } => ident is queried; failure adds ~."""
    client = await _register(ircd_network["leaf2"], "identleaf2", "leafuser")
    try:
        replies = await whois(client, "identleaf2")
        assert replies["311"].params[2] == "~leafuser", replies["311"].raw
    finally:
        await client.disconnect()


async def test_webirc_client_username_is_trusted(ircd_network):
    leaf = ircd_network["leaf2"]
    client = await _register(
        leaf, "identweb3", "webuser", port=leaf["webirc_port"],
        pre="WEBIRC webircpass gateway spoofed.example.net 192.0.2.7",
    )
    try:
        replies = await whois(client, "identweb3")
        assert replies["311"].params[2] == "webuser", replies["311"].raw
        assert replies["311"].params[3] == "spoofed.example.net", replies["311"].raw
    finally:
        await client.disconnect()


async def test_webirc_client_skips_ident(ircd_network):
    """A spoofed client never sees the ident probe (auth_spoof_user path)."""
    leaf = ircd_network["leaf2"]
    client = IRCClient()
    await client.connect(leaf["host"], leaf["webirc_port"])
    await client.send("WEBIRC webircpass gateway spoofed.example.net 192.0.2.9")
    await client.register("identweb9", "webuser", "x")
    try:
        notices = [m.params[-1] for m in client.received_messages
                   if m.command == "NOTICE" and m.params[0] == "AUTH"]
        assert not any("Ident" in n for n in notices), notices
    finally:
        await client.disconnect()


async def test_webirc_port_requires_webirc_first(ircd_network):
    """NICK/USER on a WebIRC port before WEBIRC closes the link (m_nick/m_user)."""
    leaf = ircd_network["leaf2"]
    client = IRCClient()
    await client.connect(leaf["host"], leaf["webirc_port"])
    with pytest.raises(ConnectionError):
        await client.register("identweb4", "plainuser", "x")
    await client.disconnect()


async def test_webirc_bad_password_is_rejected(ircd_network):
    leaf = ircd_network["leaf2"]
    client = IRCClient()
    await client.connect(leaf["host"], leaf["webirc_port"])
    await client.send("WEBIRC wrongpass gateway spoofed.example.net 192.0.2.8")
    with pytest.raises(ConnectionError):
        await client.register("identweb5", "webuser", "x")
    await client.disconnect()


async def test_webirc_on_normal_port_is_rejected(ircd_network):
    """WEBIRC is only accepted on ports flagged webirc = yes."""
    leaf = ircd_network["leaf2"]
    client = IRCClient()
    await client.connect(leaf["host"], leaf["port"])
    await client.send("WEBIRC webircpass gateway spoofed.example.net 192.0.2.10")
    with pytest.raises(ConnectionError):
        await client.register("identweb6", "webuser", "x")
    await client.disconnect()


async def test_webirc_invalid_spoof_host_is_rejected(ircd_network):
    """auth_verify_hostname() failure => "WEBIRC invalid spoof"."""
    leaf = ircd_network["leaf2"]
    client = IRCClient()
    await client.connect(leaf["host"], leaf["webirc_port"])
    await client.send("WEBIRC webircpass gateway bad host!name 192.0.2.11")
    with pytest.raises(ConnectionError):
        await client.register("identweb7", "webuser", "x")
    await client.disconnect()
