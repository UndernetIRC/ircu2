"""IRCv3 capability list (commit 4db844d and later additions).

The six capabilities introduced by 4db844d/f78fe06 are always advertised
(plus whatever later features added); a capability disabled through its
FEAT_CAP_* feature disappears from CAP LS and is refused on CAP REQ; sasl
stays hidden while no SASL agent is linked.
"""

from __future__ import annotations

import asyncio

import pytest

from common import set_feature
from irc_client import IRCClient

pytestmark = pytest.mark.single_server

EXPECTED_CAPS = {
    "account-notify",
    "away-notify",
    "chghost",
    "echo-message",
    "extended-join",
    "invite-notify",
}


async def _cap_ls(client: IRCClient) -> set[str]:
    await client.send("CAP LS")
    names: set[str] = set()
    while True:
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "LS", msg.raw
        names.update(t.split("=", 1)[0].lstrip("~=") for t in msg.params[-1].split())
        if len(msg.params) < 4 or msg.params[2] != "*":
            return names


async def test_cap_ls_lists_builtin_caps(ircd_hub):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        names = await _cap_ls(client)
        assert EXPECTED_CAPS <= names, names
        assert "sasl" not in names, names  # CAPFL_UNAVAILABLE without an agent
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_acks_every_builtin_cap(ircd_hub):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        acked = await client.negotiate_cap(sorted(EXPECTED_CAPS))
        assert set(acked) == EXPECTED_CAPS
        await client.register("capall1", "testuser", "cap all")
        await client.send("CAP LIST")
        listing = await client.wait_for("CAP", timeout=5.0)
        assert listing.params[1] == "LIST"
        assert set(listing.params[-1].split()) == EXPECTED_CAPS
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_works_after_registration(make_client):
    """CAP LS after registration answers without suspending anything (2e93875)."""
    client = await make_client("capreg1")
    names = await _cap_ls(client)
    assert EXPECTED_CAPS <= names
    await client.send("CAP END")  # ignored once registered
    await client.send("PING :still-here")
    pong = await client.wait_for("PONG", timeout=5.0)
    assert pong.params[-1] == "still-here"


async def test_cap_ls_before_registration_waits_for_cap_end(ircd_hub):
    """A pending CAP negotiation holds registration until CAP END (2e93875)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await _cap_ls(client)
        await client.send("NICK capwait1")
        await client.send("USER testuser 0 * :waiting")
        with pytest.raises((asyncio.TimeoutError, TimeoutError)):
            await client.wait_for("001", timeout=1.5)
        await client.send("CAP END")
        welcome = await client.wait_for("001", timeout=10.0)
        assert welcome.command == "001"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_feature_disables_cap(ircd_hub, oper):
    """FEAT_CAP_ECHOMESSAGE=FALSE hides echo-message and NAKs a REQ for it."""
    await set_feature(oper, "CAP_ECHOMESSAGE", "FALSE")
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        names = await _cap_ls(client)
        assert "echo-message" not in names
        assert EXPECTED_CAPS - {"echo-message"} <= names
        await client.send("CAP REQ :echo-message")
        nak = await client.wait_for("CAP", timeout=5.0)
        assert nak.params[1] == "NAK", nak.raw
        await client.send("CAP REQ :away-notify")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK", ack.raw
    finally:
        await set_feature(oper, "CAP_ECHOMESSAGE", "TRUE")
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()

    client2 = IRCClient()
    await client2.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        assert "echo-message" in await _cap_ls(client2)
    finally:
        await client2.send("CAP END")
        await client2.send("QUIT :done")
        await client2.disconnect()
