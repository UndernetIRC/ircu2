"""Server-to-server parser robustness.

* 30d035b — a numeric outside 001..999 from a server is dropped instead of
  being dispatched.
* 9cad720 / a7bc0ee — msg_tree_parse() accepts '_' so full-name tokens such
  as END_OF_BURST are recognised again.
"""

from __future__ import annotations

import asyncio

import pytest

from common import whois
from p10_server import P10Server

pytestmark = pytest.mark.single_server


async def _link(hub, name="notulined.test.net", numeric=5) -> P10Server:
    srv = P10Server(name=name, numeric=numeric, password="testpass", server_flags="")
    await srv.connect(hub["host"], hub["server_port"])
    return srv


async def test_invalid_numeric_is_ignored(ircd_hub, make_client):
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        await srv._send(f"{srv.server_numnick} 000 AB :bogus numeric")
        await asyncio.sleep(0.3)
        # The link must still be alive and processing messages.
        await srv.introduce_user("parseok1", realname="Parse OK")
        client = await make_client("parsecli1")
        replies = await whois(client, "parseok1")
        assert "311" in replies, replies
        assert replies["311"].params[1] == "parseok1"
    finally:
        await srv.disconnect()


async def test_valid_numeric_is_relayed(ircd_hub, make_client):
    """Control: a numeric addressed to a local user is delivered."""
    client = await make_client("parsecli2")
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        numnick = await srv.wait_for_user("parsecli2")
        await srv._send(f"{srv.server_numnick} 391 {numnick} notulined.test.net 0 0 :fake time")
        reply = await client.wait_for("391", timeout=5.0)
        assert reply.params[-1] == "fake time", reply.raw
    finally:
        await srv.disconnect()


async def test_end_of_burst_full_token_name(ircd_hub):
    """END_OF_BURST spelled out (instead of EB) completes the handshake."""
    srv = await _link(ircd_hub)
    try:
        await srv.begin_handshake()
        await srv._send(f"{srv.server_numnick} END_OF_BURST")
        await srv.complete_handshake(timeout=10.0)
        assert srv.burst_complete
    finally:
        await srv.disconnect()


async def test_end_of_burst_ack_full_token_name(ircd_hub, make_client):
    """END_OF_BURST_ACK spelled out is accepted like EA."""
    srv = await _link(ircd_hub)
    try:
        await srv.begin_handshake()
        await srv.send_end_of_burst()
        await srv.recv_until("EA", timeout=10.0)
        await srv._send(f"{srv.server_numnick} END_OF_BURST_ACK")
        srv.burst_complete = True
        await srv.introduce_user("parseok4", realname="Parse OK")
        client = await make_client("parsecli4")
        replies = await whois(client, "parseok4")
        assert "311" in replies, replies
    finally:
        await srv.disconnect()


async def test_unknown_underscore_command_is_ignored(ircd_hub, make_client):
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        await srv._send(f"{srv.server_numnick} NO_SUCH_COMMAND foo :bar")
        await asyncio.sleep(0.3)
        await srv.introduce_user("parseok5", realname="Parse OK")
        client = await make_client("parsecli5")
        assert "311" in await whois(client, "parseok5")
    finally:
        await srv.disconnect()
