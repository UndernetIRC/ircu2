"""S2S TLS link carrying a populated burst, initiated from each side.

Links tls-hub and tls-leaf over TLS with the hub in both TLS roles (client
when it initiates, server when the leaf does) and a non-trivial user burst,
and requires the link to stay up and the burst to have arrived on the far
side.  Regression coverage for the TLS handshake / send-path code on server
links, which the other S2S tests exercise only with an empty network.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from irc_client import IRCClient
from tls.helpers import (
    links_contains,
    oper_up,
    populate_channels,
)

log = logging.getLogger(__name__)

pytestmark = [pytest.mark.tls, pytest.mark.tls_stress, pytest.mark.asyncio]

HUB_NAME = "tls-hub.test.net"
LEAF_NAME = "tls-leaf.test.net"


async def _oper(host: str, port: int, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(host, port)
    await c.register(nick, "oper", "Oper")
    msg = await oper_up(c)
    assert msg.command == "381", msg
    # See server notices (net breaks, TLS failures) for diagnosis.
    await c.send(f"MODE {nick} +s +65535")
    return c


async def _drain(c: IRCClient, seconds: float, tag: str) -> list:
    """Read everything for `seconds`, logging each line."""
    out = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return out
        try:
            msg = await c.recv(timeout=remaining)
        except asyncio.TimeoutError:
            return out
        out.append(msg)
        log.info("%s <- %s", tag, msg.raw)


async def _wait_linked(c: IRCClient, peer: str, tag: str, timeout: float = 45.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await _drain(c, 1.0, tag)
        if await links_contains(c, peer, timeout=5.0):
            return
    raise TimeoutError(f"{tag}: {peer} never appeared in LINKS")


async def _wait_unlinked(c: IRCClient, peer: str, tag: str, timeout: float = 30.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await _drain(c, 1.0, tag)
        if not await links_contains(c, peer, timeout=5.0):
            return
    raise TimeoutError(f"{tag}: {peer} still in LINKS")


async def _whois_ok(c: IRCClient, nick: str) -> bool:
    await c.send(f"WHOIS {nick}")
    while True:
        msg = await c.recv(timeout=10.0)
        if msg.command == "311":
            return True
        if msg.command in ("401", "318"):
            return False


async def _link_and_check(
    initiator: IRCClient, other: IRCClient, peer: str, port: int,
    other_peer: str, probe_nick: str, tag: str,
) -> None:
    await initiator.send(f"CONNECT {peer} {port}")
    await _wait_linked(initiator, peer, f"{tag}/init")
    await _wait_linked(other, other_peer, f"{tag}/other")
    # Let the burst finish and any delayed failure show up.
    await _drain(initiator, 8.0, f"{tag}/init")
    await _drain(other, 3.0, f"{tag}/other")
    assert await links_contains(initiator, peer), f"{tag}: link dropped (initiator side)"
    assert await links_contains(other, other_peer), f"{tag}: link dropped (other side)"
    assert await _whois_ok(other, probe_nick), f"{tag}: burst did not arrive on other side"


@pytest.mark.timeout(400)
async def test_s2s_tls_burst_both_directions(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    leaf = ircd_tls_network["leaf"]
    crowd: list[IRCClient] = []
    hub_op = leaf_op = None
    try:
        hub_op = await _oper(hub["host"], hub["port"], "s2sophub")
        leaf_op = await _oper(leaf["host"], leaf["port"], "s2sopleaf")

        # Start from an unlinked state.
        if await links_contains(hub_op, LEAF_NAME):
            await hub_op.send(f"SQUIT {LEAF_NAME} :reset")
            await _wait_unlinked(hub_op, LEAF_NAME, "reset/hub")
            await _wait_unlinked(leaf_op, HUB_NAME, "reset/leaf")

        crowd = await populate_channels(hub)
        log.info("crowd of %d populated on hub", len(crowd))

        # Direction 1: hub initiates (hub is TLS client, sends the big burst).
        await _link_and_check(hub_op, leaf_op, LEAF_NAME, 4401, HUB_NAME,
                              "crwd00", "hub->leaf")

        await hub_op.send(f"SQUIT {LEAF_NAME} :direction swap")
        await _wait_unlinked(hub_op, LEAF_NAME, "swap/hub")
        await _wait_unlinked(leaf_op, HUB_NAME, "swap/leaf")

        # Direction 2: leaf initiates (hub is TLS server).
        await _link_and_check(leaf_op, hub_op, HUB_NAME, 4441, LEAF_NAME,
                              "crwd00", "leaf->hub")
    finally:
        for c in [hub_op, leaf_op, *crowd]:
            if c is None:
                continue
            try:
                await c.disconnect()
            except Exception:
                pass
