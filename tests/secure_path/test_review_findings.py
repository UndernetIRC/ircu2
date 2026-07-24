"""TDD tests for the PR #82 review findings (SECUREPATH-PR-REVIEW.md).

Each test reproduces one confirmed issue in the secure-path implementation
and asserts the *intended* behavior, so all of them fail before the fixes
and pass after:

- Finding 1: multi-hop TLS topologies are mis-grouped. A TLS subtree behind
  one hub link keeps a different secure group than a sibling TLS leaf, so a
  fully-TLS path is reported as insecure.
- Finding 2: per-channel cached group IDs go stale when the topology changes
  and groups are renumbered, leaving channels stuck at +z.
- Finding 3: group 0 (insecure) counts as "one group", so a mixed +z channel
  whose TLS members all leave flips to +Z while only plaintext members remain.
- Finding 4: two TLS clients on the same server never share a secure path
  when that server has no TLS server links.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from irc_client import IRCClient
from p10_server import P10Server
from secure_path.helpers import (
    channel_mode_flags as _channel_mode_flags,
    collect_whois as _collect_whois,
    join as _join,
    make_oper as _make_oper,
    whois_secure_text as _whois_secure_text,
)
from tls.helpers import connect_link
from tls_certs import client_ssl_context

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

TLS_LEAF_NAME = "tls-leaf.test.net"
TLS_LEAF_PORT = 4401


async def _drain(client: IRCClient, seconds: float = 1.0) -> None:
    """Discard queued messages for a while (SQUIT wallops, snotices, ...)."""
    deadline = asyncio.get_running_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return
        with contextlib.suppress(asyncio.TimeoutError, TimeoutError):
            await client.recv(timeout=remaining)


async def _squit_tls_leaf(op: IRCClient) -> None:
    """Ensure the hub has no link to the TLS leaf (isolation between tests)."""
    await op.send(f"SQUIT {TLS_LEAF_NAME} :secure-path test isolation")
    await _drain(op, 1.5)


async def _ping_loop(gateway: P10Server) -> None:
    try:
        while gateway.connected:
            await gateway.drain_messages(timeout=1.0)
    except (ConnectionError, asyncio.CancelledError, TimeoutError):
        pass


@contextlib.asynccontextmanager
async def _tls_gateway(hub: dict, name: str, numeric: int, flags: str = "s"):
    """Fake P10 server linked to the hub over TLS, with a keepalive task."""
    ctx = client_ssl_context(cert="tlspeer")
    srv = P10Server(name=name, numeric=numeric, password="testpass",
                    server_flags=flags)
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    await srv.handshake()
    ping_task = asyncio.create_task(_ping_loop(srv))
    try:
        yield srv
    finally:
        ping_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ping_task
        await srv.disconnect()
        await asyncio.sleep(0.5)


async def _tls_client(hub: dict, nick: str) -> IRCClient:
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    await client.register(nick, "testuser", nick)
    return client


# ---------------------------------------------------------------------------
# Finding 1: multi-hop sibling TLS subtree is mis-grouped
# ---------------------------------------------------------------------------


async def test_secure_path_spans_sibling_tls_subtree(ircd_tls_network):
    """A TLS user two hops away (hub -TLS- gateway -TLS- leaf) must share a
    secure path with a TLS user on the hub, even when another TLS server
    (tls-leaf) linked to the hub more recently.

    The buggy grouping merges the hub and its *direct* TLS downlinks into the
    newest downlink's group, orphaning the gateway's subtree in a stale group.
    """
    hub = ircd_tls_network["hub"]
    op = await _make_oper(hub, "srf1op")
    try:
        # Deterministic link order: gateway first, tls-leaf last (newest).
        await _squit_tls_leaf(op)

        async with _tls_gateway(hub, "tlspeer.test.net", 40) as gw:
            down_num = await gw.send_downstream_server(
                "deep.test.net", 41, hop=2, flags="z",
                description="TLS leaf behind gateway",
            )
            await gw.send_downstream_nick(
                down_num, "deepuser", server_numeric=41, modes="z",
                realname="TLS user two hops away",
            )
            await asyncio.sleep(0.5)

            # tls-leaf links last: it becomes the head of the hub's downlink
            # list and (in the buggy code) donates its group to the hub.
            await connect_link(op, TLS_LEAF_NAME, TLS_LEAF_PORT, timeout=45.0)
            await asyncio.sleep(1.0)

            observer = await _tls_client(hub, "srf1obs")
            try:
                msgs = await _collect_whois(observer, "deepuser")
                text = _whois_secure_text(msgs)
                assert text is not None, (
                    f"expected 671 for remote TLS (+z) user, got {msgs}"
                )
                assert "secure network path" in text.lower(), (
                    "hub->gateway->deep are all TLS hops; the hub observer "
                    f"must share a secure path with deepuser, got {text!r} "
                    "(finding 1: sibling TLS subtree left in a stale group)"
                )
            finally:
                await observer.disconnect()
    finally:
        await op.disconnect()


# ---------------------------------------------------------------------------
# Finding 2: channel group cache goes stale when groups are renumbered
# ---------------------------------------------------------------------------


async def test_channel_stays_Z_after_group_renumbering(ircd_tls_network):
    """A +Z channel of same-server TLS users must stay +Z across a topology
    change that renumbers secure groups.

    The buggy code caches group IDs in the channel at join time; after the
    gateway leaves, a new join adds a *different* ID next to the stale one and
    the channel wrongly degrades to +z.
    """
    hub = ircd_tls_network["hub"]
    channel = "#srf2"
    op = await _make_oper(hub, "srf2op")
    try:
        await _squit_tls_leaf(op)

        first = await _tls_client(hub, "srf2a")
        try:
            async with _tls_gateway(hub, "tlspeer.test.net", 42):
                await asyncio.sleep(0.5)
                await _join(first, channel)
                await first.send(f"MODE {channel} +Z")
                await asyncio.sleep(0.5)

                flags = await _channel_mode_flags(first, channel)
                assert flags is not None and "Z" in flags and "z" not in flags, (
                    f"sanity: expected +Z with a single secure group, got {flags!r}"
                )

            # Gateway disconnected here -> secure groups recomputed/renumbered.
            await asyncio.sleep(1.0)

            second = await _tls_client(hub, "srf2b")
            try:
                await _join(second, channel)
                await asyncio.sleep(0.5)

                flags = await _channel_mode_flags(first, channel)
                assert flags is not None
                assert "z" not in flags and "Z" in flags, (
                    "both members are TLS clients on the same server, so the "
                    f"channel must remain +Z, got {flags!r} "
                    "(finding 2: stale cached group IDs after renumbering)"
                )
            finally:
                await second.disconnect()
        finally:
            await first.disconnect()
    finally:
        await op.disconnect()


# ---------------------------------------------------------------------------
# Finding 3: insecure group 0 must not flip a mixed channel back to +Z
# ---------------------------------------------------------------------------


async def test_z_channel_keeps_z_when_only_plaintext_members_remain(ircd_tls_network):
    """When the TLS members of a mixed +z channel all leave, the channel must
    not announce -z+Z: the remaining members are plaintext, so claiming a
    secure TLS-only channel is wrong.

    The buggy code counts group 0 (insecure) as "one group present" and flips
    to +Z.
    """
    hub = ircd_tls_network["hub"]
    channel = "#srf3"
    op = await _make_oper(hub, "srf3op")
    try:
        await _squit_tls_leaf(op)

        async with _tls_gateway(hub, "tlspeer.test.net", 43):
            await asyncio.sleep(0.5)

            tls_user = await _tls_client(hub, "srf3tls")
            plain = IRCClient()
            await plain.connect(hub["host"], hub["port"])
            await plain.register("srf3plain", "testuser", "Plain member")
            try:
                await _join(tls_user, channel)
                await _join(plain, channel)
                await tls_user.send(f"MODE {channel} +Z")
                await asyncio.sleep(0.5)

                flags = await _channel_mode_flags(tls_user, channel)
                assert flags is not None and "z" in flags, (
                    f"sanity: expected local +z on mixed channel, got {flags!r}"
                )

                await tls_user.send(f"PART {channel}")
                await tls_user.wait_for("PART", timeout=5.0)
                part_seen = await plain.wait_for("PART", timeout=5.0)
                assert channel in part_seen.params, (
                    f"sanity: plain member must see the PART, got {part_seen!r}"
                )
                await asyncio.sleep(0.5)

                flags = await _channel_mode_flags(plain, channel)
                assert flags is not None
                assert "z" in flags and "Z" not in flags, (
                    "only plaintext members remain; the channel must not claim "
                    f"to be a secure TLS-only (+Z) channel, got {flags!r} "
                    "(finding 3: sid 0 counted as a secure group)"
                )
            finally:
                await plain.disconnect()
                await tls_user.disconnect()
    finally:
        await op.disconnect()


# ---------------------------------------------------------------------------
# Finding 4: same-server TLS clients share a secure path
# ---------------------------------------------------------------------------


async def test_same_server_tls_clients_share_secure_path(ircd_tls_network):
    """Two TLS clients on the same server trivially share a secure path (no
    server-to-server hop is involved), even when that server has no TLS
    server links.

    Prefer tests/secure_path/test_single_server.py for the true never-linked
    case: this test SQUITs the leaf, which itself recomputes groups and can
    mask a missing startup call to compute_secure_path_groups().
    """
    hub = ircd_tls_network["hub"]
    op = await _make_oper(hub, "srf4op")
    try:
        # No TLS server links at all: the hub is on its own.
        await _squit_tls_leaf(op)
        await asyncio.sleep(0.5)

        alice = await _tls_client(hub, "srf4a")
        bob = await _tls_client(hub, "srf4b")
        try:
            msgs = await _collect_whois(alice, "srf4b")
            text = _whois_secure_text(msgs)
            assert text is not None, (
                f"expected 671 for TLS user, got {msgs}"
            )
            assert "secure network path" in text.lower(), (
                "two TLS clients on the same server must share a secure "
                f"path, got {text!r} "
                "(finding 4: standalone server never gets a secure group)"
            )
        finally:
            await bob.disconnect()
            await alice.disconnect()
    finally:
        await op.disconnect()
