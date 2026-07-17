"""Integration tests for secure network path tracking (+Z/+z, WHOIS 671).

Exercises TLS server grouping (sid), WHOIS secure-path reporting, and
channel mode transitions between +Z (single secure group) and +z (mixed
groups). Uses the TLS docker topology plus a fake P10 TLS gateway with a
plaintext downstream leaf to simulate mixed secure groups.

+Z vs +z semantics:
- +Z (MODE_TLSONLY): TLS users only; propagated to the network as +Z.
- +z (MODE_TLSINSECURE): mixed secure groups; shown to *local* clients only
  in MODE 324. Servers still see +Z on the wire, but the channel keeps
  MODE_TLSONLY set internally so plaintext users cannot join either +Z or
  +z channels (469 ERR_TLSONLYCHAN).
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from irc_client import IRCClient, Message
from p10_server import P10Server
from tls.helpers import connect_link, oper_up
from tls_certs import client_ssl_context

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

TLS_GATEWAY = "tlspeer.test.net"
TLS_GATEWAY_NUM = 49


async def _collect_whois(client: IRCClient, target: str, timeout: float = 10.0) -> list[Message]:
    await client.send(f"WHOIS {target}")
    return await client.collect_until("318", timeout=timeout)


def _whois_secure_text(msgs: list[Message]) -> str | None:
    for msg in msgs:
        if msg.command == "671":
            return msg.params[-1] if msg.params else None
    return None


async def _ensure_tls_leaf_link(hub: dict) -> None:
    """Bring up hub <-> tls-leaf if a prior test has not already."""
    op = IRCClient()
    await op.connect(hub["host"], hub["port"])
    await op.register("splink", "oper", "Oper")
    try:
        await oper_up(op)
        await connect_link(op, "tls-leaf.test.net", 4401, timeout=45.0)
    finally:
        await op.disconnect()


async def _gateway_ping_loop(gateway: P10Server) -> None:
    """Keep the S2S link alive by answering PINGs while tests run clients."""
    try:
        while gateway.connected:
            await gateway.drain_messages(timeout=1.0)
    except (ConnectionError, asyncio.CancelledError, TimeoutError):
        pass


@pytest.fixture
async def tls_gateway(ircd_tls_network, request):
    """TLS P10 gateway with an attached plaintext downstream server."""
    hub = ircd_tls_network["hub"]
    downstream_name = f"plain-{request.node.name[:20]}.test.net"
    downstream_num = 50 + (hash(request.node.nodeid) % 200)
    ctx = client_ssl_context(cert="tlspeer")
    srv = P10Server(
        name=TLS_GATEWAY,
        numeric=TLS_GATEWAY_NUM,
        password="testpass",
        server_flags="s",
    )
    await srv.connect_tls(hub["host"], hub["server_port"], ctx)
    await srv.handshake()
    ping_task = asyncio.create_task(_gateway_ping_loop(srv))
    down_num = await srv.send_downstream_server(
        downstream_name,
        downstream_num,
        hop=2,
        flags="",
        description="Plain downstream via TLS gateway",
    )
    try:
        yield srv, down_num, downstream_num
    finally:
        ping_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ping_task
        await srv.disconnect()


async def _gateway_ready(gateway: P10Server) -> None:
    """No-op placeholder; the fixture keeps the gateway link alive."""
    if not gateway.connected:
        raise ConnectionError("TLS gateway server link is down")


async def _join(client: IRCClient, channel: str) -> None:
    await client.send(f"JOIN {channel}")
    await client.wait_for("JOIN", timeout=5.0)


async def _channel_mode_flags(client: IRCClient, channel: str) -> str | None:
    await client.send(f"MODE {channel}")
    msgs = await client.collect_until("324", timeout=5.0)
    for msg in msgs:
        if msg.command == "324" and len(msg.params) >= 3:
            return msg.params[2]
    return None


async def _join_rejected(
    client: IRCClient, channel: str, code: str = "469"
) -> Message:
    """JOIN must fail with a numeric error and must not succeed."""
    await client.send(f"JOIN {channel}")
    err = await client.wait_for(code, timeout=5.0)
    assert channel in err.params, (
        f"expected {code} to reference {channel}, got {err.params!r}"
    )
    with pytest.raises(asyncio.TimeoutError):
        await client.wait_for("JOIN", timeout=1.0)
    return err


# ---------------------------------------------------------------------------
# WHOIS secure network path
# ---------------------------------------------------------------------------


async def test_whois_secure_path_same_tls_mesh(ircd_tls_network):
    """Two TLS users on a fully TLS-linked mesh share a secure path."""
    hub = ircd_tls_network["hub"]
    leaf = ircd_tls_network["leaf"]
    await _ensure_tls_leaf_link(hub)

    leaf_user = IRCClient()
    await leaf_user.connect_tls(leaf["host"], leaf["tls_port"])
    await leaf_user.register("secleaf1", "testuser", "Secure Leaf")

    observer = IRCClient()
    await observer.connect_tls(hub["host"], hub["tls_port"])
    await observer.register("secobs1", "testuser", "Observer")

    try:
        msgs = await _collect_whois(observer, "secleaf1")
        text = _whois_secure_text(msgs)
        assert text is not None, f"expected 671 for TLS user, got {msgs}"
        assert "secure network path" in text.lower(), (
            f"expected shared secure path in WHOIS 671, got {text!r}"
        )
    finally:
        await observer.disconnect()
        await leaf_user.disconnect()


async def test_whois_no_secure_path_plaintext_client(ircd_tls_network):
    """Plaintext clients are not reported as using a secure connection."""
    hub = ircd_tls_network["hub"]

    plain = IRCClient()
    await plain.connect(hub["host"], hub["port"])
    await plain.register("secplain", "testuser", "Plain")

    observer = IRCClient()
    await observer.connect_tls(hub["host"], hub["tls_port"])
    await observer.register("secobs2", "testuser", "Observer")

    try:
        msgs = await _collect_whois(observer, "secplain")
        assert _whois_secure_text(msgs) is None, (
            "plaintext user should not receive RPL_WHOISSECURE (671)"
        )
    finally:
        await observer.disconnect()
        await plain.disconnect()


async def test_whois_secure_path_suffix_only_for_shared_path(ircd_tls_network):
    """671 omits the path suffix when the observer is not on the same secure path."""
    hub = ircd_tls_network["hub"]

    target = IRCClient()
    await target.connect_tls(hub["host"], hub["tls_port"])
    await target.register("sectls", "testuser", "TLS Target")

    plain_observer = IRCClient()
    await plain_observer.connect(hub["host"], hub["port"])
    await plain_observer.register("secobs4", "testuser", "Plain Observer")

    try:
        msgs = await _collect_whois(plain_observer, "sectls")
        text = _whois_secure_text(msgs)
        assert text is not None, f"expected 671 for TLS target, got {msgs}"
        assert "secure network path" not in text.lower(), (
            f"plaintext observer should not see path suffix, got {text!r}"
        )
    finally:
        await plain_observer.disconnect()
        await target.disconnect()


async def test_whois_tls_without_shared_path_to_plain_downstream(
    ircd_tls_network, tls_gateway
):
    """671 for a TLS peer omits secure-path text when groups differ."""
    hub = ircd_tls_network["hub"]
    gateway, down_num, downstream_num = tls_gateway

    await gateway.send_downstream_nick(
        down_num,
        "secremote",
        server_numeric=downstream_num,
        realname="Remote plain leaf user",
    )
    await asyncio.sleep(0.5)

    # Downstream user is not TLS — should not get 671 at all.
    observer = IRCClient()
    await observer.connect_tls(hub["host"], hub["tls_port"])
    await observer.register("secobs3", "testuser", "Observer")
    try:
        msgs = await _collect_whois(observer, "secremote")
        assert _whois_secure_text(msgs) is None, (
            "non-TLS remote user must not trigger RPL_WHOISSECURE"
        )
    finally:
        await observer.disconnect()


# ---------------------------------------------------------------------------
# Channel +Z / +z mode transitions
# ---------------------------------------------------------------------------


async def test_channel_stays_Z_single_secure_group(ircd_tls_network):
    """+Z channel with two TLS users on the same sid stays +Z."""
    hub = ircd_tls_network["hub"]
    channel = "#secz1"

    alice = IRCClient()
    await alice.connect_tls(hub["host"], hub["tls_port"])
    await alice.register("secz_a", "testuser", "Alice")

    bob = IRCClient()
    await bob.connect_tls(hub["host"], hub["tls_port"])
    await bob.register("secz_b", "testuser", "Bob")

    try:
        await _join(alice, channel)
        await _join(bob, channel)
        await alice.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(alice, channel)
        assert flags is not None
        assert "Z" in flags, f"expected +Z for single secure group, got {flags!r}"
        assert "z" not in flags, f"did not expect local +z, got {flags!r}"
    finally:
        await bob.disconnect()
        await alice.disconnect()


async def test_channel_switches_Z_to_z_on_mixed_sids(ircd_tls_network):
    """Setting +Z when two secure groups are present exposes +z locally."""
    hub = ircd_tls_network["hub"]
    channel = "#secz2"

    tls_local = IRCClient()
    await tls_local.connect_tls(hub["host"], hub["tls_port"])
    await tls_local.register("secz_tls", "testuser", "TLS local")

    plain_remote = IRCClient()
    await plain_remote.connect(hub["host"], hub["port"])
    await plain_remote.register("secz_plain", "testuser", "Plain remote")

    try:
        await _join(tls_local, channel)
        await _join(plain_remote, channel)

        await tls_local.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(tls_local, channel)
        assert flags is not None
        assert "z" in flags, f"expected local +z for mixed secure groups, got {flags!r}"
    finally:
        await plain_remote.disconnect()
        await tls_local.disconnect()


async def test_plaintext_join_rejected_on_Z_channel(ircd_tls_network):
    """Plaintext users cannot join a +Z channel (469)."""
    hub = ircd_tls_network["hub"]
    channel = "#secz4"

    tls_local = IRCClient()
    await tls_local.connect_tls(hub["host"], hub["tls_port"])
    await tls_local.register("secz_zop", "testuser", "TLS op")

    plain = IRCClient()
    await plain.connect(hub["host"], hub["port"])
    await plain.register("secz_zdeny", "testuser", "Plain denied")

    try:
        await _join(tls_local, channel)
        await tls_local.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(tls_local, channel)
        assert flags is not None and "Z" in flags, f"expected +Z, got {flags!r}"

        err = await _join_rejected(plain, channel)
        assert "+Z" in err.params[-1], (
            f"expected TLSONLY reason to mention +Z, got {err.params!r}"
        )
    finally:
        await plain.disconnect()
        await tls_local.disconnect()


async def test_plaintext_join_rejected_on_z_channel(ircd_tls_network):
    """Plaintext users cannot join a local +z channel either (469)."""
    hub = ircd_tls_network["hub"]
    channel = "#secz5"

    tls_local = IRCClient()
    await tls_local.connect_tls(hub["host"], hub["tls_port"])
    await tls_local.register("secz_zloc", "testuser", "TLS local")

    plain_member = IRCClient()
    await plain_member.connect(hub["host"], hub["port"])
    await plain_member.register("secz_zmem", "testuser", "Plain member")

    plain_joiner = IRCClient()
    await plain_joiner.connect(hub["host"], hub["port"])
    await plain_joiner.register("secz_znew", "testuser", "Plain joiner")

    try:
        await _join(tls_local, channel)
        await _join(plain_member, channel)

        await tls_local.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(tls_local, channel)
        assert flags is not None and "z" in flags, (
            f"expected local +z for mixed secure groups, got {flags!r}"
        )

        err = await _join_rejected(plain_joiner, channel)
        assert "+Z" in err.params[-1], (
            f"join rejection still cites +Z even when channel shows +z locally, "
            f"got {err.params!r}"
        )
    finally:
        await plain_joiner.disconnect()
        await plain_member.disconnect()
        await tls_local.disconnect()


async def test_cross_server_Z_stays_on_tls_mesh_join(ircd_tls_network):
    """+Z stays +Z when a linked TLS leaf user joins the same secure group."""
    hub = ircd_tls_network["hub"]
    leaf = ircd_tls_network["leaf"]
    await _ensure_tls_leaf_link(hub)
    channel = "#secz6"

    hub_user = IRCClient()
    await hub_user.connect_tls(hub["host"], hub["tls_port"])
    await hub_user.register("secz_hub", "testuser", "Hub TLS")

    leaf_user = IRCClient()
    await leaf_user.connect_tls(leaf["host"], leaf["tls_port"])
    await leaf_user.register("secz_leaf", "testuser", "Leaf TLS")

    try:
        await _join(hub_user, channel)
        await hub_user.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        await _join(leaf_user, channel)
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(hub_user, channel)
        assert flags is not None
        assert "Z" in flags, (
            f"linked TLS peers should keep +Z, got {flags!r}"
        )
        assert "z" not in flags, (
            f"did not expect local +z for single secure group, got {flags!r}"
        )
    finally:
        await leaf_user.disconnect()
        await hub_user.disconnect()


async def test_channel_reverts_z_to_Z_when_mixed_user_parts(ircd_tls_network):
    """When the foreign secure group leaves, +z reverts to +Z."""
    hub = ircd_tls_network["hub"]
    channel = "#secz3"

    tls_local = IRCClient()
    await tls_local.connect_tls(hub["host"], hub["tls_port"])
    await tls_local.register("secz_rt", "testuser", "TLS local")

    plain_remote = IRCClient()
    await plain_remote.connect(hub["host"], hub["port"])
    await plain_remote.register("secz_part", "testuser", "Plain part")

    try:
        await _join(tls_local, channel)
        await _join(plain_remote, channel)

        await tls_local.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)
        mixed = await _channel_mode_flags(tls_local, channel)
        assert mixed is not None and "z" in mixed, f"expected +z with mixed members, got {mixed!r}"

        await plain_remote.send(f"PART {channel}")
        await asyncio.sleep(0.5)

        clean = await _channel_mode_flags(tls_local, channel)
        assert clean is not None
        assert "z" not in clean, (
            f"expected +Z after remote user left mixed group, got {clean!r}"
        )
        assert "Z" in clean, f"expected +Z restored, got {clean!r}"
    finally:
        await plain_remote.disconnect()
        await tls_local.disconnect()
