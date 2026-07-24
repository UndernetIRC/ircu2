"""Secure-path coverage for a standalone TLS server (no peer links).

Reproduces the bug where compute_secure_path_groups() was only invoked on
server link/SQUIT, so a lone ircd left &me.sid == 0 and same-server TLS
clients never shared a secure path.

These tests use the ircd_tls_hub fixture (TLS hub only — the leaf is never
started), so no SQUIT/CONNECT can mask a missing startup computation.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from secure_path.helpers import (
    channel_mode_flags as _channel_mode_flags,
    collect_whois as _collect_whois,
    join as _join,
    whois_secure_text as _whois_secure_text,
)

pytestmark = [pytest.mark.tls_single, pytest.mark.asyncio]


async def _tls_client(hub: dict, nick: str) -> IRCClient:
    client = IRCClient()
    await client.connect_tls(hub["host"], hub["tls_port"])
    await client.register(nick, "testuser", nick)
    return client


async def test_standalone_tls_clients_share_secure_path(ircd_tls_hub):
    """Several TLS clients on a never-linked server share a secure path."""
    hub = ircd_tls_hub
    nicks = ["sspath1", "sspath2", "sspath3", "sspath4"]
    clients = [await _tls_client(hub, nick) for nick in nicks]
    try:
        observer, *targets = clients
        for target in targets:
            msgs = await _collect_whois(observer, target.nick)
            text = _whois_secure_text(msgs)
            assert text is not None, (
                f"expected 671 for TLS peer {target.nick}, got {msgs}"
            )
            assert "secure network path" in text.lower(), (
                f"standalone TLS clients must share a secure path, "
                f"got {text!r} for WHOIS {target.nick} "
                "(missing compute_secure_path_groups at startup?)"
            )
    finally:
        for client in clients:
            await client.disconnect()


async def test_standalone_plaintext_observer_omits_path_suffix(ircd_tls_hub):
    """Plaintext observers still see 671 for TLS targets, without the path suffix."""
    hub = ircd_tls_hub
    tls_user = await _tls_client(hub, "ssplaint")
    plain = IRCClient()
    await plain.connect(hub["host"], hub["port"])
    await plain.register("ssplaino", "testuser", "Plain observer")
    try:
        msgs = await _collect_whois(plain, "ssplaint")
        text = _whois_secure_text(msgs)
        assert text is not None, f"expected 671 for TLS target, got {msgs}"
        assert "secure network path" not in text.lower(), (
            f"plaintext observer must not see path suffix, got {text!r}"
        )
    finally:
        await plain.disconnect()
        await tls_user.disconnect()


async def test_standalone_channel_stays_Z_with_several_tls_clients(ircd_tls_hub):
    """+Z with multiple same-server TLS members stays +Z (single secure group)."""
    hub = ircd_tls_hub
    channel = "#sszmany"
    nicks = ["ssz_a", "ssz_b", "ssz_c"]
    clients = [await _tls_client(hub, nick) for nick in nicks]
    try:
        for client in clients:
            await _join(client, channel)

        await clients[0].send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(clients[0], channel)
        assert flags is not None
        assert "Z" in flags, (
            f"expected +Z on standalone server with several TLS clients, "
            f"got {flags!r}"
        )
        assert "z" not in flags, (
            f"did not expect local +z when all members share one group, "
            f"got {flags!r}"
        )
    finally:
        for client in clients:
            await client.disconnect()


async def test_standalone_mixed_channel_shows_local_z(ircd_tls_hub):
    """TLS + plaintext members on a standalone server expose local +z."""
    hub = ircd_tls_hub
    channel = "#sszmix"

    tls_user = await _tls_client(hub, "ssmix_t")
    plain = IRCClient()
    await plain.connect(hub["host"], hub["port"])
    await plain.register("ssmix_p", "testuser", "Plain member")
    try:
        await _join(tls_user, channel)
        await _join(plain, channel)

        await tls_user.send(f"MODE {channel} +Z")
        await asyncio.sleep(0.5)

        flags = await _channel_mode_flags(tls_user, channel)
        assert flags is not None
        assert "z" in flags, (
            f"expected local +z for mixed TLS/plaintext members, got {flags!r}"
        )
    finally:
        await plain.disconnect()
        await tls_user.disconnect()
