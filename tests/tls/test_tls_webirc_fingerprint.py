"""
TLS WEBIRC gateway port: the gateway's client certificate is not the user's.

On a ``webirc = yes; tls = yes;`` Port the TLS peer is the gateway, so the
ircd must not store the peer certificate fingerprint on the client (it would
satisfy fingerprint-pinned Operator/Client blocks, be forwarded to services
and iauth, and be shown network-wide for every user behind the gateway).

Uses port 6703 (published as TLS_HUB["webirc_tls_port"]) and the WebIRC block
in tests/docker/ircd-tls-hub.conf.  The positive control (the same cert on a
plain user TLS port does satisfy ``certoper``) lives in test_tls_policy.py.

  pytest tests/tls/test_tls_webirc_fingerprint.py -v --timeout=300
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from tls_certs import client_ssl_context, fingerprint

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

WEBIRC_PASSWORD = "webirc-secret"
# RFC 5737 documentation range — the address the gateway claims for the user.
SPOOF_IP = "203.0.113.60"
SPOOF_HOST = "user.gateway.example"


async def _oper_result(client: IRCClient, name: str, password: str) -> list[str]:
    """Send OPER and collect numerics until success (381) or a failure code."""
    await client.send(f"OPER {name} {password}")
    got: list[str] = []
    deadline = asyncio.get_running_loop().time() + 10.0
    while asyncio.get_running_loop().time() < deadline:
        msg = await client.recv(timeout=5.0)
        got.append(msg.command)
        if msg.command in ("381", "532", "491", "464"):
            break
    return got


async def _whois_host(client: IRCClient, nick: str) -> str:
    await client.send(f"WHOIS {nick}")
    while True:
        msg = await client.recv(timeout=10.0)
        if msg.command == "311":
            return msg.params[3]
        if msg.command in ("318", "401"):
            raise AssertionError(f"WHOIS for {nick} failed: {msg}")


async def _connect_via_webirc(hub: dict, nick: str, cert: str) -> IRCClient:
    """Connect to the TLS WEBIRC port presenting the gateway's client cert."""
    client = IRCClient()
    await client.connect_tls(
        hub["host"], hub["webirc_tls_port"], ssl_context=client_ssl_context(cert=cert)
    )
    await client.send(f"WEBIRC {WEBIRC_PASSWORD} gateway {SPOOF_HOST} {SPOOF_IP}")
    msgs = await client.register(nick, "testuser", "tls webirc user")
    assert any(m.command == "001" for m in msgs), f"register via WEBIRC failed: {msgs}"
    return client


async def test_webirc_tls_port_does_not_store_gateway_fingerprint(ircd_tls_network):
    """certoper is pinned to the selfsigned cert; a gateway presenting it must not qualify the user."""
    hub = ircd_tls_network["hub"]
    assert len(fingerprint("selfsigned")) == 64
    client = await _connect_via_webirc(hub, "gwfp", cert="selfsigned")
    try:
        # WEBIRC itself was honoured: the user carries the spoofed address.
        host = await _whois_host(client, "gwfp")
        assert host == SPOOF_IP or host == SPOOF_HOST, f"WEBIRC not applied, WHOIS host {host!r}"

        got = await _oper_result(client, "certoper", "certpass")
        assert "381" not in got, f"gateway certificate satisfied the OPER fingerprint pin: {got}"
        assert "532" in got, f"expected ERR_TLSCLIFINGERPRINT, got {got}"
    finally:
        try:
            await client.send("QUIT :test done")
            await asyncio.sleep(0.05)
        except Exception:
            pass
        await client.disconnect()
