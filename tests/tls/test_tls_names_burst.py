"""Regression: large TLS NAMES bursts must not drop the client.

Production report: after joining several busy channels (large NAMES replies), a
TLS client connection dropped with no ERROR. Root cause was incorrect TLS
sendq accounting on partial SSL_write / con_rexmit (default builds abort at
msgq_excise assert; --disable-asserts silently corrupts the queue).
"""

from __future__ import annotations

import pytest

from irc_client import IRCClient
from tls.helpers import (
    NAMES_BURST_CHANNELS,
    assert_client_alive,
    drain_channel_joins,
    populate_channels,
)

pytestmark = [pytest.mark.tls, pytest.mark.tls_stress, pytest.mark.asyncio]


@pytest.mark.timeout(300)
async def test_tls_names_burst_survives(ircd_tls_network):
    """Large NAMES replies over TLS must not drop the victim connection."""
    hub = ircd_tls_network["hub"]
    crowd: list[IRCClient] = []
    victim = IRCClient()
    try:
        crowd = await populate_channels(hub)

        await victim.connect_tls(hub["host"], hub["tls_port"])
        msgs = await victim.register("tlsburst", "victim", "TLS NAMES burst")
        assert any(m.command == "001" for m in msgs)

        await drain_channel_joins(victim, NAMES_BURST_CHANNELS, timeout=90.0)
        await assert_client_alive(victim)
    finally:
        await victim.disconnect()
        for c in crowd:
            try:
                await c.disconnect()
            except Exception:
                pass
