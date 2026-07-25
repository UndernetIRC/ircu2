"""AWAY_BURST between servers (commit 8c396f0).

When a server links, each away user's state is sent as ``AWAY :<msg>``
immediately after their NICK in the client burst.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import burst_lines, connect_services, make_cap_client
from p10_server import strip_msg_tags

pytestmark = pytest.mark.multi_server


async def test_away_burst_between_servers(ircd_network):
    """AWAY state is sent in the S2S client burst after NICK."""
    hub = ircd_network["hub"]

    user = await make_cap_client(hub["host"], hub["port"], "awaybrst")
    await user.send("AWAY :burst me")
    await asyncio.sleep(0.3)

    srv = await connect_services(hub)
    try:
        away_lines = burst_lines(srv, "A")
        matched = [
            line for line in away_lines
            if line.endswith(":burst me") or " :burst me" in line
        ]
        assert matched, (
            f"Expected AWAY burst for awaybrst, got A lines: {away_lines!r}"
        )
        numnick = srv.get_user_numnick("awaybrst")
        assert numnick is not None
        assert any(
            strip_msg_tags(line).split()[0] == numnick for line in matched
        ), f"AWAY burst source was not awaybrst ({numnick}): {matched}"
    finally:
        await srv.disconnect()
        await user.disconnect()
