"""CAP NEW for a cap-notify client that has not finished registering.

cap-notify is enabled by negotiation (implicitly by ``CAP LS 302``), not by
registration, and the IRCv3 capability-negotiation spec lets ``CAP NEW`` be
"sent at any time", with ``*`` as the target while no nick is available.

A restarted leaf takes its clients back while it is still linking to the
network: they see no ``sasl`` in ``CAP LS``, and the SASL server becomes
reachable before they are registered.  If the NEW is only sent to registered
users they register without ever learning that sasl exists.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.single_server

SASL_SERVER = "services.test.net"
MECHANISMS = "PLAIN"


async def _collect_cap(client: IRCClient, timeout: float) -> list[tuple[str, str]]:
    """Return every (subcommand, argument) CAP message seen within timeout."""
    seen = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return seen
        try:
            msg = await client.wait_for("CAP", timeout=remaining)
        except asyncio.TimeoutError:
            return seen
        seen.append((msg.params[1], msg.params[-1]))


async def test_cap_new_reaches_client_still_registering(ircd_hub):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    srv = None
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert "sasl" not in msg.params[-1], msg.params
        # Registration stays suspended: no CAP END yet.
        await client.send("NICK capreg1")
        await client.send("USER testuser 0 * :Test User")

        # The SASL server links and is configured while we are still
        # negotiating.
        srv = P10Server(name=SASL_SERVER, numeric=4, password="testpass")
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        await srv.handshake()
        await srv.send_config("sasl.mechanisms", MECHANISMS)
        await srv.send_config("sasl.server", SASL_SERVER)

        caps = await _collect_cap(client, 3.0)
        assert caps and caps[-1] == ("NEW", f"sasl={MECHANISMS}"), caps

        # The announced capability is usable before registration completes.
        await client.send("CAP REQ :sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", msg.params

    finally:
        if srv is not None:
            await srv.disconnect()
        await client.disconnect()
