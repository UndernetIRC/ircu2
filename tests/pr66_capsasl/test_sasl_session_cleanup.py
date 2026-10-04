"""A SASL session ended by the client or by the timeout must be forgotten.

AUTHENTICATE * and the SASL timeout cleared the client's cookie but left
it in the session table, still pointing at the client.  A reply the SASL
server sent for that cookie afterwards was delivered anyway -- an "OK"
logged in a client that had aborted -- and once the client had quit, the
stale entry pointed at freed memory.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = [
    pytest.mark.single_server,
    pytest.mark.usefixtures("reset_sasl_netconf"),
]


@pytest.fixture
async def services(ircd_hub):
    """Fake services server on the hub with SASL enabled."""
    srv = P10Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    await srv.send_config("sasl.server", "services.test.net")
    await srv.send_config("sasl.mechanisms", "PLAIN")
    await asyncio.sleep(0.5)
    yield srv
    await srv.disconnect()


async def _start_sasl(client: IRCClient, services: P10Server) -> tuple[str, str]:
    """Negotiate sasl and send AUTHENTICATE PLAIN; return (hub numeric, routing)."""
    await client.send("CAP LS 302")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert "sasl" in msg.params[-1], "hub does not advertise sasl"
    await client.send("CAP REQ :sasl")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert msg.params[1] == "ACK", msg.params
    await client.send("AUTHENTICATE PLAIN")
    # "<hubnum> XQ <servicesnum> sasl:<cookie> :SASL ..."
    parts = (await services.wait_for_token("XQ", timeout=5.0)).split()
    assert parts[3].startswith("sasl:"), parts
    return parts[0], parts[3]


async def _assert_not_logged_in(client: IRCClient) -> None:
    with pytest.raises(asyncio.TimeoutError):
        msg = await client.wait_for("903", timeout=2.0)
        pytest.fail(f"reply for an ended SASL session logged the client in: {msg}")


async def test_reply_after_abort_is_dropped(ircd_hub, services):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        await client.send("AUTHENTICATE *")
        await client.wait_for("906", timeout=5.0)

        await services.send_xreply(hub_num, routing, "OK abortacct:1:0 +x")
        await _assert_not_logged_in(client)
    finally:
        await client.disconnect()


async def test_reply_after_timeout_is_dropped(ircd_hub, services):
    await services.send_config("sasl.timeout", "2")
    await asyncio.sleep(0.5)
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        msg = await client.wait_for("904", timeout=10.0)
        assert "timed out" in msg.params[-1], msg.params

        await services.send_xreply(hub_num, routing, "OK lateacct:1:0 +x")
        await _assert_not_logged_in(client)
    finally:
        await client.disconnect()
