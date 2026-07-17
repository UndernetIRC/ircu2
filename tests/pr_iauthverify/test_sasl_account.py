"""TDD tests for the iauthverify branch: auth_set_account() hardening.

The branch moves SASL "OK <account>" reply parsing from sasl.c into
auth_set_account() in s_auth.c. The parsing uses strtok() and copies the
result with ircd_strncpy() without checking for NULL: a services server
that replies "OK" or "OK " (no account name, or a malformed one like
"OK ::::") makes strtok() return NULL and the ircd dereferences it,
crashing the whole server.

These tests link a fake P10 services server to the hub, enable SASL via
netconf, run a client through SASL during registration, and have the
services server send back malformed OK replies. The server must survive
and the client must still be able to register.
"""

import asyncio
import time

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.single_server


@pytest.fixture
async def services(ircd_hub):
    """Connect a fake P10 services server to the hub and enable SASL."""
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    # Enable SASL through netconf, pointing at ourselves.
    await srv.send_config("sasl.server", "services.test.net")
    await srv.send_config("sasl.mechanisms", "PLAIN")
    await asyncio.sleep(0.5)
    yield srv
    await srv.disconnect()


async def _start_sasl(client, services):
    """Negotiate the sasl cap and send AUTHENTICATE PLAIN.

    Returns (hub_numeric, routing) parsed from the XQUERY the hub sends
    to the services server, so the test can send a matching XREPLY.
    """
    await client.send("CAP LS 302")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert "sasl" in msg.params[-1], "hub does not advertise sasl"

    await client.send("CAP REQ :sasl")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert msg.params[1] == "ACK", f"expected CAP ACK, got {msg.params}"

    await client.send("AUTHENTICATE PLAIN")

    # Hub relays the request: "<hubnum> XQ <servicesnum> sasl:<cookie> :SASL ..."
    line = await services.wait_for_token("XQ", timeout=5.0)
    parts = line.split()
    hub_num = parts[0]
    routing = parts[3]
    assert routing.startswith("sasl:")
    return hub_num, routing


async def _finish_registration(client, nick):
    """Complete registration after SASL and wait for the 001 welcome."""
    await client.send(f"NICK {nick}")
    await client.send(f"USER testuser 0 * :Test User")
    await client.send("CAP END")
    await client.wait_for("001", timeout=10.0)


async def test_sasl_ok_with_valid_account(ircd_hub, services):
    """Positive control: OK with a full account payload logs the client in."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        await services.send_xreply(hub_num, routing, "OK goodacct:42:0 +x")

        msg = await client.wait_for("903", timeout=5.0)
        assert msg is not None

        await _finish_registration(client, "iavok1")

        # The account must be attached: WHOIS shows 330 (RPL_WHOISACCOUNT).
        await client.send("WHOIS iavok1")
        found_account = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            msg = await client.recv(timeout=5.0)
            if msg.command == "330":
                found_account = msg.params[2]
            if msg.command == "318":  # end of WHOIS
                break
        assert found_account == "goodacct"
    finally:
        await client.disconnect()


@pytest.mark.parametrize("bad_reply", ["OK", "OK ", "OK ::::"])
async def test_sasl_ok_without_account_must_not_crash(
    ircd_hub, services, bad_reply
):
    """An OK reply with a missing or malformed account must not kill the ircd.

    On the unfixed branch, auth_set_account() passes strtok()'s NULL
    result to ircd_strncpy() and the server segfaults.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        await services.send_xreply(hub_num, routing, bad_reply)

        # Whatever the server decides about the reply, it must stay up:
        # the client must still be able to finish registering...
        await _finish_registration(client, "iavbad1")
    finally:
        await client.disconnect()

    # ...and brand-new connections must still be accepted.
    probe = IRCClient()
    await probe.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await probe.register("iavprobe", "testuser", "Test User")
    finally:
        await probe.send("QUIT :done")
        await probe.disconnect()
