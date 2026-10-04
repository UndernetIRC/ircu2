"""CAP NEW sasl for clients of a real leaf that (re)links to the SASL side.

``test_sasl_cap_burst_split.py`` only ever links a scripted server *into*
the ircd under test.  Here the ircd under test is a real leaf that is split
from the network, picks up a cap-notify client while alone, and then links
to the hub behind which the SASL server lives::

    leaf1.test.net --- hub.test.net --- services.test.net  (sasl.server)
    (client here)                       (fake, P10Server)

sasl.server/sasl.mechanisms reach the leaf only through the hub's CONFIG
burst, the SASL server only as a P-introduced downlink of the bursting hub,
so the transition must come from the hub's END_OF_BURST on the leaf.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server
from tls.helpers import links_contains, oper_up

pytestmark = [pytest.mark.multi_server, pytest.mark.asyncio]

HUB_NAME = "hub.test.net"
LEAF1_NAME = "leaf1.test.net"
SASL_SERVER = "services.test.net"
MECHANISMS = "PLAIN"


async def drain(client: IRCClient, seconds: float) -> None:
    """Consume whatever arrives within ``seconds``."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return
        try:
            await client.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            return


async def _oper(server: dict, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(server["host"], server["port"])
    await c.register(nick, "testuser", "Test User")
    msg = await oper_up(c)
    assert msg.command == "381", f"OPER failed for {nick}: {msg}"
    return c


async def _wait_links(c: IRCClient, peer: str, present: bool, timeout: float = 45.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await drain(c, 1.0)
        if await links_contains(c, peer, timeout=5.0) == present:
            return
    raise TimeoutError(f"{peer} LINKS presence never became {present}")


async def _collect_cap(client: IRCClient, timeout: float) -> list[tuple[str, str]]:
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


async def _isolated_leaf_client(hub_op, leaf_op, leaf1, nick: str) -> IRCClient:
    """Split leaf1 off and register a cap-notify client on it while alone.

    leaf1 has autoconnect, so it may relink on its own at any point; if it
    did by the time the client is registered, start over.
    """
    for _ in range(3):
        if await links_contains(hub_op, LEAF1_NAME):
            await hub_op.send(f"SQUIT {LEAF1_NAME} :test")
        await _wait_links(hub_op, LEAF1_NAME, False)
        await _wait_links(leaf_op, HUB_NAME, False)

        client = IRCClient()
        await client.connect(leaf1["host"], leaf1["port"])
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert "sasl" not in msg.params[-1], f"lone leaf advertises sasl: {msg.params}"
        await client.send("CAP END")
        await client.register(nick, "testuser", "Test User")
        await drain(client, 1.0)

        if not await links_contains(leaf_op, HUB_NAME):
            return client
        await client.disconnect()
    raise RuntimeError("leaf1 kept autoconnecting to the hub; could not isolate it")


async def _restore_link(hub_op, leaf1) -> None:
    """Leave hub and leaf1 linked for the tests that follow, whatever happened."""
    if not await links_contains(hub_op, LEAF1_NAME):
        await hub_op.send(f"CONNECT {LEAF1_NAME} {leaf1['server_port']}")
    await _wait_links(hub_op, LEAF1_NAME, True)


async def _run(ircd_network, *, leaf_initiates: bool, nick: str) -> None:
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    hub_op = await _oper(hub, f"{nick}ho")
    leaf_op = await _oper(leaf1, f"{nick}lo")
    srv = None
    client = None
    try:
        # 1. SASL server fully linked on the network side.
        srv = P10Server(name=SASL_SERVER, numeric=4, password="testpass")
        await srv.connect(hub["host"], hub["server_port"])
        await srv.begin_handshake()
        await srv.send_config("sasl.server", SASL_SERVER)
        await srv.send_config("sasl.mechanisms", MECHANISMS)
        await srv.send_end_of_burst()
        await srv.complete_handshake()

        # 2. cap-notify client on the lone leaf: no sasl on offer.
        client = await _isolated_leaf_client(hub_op, leaf_op, leaf1, nick)

        # 3. Link the leaf to the SASL side.
        if leaf_initiates:
            await leaf_op.send(f"CONNECT {HUB_NAME}")
        else:
            await hub_op.send(f"CONNECT {LEAF1_NAME} {leaf1['server_port']}")
        await _wait_links(leaf_op, SASL_SERVER, True)

        caps = await _collect_cap(client, 5.0)
        assert caps == [("NEW", f"sasl={MECHANISMS}")], caps
    finally:
        try:
            await _restore_link(hub_op, leaf1)
        finally:
            for c in (client, hub_op, leaf_op):
                if c is not None:
                    await c.disconnect()
            if srv is not None:
                await srv.disconnect()


@pytest.mark.timeout(300)
async def test_cap_new_when_hub_connects_to_leaf(ircd_network):
    await _run(ircd_network, leaf_initiates=False, nick="relnkA")


@pytest.mark.timeout(300)
async def test_cap_new_when_leaf_connects_to_hub(ircd_network):
    await _run(ircd_network, leaf_initiates=True, nick="relnkB")
