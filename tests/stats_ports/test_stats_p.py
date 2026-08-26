"""Regression test for STATS p (listening ports)."""

import pytest

from irc_client import IRCClient


@pytest.mark.single_server
async def test_stats_p_lists_ports(ircd_hub):
    """An oper issuing STATS p must receive RPL_STATSPLINE (217) lines."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.register("statsp", "testuser", "Test User")
    try:
        await client.send("OPER testoper operpass")
        await client.wait_for("381")

        await client.send("STATS p")
        msgs = await client.collect_until("219", timeout=5.0)
        plines = [m for m in msgs if m.command == "217"]
        print("STATS p replies:", [(m.command, m.params) for m in msgs])
        assert msgs[-1].command == "219"
        assert plines, f"STATS p returned no 217 lines: {[(m.command, m.params) for m in msgs]}"
        ports = {int(m.params[2]) for m in plines}
        assert {4400, 6667, 7000, 7001, 7002} <= ports, ports

        # Long-form alias and port filter.
        await client.send("STATS ports")
        msgs = await client.collect_until("219", timeout=5.0)
        assert [m for m in msgs if m.command == "217"], msgs

        await client.send("STATS p hub.test.net 6667")
        msgs = await client.collect_until("219", timeout=5.0)
        plines = [m for m in msgs if m.command == "217"]
        assert len(plines) == 1 and plines[0].params[2] == "6667", [(m.command, m.params) for m in msgs]
    finally:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()


async def _oper_client(host, port, nick):
    client = IRCClient()
    await client.connect(host, port)
    await client.register(nick, "testuser", "Test User")
    await client.send("OPER testoper operpass")
    await client.wait_for("381")
    return client


async def _stats_p(client, extra=""):
    await client.send(f"STATS p{extra}")
    msgs = await client.collect_until("219", timeout=5.0)
    return [m for m in msgs if m.command == "217"], msgs


@pytest.mark.multi_server
async def test_stats_p_remote_and_after_rehash(ircd_network):
    """STATS p hunted to a remote server, and STATS p after REHASH."""
    leaf1 = ircd_network["leaf1"]
    client = await _oper_client(leaf1["host"], leaf1["port"], "statsp2")
    try:
        plines, msgs = await _stats_p(client)
        print("leaf1 local:", [(m.command, m.params) for m in msgs])
        assert plines, msgs

        plines, msgs = await _stats_p(client, " hub.test.net")
        print("remote hub:", [(m.command, m.params) for m in msgs])
        assert plines, msgs
        assert any(m.prefix == "hub.test.net" for m in plines), plines

        await client.send("REHASH")
        await client.wait_for("382")
        plines, msgs = await _stats_p(client)
        print("leaf1 after rehash:", [(m.command, m.params) for m in msgs])
        assert plines, msgs
        assert all(m.params[-1] == "active" for m in plines), plines
    finally:
        await client.disconnect()


@pytest.mark.single_server
async def test_stats_p_tls_hub(ircd_tls_hub):
    """STATS p on a server with TLS/websocket/cloudflare listeners."""
    client = await _oper_client(ircd_tls_hub["host"], ircd_tls_hub["port"], "statsp3")
    try:
        plines, msgs = await _stats_p(client)
        print("tls hub:", [(m.command, m.params) for m in msgs])
        assert plines, msgs
        ports = {int(m.params[2]) for m in plines}
        assert {6677, 6697, 6698, 6699, 4440, 4441, 6700, 6701} <= ports, ports
        await client.send("REHASH")
        await client.wait_for("382")
        plines, msgs = await _stats_p(client)
        print("tls hub after rehash:", [(m.command, m.params) for m in msgs])
        ports2 = {int(m.params[2]) for m in plines}
        assert ports2 == ports, (ports, ports2)
    finally:
        await client.disconnect()
