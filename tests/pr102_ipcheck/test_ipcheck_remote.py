"""IPcheck accounting for remote (server-introduced) clients.

IPcheck_remote_connect() shares the per-address registry with local
connections: a user introduced by another server with the same IP as a
local client raises that address's connected count (visible in the "on N"
registry notice given to local clients, and used by Client-block maxlinks),
and IPcheck_disconnect() releases it again when the user goes away with its
server.  Remote clients are never rate-limited themselves.

Uses the plain hub (IPCHECK_CLONE_LIMIT is set high there, so local
connects in this test are never throttled) and a P10 pseudo-server that
introduces a user carrying the test host's own address.
"""

from __future__ import annotations

import pytest

from pr102_ipcheck.helpers import disconnect_all, register_with_notice, userip
from irc_client import IRCClient
from p10_server import P10Server
from tls.helpers import oper_up

pytestmark = pytest.mark.multi_server


async def test_remote_user_with_same_ip_counts_and_releases(ircd_network):
    hub = ircd_network["hub"]
    oper = local_a = local_b = local_c = None
    srv = None
    try:
        oper = IRCClient()
        await oper.connect(hub["host"], hub["port"])
        await oper.register("ipcrop", "oper", "IPcheck oper")
        await oper_up(oper)
        my_ip = await userip(oper, "ipcrop")

        local_a, na = await register_with_notice(hub["host"], hub["port"], "ipcra")

        srv = P10Server(name="services.test.net", numeric=4, password="testpass")
        await srv.connect(hub["host"], hub["server_port"])
        await srv.handshake()
        await srv.introduce_user("ipcremote", ip=my_ip)
        # Wait until the hub knows the remote user before measuring.
        await oper.send("WHOIS ipcremote")
        await oper.wait_for("311", timeout=5.0)

        local_b, nb = await register_with_notice(hub["host"], hub["port"], "ipcrb")
        assert nb.connected == na.connected + 2, (na, nb)   # local_b + remote

        # Take the pseudo-server down: its user leaves with it.
        await srv.disconnect()
        srv = None
        await oper.send("WHOIS ipcremote")
        await oper.wait_for("401", timeout=5.0)

        local_c, nc = await register_with_notice(hub["host"], hub["port"], "ipcrc")
        assert nc.connected == na.connected + 2, (na, nb, nc)  # a, b, c: remote gone
    finally:
        if srv is not None:
            try:
                await srv.disconnect()
            except Exception:
                pass
        await disconnect_all(local_a, local_b, local_c, oper)


async def test_remote_user_with_other_ip_does_not_count(ircd_network):
    hub = ircd_network["hub"]
    local_a = local_b = None
    srv = None
    try:
        local_a, na = await register_with_notice(hub["host"], hub["port"], "ipcoa")

        srv = P10Server(name="notulined.test.net", numeric=5, password="testpass")
        await srv.connect(hub["host"], hub["server_port"])
        await srv.handshake()
        await srv.introduce_user("ipcother", ip="192.0.2.77")
        await local_a.send("WHOIS ipcother")
        await local_a.wait_for("311", timeout=5.0)

        local_b, nb = await register_with_notice(hub["host"], hub["port"], "ipcob")
        assert nb.connected == na.connected + 1, (na, nb)
    finally:
        if srv is not None:
            try:
                await srv.disconnect()
            except Exception:
                pass
        await disconnect_all(local_a, local_b)
