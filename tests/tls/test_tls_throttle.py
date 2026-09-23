"""IPcheck throttle on a TLS listener.

A throttled connection is refused in add_connection(), before any TLS
handshake, so the ircd has no way to tell a TLS client why.  It must
close the socket without writing anything: an "ERROR :... throttled" line
at that point is plaintext on a TLS port, which the client can only
report as a TLS protocol error.  A plaintext listener keeps the line.

The throttle only engages once the server has been up for
IPCHECK_CLONE_DELAY seconds, so the test lowers that (and the clone limit)
on the hub with a REHASH and restores both afterwards.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from debug_support import docker_exec
from irc_client import IRCClient
from tls.helpers import oper_up

pytestmark = pytest.mark.asyncio

HUB = "ircu-tls-hub"
CONF = "/opt/ircu/lib/ircd.conf"
CLONE_LIMIT = 3


def _sh(*cmd: str) -> None:
    docker_exec(HUB, "sh", "-c", " ".join(cmd))


def _set_features(limit: str, delay: str) -> None:
    _sh(
        f"sed -i -e 's/\"IPCHECK_CLONE_LIMIT\" = \"[0-9]*\"/\"IPCHECK_CLONE_LIMIT\" = \"{limit}\"/'",
        f"-e '/\"IPCHECK_CLONE_DELAY\"/d'",
        f"-e 's/\"IPCHECK_CLONE_LIMIT\" = \"{limit}\";/&\\n        \"IPCHECK_CLONE_DELAY\" = \"{delay}\";/'",
        CONF,
    )


def _connect_and_read(host: str, port: int, timeout: float = 5.0) -> bytes:
    """Open a TCP connection, send nothing, return whatever arrives before EOF."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        got = b""
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                got += data
        except (socket.timeout, ConnectionError):
            pass
        return got


async def _provoke_throttle(host: str, port: int) -> bytes:
    """Burn the clone allowance from this address, then return what the
    next (refused) connection is sent."""
    for _ in range(CLONE_LIMIT):
        with socket.create_connection((host, port), timeout=5.0):
            pass
    await asyncio.sleep(0.2)
    return await asyncio.to_thread(_connect_and_read, host, port)


async def test_throttled_tls_connection_gets_no_plaintext(ircd_tls_network):
    hub = ircd_tls_network["hub"]

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("throtop", "op", "throttle oper")
    assert (await oper_up(oper)).command == "381"

    await asyncio.to_thread(_sh, f"cp {CONF} {CONF}.orig")
    try:
        await asyncio.to_thread(_set_features, str(CLONE_LIMIT), "0")
        await oper.send("REHASH")
        await asyncio.sleep(1.0)

        # The plaintext port explains the refusal ...
        plain = await _provoke_throttle(hub["host"], hub["port"])
        assert b"throttled" in plain, f"plaintext port did not report the throttle: {plain!r}"

        # ... the TLS port must not: nothing has been negotiated, so any
        # bytes here are cleartext a TLS client cannot read.
        tls = await _provoke_throttle(hub["host"], hub["tls_port"])
        assert tls == b"", f"cleartext sent on a throttled TLS connection: {tls!r}"
    finally:
        await asyncio.to_thread(_sh, f"mv {CONF}.orig {CONF}")
        await oper.send("REHASH")
        await asyncio.sleep(1.0)
        # The oper's own address is now throttled until IPCHECK_CLONE_PERIOD
        # passes; the restored (large) clone limit lifts that immediately.
        await oper.disconnect()
