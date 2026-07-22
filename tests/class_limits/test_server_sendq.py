"""Server links must use their Connect class sendq, not a stale cached default.

Regression test: get_sendq() caches the DEFAULTMAXSENDQLENGTH fallback into
cli_max_sendq when a client has no attached conf yet.  Anything queued to an
inbound server connection *before* its Connect block is attached (an error
numeric, a pre-registration reply, TLS auth notices) plants that default
(40000 bytes).  attach_conf() must clear the cache when the Connect block
attaches, or the link stays capped at the client default and dies with
"Max SendQ exceeded" on the first real burst.

The stalled server peer runs *inside* the container (docker exec + perl) so
its connection crosses the container loopback only; Docker Desktop's port
relay would otherwise buffer the whole flood and hide the sendq growth.
"""

import asyncio
from pathlib import Path

import pytest

from class_limits.helpers import (
    CONTAINER,
    patch_config,
    rehash_config,
    restore_config,
)

pytestmark = pytest.mark.limits

STALL_SCRIPT = Path(__file__).parent / "stall_server.pl"

# The Connect block's class in ircd-limits.conf ("Server") has sendq = 9 MB.
# The flood below (~2 MB) sits far above the 40000-byte feature default and
# far below the class limit, so the link survives iff the class sendq won.
FLOOD_MESSAGES = 5000
FLOOD_PAYLOAD = "x" * 400

# Raise the flooding oper's maxflood so a single large TCP read (up to the
# ircd's 61440-byte read buffer) cannot trip its own Excess Flood check.
_OPER_CLASS_OLD = (
    'name = "OperClass";\n'
    '        pingfreq = 1 minutes 30 seconds;\n'
    '        sendq = 320000;\n'
    '        maxflood = 1200;'
)
_OPER_CLASS_BLAST = (
    'name = "OperClass";\n'
    '        pingfreq = 1 minutes 30 seconds;\n'
    '        sendq = 320000;\n'
    '        maxflood = 100000;'
)
# Pin the server listener's socket send buffer so kernel autotuning cannot
# absorb the flood before the ircd's own sendq starts growing.  Listeners
# are reopened on rehash, so this takes effect for the stalled peer.
_FEATURES_OLD = "Features {"
_FEATURES_SMALL_SNDBUF = 'Features {\n        "SOCKSENDBUF" = "4096";'
# The stalled peer connects from the container's own loopback, not from the
# docker network gateway the base config expects.  Connect hosts must be
# literal IPs, so swap in the loopback address.
_CONNECT_HOST_OLD = 'host = "10.55.0.1";'
_CONNECT_HOST_LOOPBACK = 'host = "127.0.0.1";'


async def _run(*argv: str) -> None:
    proc = await asyncio.create_subprocess_exec(*argv)
    assert await proc.wait() == 0, f"command failed: {argv}"


async def test_inbound_server_link_uses_connect_class_sendq(
    limits_oper, ircd_limits, limits_config_snapshot
):
    """A pre-registration reply must not freeze a server link's sendq limit."""
    patch_config(**{
        _OPER_CLASS_OLD: _OPER_CLASS_BLAST,
        _FEATURES_OLD: _FEATURES_SMALL_SNDBUF,
        _CONNECT_HOST_OLD: _CONNECT_HOST_LOOPBACK,
    })
    stall = None
    try:
        await rehash_config(limits_oper)

        # Launch the stalled in-container server peer; it poisons the sendq
        # cache pre-registration, links as services.test.net, then stops
        # reading.
        await _run("docker", "cp", str(STALL_SCRIPT),
                   f"{CONTAINER}:/tmp/stall_server.pl")
        stall = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", CONTAINER, "perl", "/tmp/stall_server.pl",
            stdout=asyncio.subprocess.PIPE,
        )
        line = await asyncio.wait_for(stall.stdout.readline(), timeout=15.0)
        assert b"HANDSHAKE-DONE" in line, f"stall peer failed: {line!r}"

        # Drop the wallops echo so the oper's own sendq stays empty, then
        # blast ~2 MB through the stalled server link.
        await limits_oper.send(f"MODE {limits_oper.nick} -w")
        for i in range(FLOOD_MESSAGES):
            await limits_oper.send(f"WALLOPS :flood {i} {FLOOD_PAYLOAD}")
        await asyncio.sleep(2.0)

        # If the stale 40000-byte limit won, the ircd killed the link with
        # "Max sendQ exceeded" mid-flood.  A dying link can still show up in
        # LINKS with its info field replaced by the kill reason, so check
        # both presence and the info text.
        await limits_oper.send("LINKS")
        rows = {}
        while True:
            msg = await limits_oper.recv(timeout=10.0)
            if msg.command == "364":
                rows[msg.params[1]] = " ".join(msg.params)
            elif msg.command == "365":
                break
        services = rows.get("services.test.net")
        assert services is not None and "sendQ exceeded" not in services, (
            "server link was killed during the flood -- sendq limit stuck "
            "at the pre-registration default instead of the Connect class "
            f"sendq (LINKS: {rows})"
        )
    finally:
        if stall is not None:
            stall.kill()
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)
