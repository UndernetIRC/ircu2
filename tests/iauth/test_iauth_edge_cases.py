"""IAuth statistics edge cases (commits b71fd1e, 4db6d5d)."""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import oper_up

pytestmark = pytest.mark.multi_server


async def _stats_lines(client, args, end_arg, timeout=8.0):
    await client.send(f"STATS {args}")
    lines = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        msg = await client.recv(timeout=max(0.1, deadline - loop.time()))
        if msg.command == "249":
            lines.append(msg.params[-1])
        elif msg.command == "219":
            assert msg.params[1] == end_arg, msg.raw
            return lines


async def test_two_opers_requesting_stats_concurrently(ircd_network, make_client):
    """The second request is queued and served by a follow-up "? stats2"."""
    leaf = ircd_network["leaf2"]
    a = await make_client("iae_a", host=leaf["host"], port=leaf["port"])
    b = await make_client("iae_b", host=leaf["host"], port=leaf["port"])
    await oper_up(a)
    await oper_up(b)
    await a.send("STATS iauth")
    await b.send("STATS iauth")
    la, lb = await asyncio.gather(
        _stats_lines_no_send(a, "iauthstats"), _stats_lines_no_send(b, "iauthstats")
    )
    assert any("stats-requests=" in l for l in la)
    assert any("stats-requests=" in l for l in lb)


async def _stats_lines_no_send(client, end_arg, timeout=8.0):
    lines = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        msg = await client.recv(timeout=max(0.1, deadline - loop.time()))
        if msg.command == "249":
            lines.append(msg.params[-1])
        elif msg.command == "219":
            assert msg.params[1] == end_arg, msg.raw
            return lines


async def test_iauthconf_reports_missing_version(ircd_network, oper):
    """The hub's iauth-tilded.pl sends no V line."""
    lines = await _stats_lines(oper, "iauthconf", "iauthconf")
    assert any("did not report a version" in l for l in lines), lines


async def test_iauth_stats_sync_path_on_hub(ircd_network, oper):
    """Without the S policy (hub stub) STATS iauth answers synchronously."""
    lines = await _stats_lines(oper, "iauth", "iauth")
    assert isinstance(lines, list)


async def test_stats_iauth_remote(ircd_network, oper):
    lines = await _stats_lines(oper, "iauth leaf2.test.net", "iauthstats")
    assert any("stats-requests=" in l for l in lines), lines
