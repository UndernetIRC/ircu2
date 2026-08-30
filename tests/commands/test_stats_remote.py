"""STATS forwards its optional extra parameter to the target server and only
then decides whether the local handler accepts it (commit 1f5142d)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.multi_server


async def _stats(client, args, end="219"):
    await client.send(f"STATS {args}")
    return await client.collect_until(end, timeout=8.0)


def _ports(msgs):
    return sorted(m.params[2] for m in msgs if m.command == "217")


async def test_remote_stats_p_with_port_filter(ircd_network, oper):
    msgs = await _stats(oper, "P leaf1.test.net 6668")
    assert _ports(msgs) == ["6668"], _ports(msgs)
    assert msgs[-1].prefix == "leaf1.test.net", msgs[-1].raw


async def test_remote_stats_p_without_filter_lists_all(ircd_network, oper):
    msgs = await _stats(oper, "P leaf1.test.net")
    assert _ports(msgs) == ["4401", "6668", "6690"], _ports(msgs)


async def test_local_stats_p_with_port_filter(ircd_network, oper):
    msgs = await _stats(oper, "P hub.test.net 6667")
    assert _ports(msgs) == ["6667"], _ports(msgs)


async def test_extra_param_ignored_for_non_varparam_stats(ircd_network, oper):
    """A stats type without VARPARAM still works with a stray parameter."""
    local = await _stats(oper, "m hub.test.net junkparam")
    assert any(m.command == "212" for m in local)
    assert local[-1].command == "219" and local[-1].prefix == "hub.test.net"

    remote = await _stats(oper, "m leaf1.test.net junkparam")
    assert any(m.command == "212" for m in remote)
    assert remote[-1].prefix == "leaf1.test.net"
