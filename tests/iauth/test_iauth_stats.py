"""IAuth statistics and configuration reporting (commits b71fd1e, 4db6d5d,
e8c0791, 5dc3f97).

leaf2 runs tests/docker/iauth-test.pl with policy ARUS (the hub and leaf1
run the ~-forcing iauth-tilded.pl used by other suites).

* /STATS iauthconf shows the reported version; "... <server> get" asks the
  program for a fresh configuration ("? config") which the next query shows.
* /STATS iauth is asynchronous with the S policy: the server sends
  "? stats2", relays each S line as RPL_STATSDEBUG and ends with
  RPL_ENDOFSTATS iauthstats when the program sends "s".
* The stub's reply starts with a fragment terminated by a bare CR; ircd
  must drop it and continue parsing the following lines.
* The "u" line the server sends carries cli_user()->username (the USER
  name with the ~ from the failed ident lookup), not the empty ident result.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import oper_up

pytestmark = pytest.mark.multi_server


@pytest.fixture
async def leaf_oper(ircd_network, make_client):
    leaf = ircd_network["leaf2"]
    client = await make_client("iaop", host=leaf["host"], port=leaf["port"], username="iaoper")
    await oper_up(client)
    return client


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


async def test_iauthconf_reports_version(leaf_oper):
    lines = await _stats_lines(leaf_oper, "iauthconf", "iauthconf")
    assert any("iauth-test 1.0" in l for l in lines), lines


async def test_iauthconf_get_requests_fresh_config(leaf_oper):
    await _stats_lines(leaf_oper, "iauthconf leaf2.test.net get", "iauthconf")
    await asyncio.sleep(0.5)
    lines = await _stats_lines(leaf_oper, "iauthconf", "iauthconf")
    assert any("policy=ARUS" in l for l in lines), lines
    assert any("config-requests=" in l for l in lines), lines


async def test_iauth_stats_are_asynchronous(leaf_oper):
    lines = await _stats_lines(leaf_oper, "iauth", "iauthstats")
    assert any("stats-requests=" in l for l in lines), lines


async def test_iauth_stats_second_request_increments(leaf_oper):
    first = await _stats_lines(leaf_oper, "iauth", "iauthstats")
    second = await _stats_lines(leaf_oper, "iauth", "iauthstats")
    n1 = next(int(l.split("stats-requests=")[1]) for l in first if "stats-requests=" in l)
    n2 = next(int(l.split("stats-requests=")[1]) for l in second if "stats-requests=" in l)
    assert n2 == n1 + 1


async def test_control_character_fragment_is_dropped(leaf_oper):
    lines = await _stats_lines(leaf_oper, "iauth", "iauthstats")
    assert not any("garbage-fragment" in l for l in lines), lines
    assert any("stats-requests=" in l for l in lines), lines


async def test_username_line_carries_user_command_name(leaf_oper):
    """5dc3f97: "u" is sent with cli_user()->username (the USER name, tilded)."""
    lines = await _stats_lines(leaf_oper, "iauth", "iauthstats")
    mine = [l for l in lines if "nick=iaop " in l]
    assert mine, lines
    # Both are reported after the ~ for the failed ident lookup was prepended.
    assert "U=~iaoper" in mine[-1], mine[-1]
    assert "u=~iaoper" in mine[-1], mine[-1]


async def test_iauth_stats_requires_oper(ircd_network, make_client):
    leaf = ircd_network["leaf2"]
    client = await make_client("iaplain", host=leaf["host"], port=leaf["port"])
    await client.send("STATS iauth")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"
