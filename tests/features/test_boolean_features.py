"""Feature handling changes:

* 170d288 — Boolean features accept "0" and "1".
* d7d9b5f — HIS_REMOTE is a Boolean feature (and gates remote queries).
* 87e808d — OPLEVELS and ZANNELS default to FALSE.
* 22c02d1 — MAXIMUM_LINKS no longer exists.
"""

from __future__ import annotations

import asyncio

import pytest

from common import drain, set_feature

pytestmark = pytest.mark.multi_server


async def _get(oper, name):
    await drain(oper, 0.2)  # discard any pending SET/RESET replies
    await oper.send(f"GET {name}")
    msg = await oper.wait_for("284", timeout=10.0)
    return msg.params[-1]


async def _set(oper, name, value):
    await set_feature(oper, name, value)


async def test_his_remote_is_boolean(oper):
    assert await _get(oper, "HIS_REMOTE") == "Boolean value of HIS_REMOTE: TRUE"


async def test_boolean_accepts_0_and_1(oper):
    try:
        await _set(oper, "HIS_REMOTE", "0")
        assert await _get(oper, "HIS_REMOTE") == "Boolean value of HIS_REMOTE: FALSE"
        await _set(oper, "HIS_REMOTE", "1")
        assert await _get(oper, "HIS_REMOTE") == "Boolean value of HIS_REMOTE: TRUE"
    finally:
        await _set(oper, "HIS_REMOTE", "TRUE")


async def test_his_remote_gates_remote_queries(ircd_network, oper, make_client):
    """Both the local and the target server check HIS_REMOTE in hunt_server_cmd()."""
    from cap_helpers import oper_up

    leaf = ircd_network["leaf1"]
    leaf_oper = await make_client("hisleafop", host=leaf["host"], port=leaf["port"])
    await oper_up(leaf_oper)

    user = await make_client("hisrem1")
    await user.send("TIME leaf1.test.net")
    err = await user.wait_for("481", timeout=5.0)
    assert err.command == "481"

    await _set(oper, "HIS_REMOTE", "0")
    try:
        # Hub forwards now, but leaf1 still refuses (its own HIS_REMOTE).
        await user.send("TIME leaf1.test.net")
        err = await user.wait_for("481", timeout=5.0)
        assert err.command == "481"

        await _set(leaf_oper, "HIS_REMOTE", "0")
        await user.send("TIME leaf1.test.net")
        reply = await user.wait_for("391", timeout=5.0)
        assert reply.params[1] == "leaf1.test.net", reply.raw
    finally:
        await _set(oper, "HIS_REMOTE", "1")
        await _set(leaf_oper, "HIS_REMOTE", "1")

    await user.send("TIME leaf1.test.net")
    err = await user.wait_for("481", timeout=5.0)
    assert err.command == "481"


async def test_oplevels_and_zannels_default_false(oper):
    assert await _get(oper, "OPLEVELS") == "Boolean value of OPLEVELS: FALSE"
    assert await _get(oper, "ZANNELS") == "Boolean value of ZANNELS: FALSE"


async def test_reset_restores_default(oper):
    await _set(oper, "ZANNELS", "1")
    try:
        assert await _get(oper, "ZANNELS") == "Boolean value of ZANNELS: TRUE"
    finally:
        await oper.send("RESET ZANNELS")
        await oper.wait_for("284", timeout=10.0)  # RESET answers on change
    assert await _get(oper, "ZANNELS") == "Boolean value of ZANNELS: FALSE"


async def test_maximum_links_removed(oper):
    await oper.send("GET MAXIMUM_LINKS")
    err = await oper.wait_for("493", timeout=5.0)
    assert err.params[1] == "MAXIMUM_LINKS", err.raw
    await oper.send("SET MAXIMUM_LINKS 5")
    err = await oper.wait_for("493", timeout=5.0)
    assert err.params[1] == "MAXIMUM_LINKS", err.raw
