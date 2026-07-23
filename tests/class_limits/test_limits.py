"""Core sendq/maxflood behavioral tests."""

import pytest

from class_limits.helpers import (
    FLOOD_KILL_MARGIN,
    FLOOD_SURVIVE_MARGIN,
    LOCAL_FLOOD,
    OPER_FLOOD,
    _build_flood_payload,
    _send_raw_bytes,
    assert_killed_by_flood,
    assert_survives_flood,
)

pytestmark = pytest.mark.limits


async def test_normal_user_survives_below_flood_limit(make_limits_client):
    """A regular user sending just under maxflood should not be disconnected."""
    user = await make_limits_client("lim1")
    await assert_survives_flood(user, LOCAL_FLOOD - FLOOD_SURVIVE_MARGIN)


async def test_normal_user_killed_above_flood_limit(make_limits_client):
    """A regular user sending above maxflood should be killed with Excess Flood."""
    user = await make_limits_client("lim2")
    await assert_killed_by_flood(user, LOCAL_FLOOD + FLOOD_KILL_MARGIN)


async def test_local_oper_has_higher_flood_limit(make_limits_client):
    """A local oper should have the OperClass maxflood, not Local."""
    user = await make_limits_client("lim3")
    await user.send("OPER testoper operpass")
    await user.wait_for("381")

    mid = (LOCAL_FLOOD + OPER_FLOOD) // 2
    await assert_survives_flood(user, mid)


async def test_local_oper_killed_above_oper_class_limit(make_limits_client):
    """A local oper sending above OperClass maxflood should still be killed."""
    user = await make_limits_client("lim4")
    await user.send("OPER testoper operpass")
    await user.wait_for("381")

    await assert_killed_by_flood(user, OPER_FLOOD + FLOOD_KILL_MARGIN)


async def test_local_oper_deoper_restores_local_flood_limit(make_limits_client):
    """MODE -o must drop the cached OperClass maxflood back to Local."""
    user = await make_limits_client("lim5")
    await user.send("OPER testoper operpass")
    await user.wait_for("381")
    # Send a command while opered: the ircd resolves and caches the
    # OperClass maxflood when it reads from the client.  De-opering must
    # invalidate that cache, not just detach the Operator block.
    await user.send("TIME")
    await user.wait_for("391")

    await user.send("MODE lim5 -o")
    # Wait for the actual -o echo (OPER's +o echo may still be buffered);
    # this also guarantees the server processed the deoper before the flood
    # arrives, so the two cannot coalesce into a single read.
    while True:
        msg = await user.wait_for("MODE")
        if "-o" in msg.params[-1]:
            break

    mid = (LOCAL_FLOOD + OPER_FLOOD) // 2
    await assert_killed_by_flood(user, mid)


async def test_stats_y_reports_class_definitions(limits_oper):
    """STATS y should expose configured class sendq/maxflood values."""
    await limits_oper.send("STATS y")
    msgs = await limits_oper.collect_until("219", timeout=5.0)
    local = [
        m for m in msgs
        if m.command == "218" and len(m.params) >= 3 and m.params[2] == "Local"
    ]
    assert len(local) == 1
    assert int(local[0].params[6]) == 160000
    assert int(local[0].params[7]) == LOCAL_FLOOD


async def test_debug_snotice_reports_maxfl(limits_oper, make_limits_client):
    """DEBUG snotices should report the resolved maxfl for a flooding client."""
    from debug_support import enable_debug_snotices, wait_for_dbuf_maxfl_snotice

    user = await make_limits_client("limdebug1")
    await enable_debug_snotices(limits_oper)
    await _send_raw_bytes(user, _build_flood_payload(500))
    snap = await wait_for_dbuf_maxfl_snotice(limits_oper, timeout=5.0)
    assert snap.maxfl == LOCAL_FLOOD
