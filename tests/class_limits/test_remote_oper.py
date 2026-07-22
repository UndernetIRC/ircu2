"""Remote oper sendq/maxflood behavioral tests."""

import asyncio

import pytest

from class_limits.helpers import (
    FLOOD_KILL_MARGIN,
    LOCAL_FLOOD,
    REMOTE_OPER_FLOOD,
    assert_killed_by_flood,
    assert_survives_flood,
)

pytestmark = pytest.mark.limits


async def test_remote_oper_has_higher_flood_limit(
    limits_services, make_limits_client
):
    """OPMODE +o from UWorld should raise flood limit to RemoteOpers."""
    user = await make_limits_client("remoper1")
    numnick = await limits_services.wait_for_user("remoper1")

    await limits_services.send_opmode(numnick, "+o")
    await asyncio.sleep(0.5)

    mid = (LOCAL_FLOOD + REMOTE_OPER_FLOOD) // 2
    await assert_survives_flood(user, mid)


async def test_remote_oper_killed_above_remoteopers_limit(
    limits_services, make_limits_client
):
    """Remote oper sending above RemoteOpers maxflood should be killed."""
    user = await make_limits_client("remoper2")
    numnick = await limits_services.wait_for_user("remoper2")

    await limits_services.send_opmode(numnick, "+o")
    await asyncio.sleep(0.5)

    await assert_killed_by_flood(user, REMOTE_OPER_FLOOD + FLOOD_KILL_MARGIN)


async def test_non_oper_uses_local_limit_not_remoteopers(make_limits_client):
    """A regular user should have Local limits, not RemoteOpers limits."""
    user = await make_limits_client("remoper3")

    mid = (LOCAL_FLOOD + REMOTE_OPER_FLOOD) // 2
    await assert_killed_by_flood(user, mid)


async def test_deoper_restores_local_flood_limit(
    limits_services, make_limits_client
):
    """OPMODE -o should restore the Local class maxflood limit."""
    user = await make_limits_client("remoper4")
    numnick = await limits_services.wait_for_user("remoper4")

    await limits_services.send_opmode(numnick, "+o")
    await asyncio.sleep(0.3)
    # Send a command while opered: the ircd resolves and caches the
    # RemoteOpers maxflood when it reads from the client.  De-opering must
    # invalidate that cache, not just detach the conf.
    await user.send("TIME")
    await user.wait_for("391")

    await limits_services.send_opmode(numnick, "-o")
    await asyncio.sleep(0.3)

    mid = (LOCAL_FLOOD + REMOTE_OPER_FLOOD) // 2
    await assert_killed_by_flood(user, mid)
