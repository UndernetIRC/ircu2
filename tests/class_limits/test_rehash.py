"""Rehash behavior for cached sendq/maxflood limits."""

import asyncio

import pytest

from class_limits.helpers import (
    FLOOD_KILL_MARGIN,
    FLOOD_SURVIVE_MARGIN,
    LOCAL_FLOOD,
    REMOTE_OPER_FLOOD,
    assert_killed_by_flood,
    assert_survives_flood,
    patch_config,
    rehash_config,
    restore_config,
)

pytestmark = pytest.mark.limits

_LOCAL_BLOCK_OLD = (
    'name = "Local";\n'
    '        pingfreq = 1 minutes 30 seconds;\n'
    '        sendq = 160000;\n'
    '        maxflood = 1024;'
)
_REMOTE_BLOCK_OLD = (
    'name = "RemoteOpers";\n'
    '        pingfreq = 1 minutes 30 seconds;\n'
    '        sendq = 200000;\n'
    '        maxflood = 1200;'
)


async def test_rehash_lower_limit_kills_previously_safe_client(
    limits_oper, make_limits_client, limits_config_snapshot
):
    """After REHASH that lowers maxflood, a previously-safe burst now kills."""
    new_flood = 512
    safe_burst = new_flood + FLOOD_SURVIVE_MARGIN
    lethal_burst = new_flood + FLOOD_KILL_MARGIN

    user = await make_limits_client("rehash1")
    user_check = await make_limits_client("rehash1check")
    await assert_survives_flood(user_check, safe_burst)

    patch_config(**{
        _LOCAL_BLOCK_OLD:
        'name = "Local";\n'
        '        pingfreq = 1 minutes 30 seconds;\n'
        '        sendq = 160000;\n'
        f'        maxflood = {new_flood};',
    })
    try:
        await rehash_config(limits_oper)
        await assert_killed_by_flood(user, lethal_burst)
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)


async def test_rehash_raise_limit_survives_previously_lethal_burst(
    limits_oper, make_limits_client, limits_config_snapshot
):
    """After REHASH raising maxflood, a previously-lethal burst now survives."""
    new_flood = 4096
    lethal_burst = LOCAL_FLOOD + FLOOD_KILL_MARGIN

    user = await make_limits_client("rehash2")
    user_check = await make_limits_client("rehash2check")
    await assert_killed_by_flood(user_check, lethal_burst)

    patch_config(**{
        _LOCAL_BLOCK_OLD:
        'name = "Local";\n'
        '        pingfreq = 1 minutes 30 seconds;\n'
        '        sendq = 160000;\n'
        f'        maxflood = {new_flood};',
    })
    try:
        await rehash_config(limits_oper)
        await assert_survives_flood(user, lethal_burst)
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)


async def test_rehash_updates_remote_oper_flood_limit(
    limits_oper, limits_services, make_limits_client, limits_config_snapshot
):
    """Remote opers should pick up RemoteOpers class changes on REHASH."""
    new_flood = 768
    safe_burst = new_flood + FLOOD_SURVIVE_MARGIN
    lethal_burst = new_flood + FLOOD_KILL_MARGIN

    user = await make_limits_client("rehash3")
    numnick = await limits_services.wait_for_user("rehash3")
    await limits_services.send_opmode(numnick, "+o")
    await asyncio.sleep(0.5)

    user_check = await make_limits_client("rehash3check")
    numnick_check = await limits_services.wait_for_user("rehash3check")
    await limits_services.send_opmode(numnick_check, "+o")
    await asyncio.sleep(0.5)
    await assert_survives_flood(user_check, safe_burst)

    patch_config(**{
        _REMOTE_BLOCK_OLD:
        'name = "RemoteOpers";\n'
        '        pingfreq = 1 minutes 30 seconds;\n'
        '        sendq = 200000;\n'
        f'        maxflood = {new_flood};',
    })
    try:
        await rehash_config(limits_oper)
        await assert_killed_by_flood(user, lethal_burst)
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)


async def test_rehash_removed_class_falls_back_to_default_flood(
    limits_oper, make_limits_client, limits_config_snapshot
):
    """Clients whose class is removed fall back to FEAT_CLIENT_FLOOD."""
    from class_limits.helpers import DEFAULT_FLOOD

    user = await make_limits_client("rehash4")

    text = limits_config_snapshot.replace(
        'Client { ip = "*"; class = "Local"; };',
        'Client { ip = "*"; class = "GoneClass"; };',
    )
    restore_config(text)
    try:
        await rehash_config(limits_oper)
        await assert_killed_by_flood(user, DEFAULT_FLOOD + FLOOD_KILL_MARGIN)
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)
