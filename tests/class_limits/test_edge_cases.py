"""Edge cases for sendq/maxflood resolution and LIST behaviour."""

import asyncio

import pytest

from class_limits.helpers import (
    DEFAULT_FLOOD,
    FLOOD_KILL_MARGIN,
    LOCAL_FLOOD,
    REMOTE_OPER_FLOOD,
    assert_killed_by_flood,
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


async def test_list_completes_after_rehash(limits_oper, make_limits_client):
    """LIST should still complete normally after a REHASH clears caches."""
    user = await make_limits_client("listedge1")
    await rehash_config(limits_oper)

    await user.send("LIST")
    msgs = await user.collect_until("323", timeout=10.0)
    assert msgs[-1].command == "323"


async def test_list_completes_after_lower_sendq_rehash(
    limits_oper, make_limits_client, limits_config_snapshot
):
    """LIST should not stall when REHASH lowers the configured sendq."""
    user = await make_limits_client("listedge2")
    patch_config(**{
        _LOCAL_BLOCK_OLD:
        'name = "Local";\n'
        '        pingfreq = 1 minutes 30 seconds;\n'
        '        sendq = 4096;\n'
        '        maxflood = 1024;',
    })
    try:
        await rehash_config(limits_oper)
        await user.send("LIST")
        msgs = await user.collect_until("323", timeout=10.0)
        assert msgs[-1].command == "323"
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)


async def test_invalid_class_falls_back_to_default_flood(
    limits_oper, make_limits_client, limits_config_snapshot
):
    """Client whose class is replaced with a non-existent one falls back to defaults."""
    user = await make_limits_client("listedge3")
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


async def test_remote_oper_without_remoteopers_class_uses_local_limits(
    limits_oper, limits_services, make_limits_client, limits_config_snapshot
):
    """Without a RemoteOpers class, remote opers use their Client class limits."""
    user = await make_limits_client("listedge4")
    numnick = await limits_services.wait_for_user("listedge4")

    text = limits_config_snapshot
    start = text.index('Class {\n        name = "RemoteOpers";')
    end = text.index("Client { ip", start)
    text = text[:start] + text[end:]
    restore_config(text)
    try:
        await rehash_config(limits_oper)
        await limits_services.send_opmode(numnick, "+o")
        await asyncio.sleep(0.5)

        mid = (LOCAL_FLOOD + REMOTE_OPER_FLOOD) // 2
        await assert_killed_by_flood(user, mid)
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)
