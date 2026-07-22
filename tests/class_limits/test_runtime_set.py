"""Runtime /SET of flood features must apply to classless clients.

Regression test: find_max_flood()/get_sendq() cache the feature-default
fallback into the per-client limit cache.  A client whose class was removed
by a rehash falls back to FEAT_CLIENT_FLOOD -- but with the fallback cached,
a later runtime ``SET CLIENT_FLOOD`` never reaches that client until the
next rehash.  The fallback must be re-read from the feature on each call.
"""

import asyncio

import pytest

from class_limits.helpers import (
    FLOOD_KILL_MARGIN,
    LOCAL_FLOOD,
    assert_survives_flood,
    rehash_config,
    restore_config,
)
from tls.helpers import oper_up

pytestmark = pytest.mark.limits


async def test_set_client_flood_applies_to_classless_client(
    limits_oper, make_limits_client, limits_config_snapshot
):
    """SET CLIENT_FLOOD must take effect for clients on the feature default."""
    # Grant PRIV_SET to the oper block (denied to global opers by default).
    text = limits_config_snapshot.replace(
        'name = "testoper";',
        'name = "testoper";\n        set = yes;',
    )
    restore_config(text)
    await rehash_config(limits_oper)
    try:
        setoper = await make_limits_client("setoper1")
        await oper_up(setoper)
        user = await make_limits_client("setuser1")

        # Remove the Local class entirely; the user's attached conf now
        # points at an invalidated class, so its flood limit falls back to
        # FEAT_CLIENT_FLOOD (1024).  New connections use DefaultFlood.
        s = text.index('Class {\n        name = "Local";')
        e = text.index('Class {\n        name = "OperClass";')
        text_b = (text[:s] + text[e:]).replace(
            'Client { ip = "*"; class = "Local"; };',
            'Client { ip = "*"; class = "DefaultFlood"; };',
        )
        restore_config(text_b)
        await rehash_config(limits_oper)

        # Make the server read from the user so the fallback limit is
        # resolved (and, with the bug, frozen into the cache) at 1024.
        await user.send("TIME")
        await user.wait_for("391")

        # Raise the default at runtime -- no rehash.
        await setoper.send("SET CLIENT_FLOOD 4096")
        await asyncio.sleep(0.3)

        # Above the old default, below the new one: survives iff the new
        # feature value is actually consulted.
        await assert_survives_flood(user, LOCAL_FLOOD + FLOOD_KILL_MARGIN)
    finally:
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)
