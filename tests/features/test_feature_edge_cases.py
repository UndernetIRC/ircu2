"""Edge cases for feature handling (commits 170d288, d7d9b5f, 87e808d, 22c02d1)."""

from __future__ import annotations

import pytest

from common import drain, get_feature, set_feature

pytestmark = pytest.mark.single_server


@pytest.mark.parametrize("value,expected", [
    ("YES", "TRUE"), ("NO", "FALSE"), ("ON", "TRUE"), ("OFF", "FALSE"),
    ("true", "TRUE"), ("false", "FALSE"), ("1", "TRUE"), ("0", "FALSE"),
])
async def test_boolean_spellings(oper, value, expected):
    try:
        await set_feature(oper, "JOIN_TARGET", value)
        assert await get_feature(oper, "JOIN_TARGET") == expected
    finally:
        await set_feature(oper, "JOIN_TARGET", "FALSE")


async def test_bad_boolean_value_is_rejected(oper):
    await drain(oper, 0.2)
    await oper.send("SET JOIN_TARGET maybe")
    err = await oper.wait_for("494", timeout=5.0)
    assert err.params[1] == "maybe" and err.params[2].endswith("JOIN_TARGET"), err.raw
    assert await get_feature(oper, "JOIN_TARGET") == "FALSE"


async def test_set_without_change_reports_value(oper):
    """SET always answers with RPL_FEATURE, even when nothing changed."""
    await drain(oper, 0.2)
    await oper.send("SET JOIN_TARGET FALSE")  # already FALSE
    msg = await oper.wait_for("284", timeout=5.0)
    assert msg.params[-1] == "Boolean value of JOIN_TARGET: FALSE"


async def test_set_and_get_require_privileges(make_client):
    client = await make_client("feat_plain")
    await client.send("SET HIS_REMOTE 0")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"
    await client.send("GET HIS_REMOTE")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"


async def test_his_remote_gates_other_remote_commands(oper, make_client):
    """MOTD/ADMIN/VERSION/STATS/LUSERS to a remote server are all gated."""
    user = await make_client("feat_rem")
    for cmd in ("MOTD leaf1.test.net", "ADMIN leaf1.test.net",
                "VERSION leaf1.test.net", "LUSERS * leaf1.test.net",
                "STATS u leaf1.test.net"):
        await user.send(cmd)
        err = await user.wait_for("481", timeout=5.0)
        assert err.command == "481", cmd


async def test_reset_unknown_feature(oper):
    await drain(oper, 0.2)
    await oper.send("RESET MAXIMUM_LINKS")
    err = await oper.wait_for("493", timeout=5.0)
    assert err.params[1] == "MAXIMUM_LINKS"


async def test_get_read_only_feature_reports_value(oper):
    """Boolean read-only features (e.g. HIS_STATS_l) are still readable."""
    assert await get_feature(oper, "HIS_STATS_l") in ("TRUE", "FALSE")
