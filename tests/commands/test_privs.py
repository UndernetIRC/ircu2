"""Default global operator privileges include unlimit_query again (commit
213e982); the other historical exclusions are unchanged."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.single_server


async def _privs(client, nick):
    await client.send(f"PRIVS {nick}")
    msg = await client.wait_for("270", timeout=5.0)
    return {p.lower() for p in msg.params[-1].split()}


async def test_default_global_oper_privs(oper):
    privs = await _privs(oper, oper.nick)
    assert "unlimit_query" in privs, privs
    # Granted explicitly in the Operator block.
    assert "set" in privs and "wide_gline" in privs, privs
    # Still excluded by default for global opers.
    for excluded in ("walk_lchan", "badchan", "local_badchan", "apass_opmode"):
        assert excluded not in privs, privs
    # A couple of the always-granted privileges.
    for granted in ("chan_limit", "show_invis", "kill", "gline", "rehash"):
        assert granted in privs, privs


async def test_privs_is_oper_only(make_client):
    client = await make_client("privsplain")
    await client.send("PRIVS privsplain")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"
