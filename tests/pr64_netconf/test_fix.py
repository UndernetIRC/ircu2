"""TDD tests for PR #64: Network configuration (netconf).

PR #64 adds a dynamic network-wide configuration system that allows services
to set/update/delete configuration options via the CF (CONFIG) server-to-server
command. Key features:

- CF command with server handler only (clients get m_ignore)
- /STATS C (uppercase) for netconf entries, distinct from /STATS c (connect lines)
- Config entries are burst to newly linking servers
- Timestamp-based conflict resolution (newer wins)
- STAT_FLAG_CASESENS added to both 'c' and 'C' stat entries

Since CF is a server-to-server only command, client-level tests focus on:
1. The CONFIG command is properly recognized (not 421 unknown command)
2. /STATS C is a distinct stat from /STATS c (case sensitivity)
3. Non-opers are denied access to /STATS C
"""

import asyncio
import pytest

from tests.irc_client import IRCClient


pytestmark = pytest.mark.single_server


async def test_config_command_recognized(ircd_hub, make_client):
    """CONFIG must be a recognized command — not return 421 ERR_UNKNOWNCOMMAND.

    Before PR #64, CONFIG is not registered in the message table, so sending
    it produces 421. With the PR, CONFIG is registered with m_ignore for
    clients, so no response is sent (no 421, no error).

    This test fails on main (421 returned) and passes with the PR.
    """
    client = await make_client("nc64a")

    await client.send("CONFIG 1234567890 test.key testvalue")

    # Send a PING to flush the message queue and check what came back
    await client.send("PING :configcheck")
    msgs = await client.collect_until("PONG", timeout=5.0)
    for msg in msgs:
        if msg.command == "421" and "CONFIG" in msg.params[1]:
            pytest.fail(
                f"CONFIG should be recognized (not 421): {msg}"
            )


async def test_stats_C_uppercase_is_netconf(ircd_hub, make_client):
    """STATS C (uppercase) should return netconf entries, not connect lines.

    Before PR #64, 'c' has no STAT_FLAG_CASESENS, so both 'C' and 'c' map
    to the connect lines handler. This means STATS C returns RPL_STATSCLINE
    (213) entries showing server connect blocks.

    With PR #64, 'C' is a separate case-sensitive entry for netconf. Since
    no netconf entries are set by default, STATS C should return only
    RPL_ENDOFSTATS (219) with no RPL_STATSCLINE (213) entries.

    This test fails on main (gets 213 connect line entries for STATS C)
    and passes with the PR (STATS C returns only 219, no 213).
    """
    client = await make_client("nc64b")

    await client.send("OPER testoper operpass")
    await client.wait_for("381")  # RPL_YOUREOPER

    await client.send("STATS C")
    msgs = await client.collect_until("219", timeout=5.0)

    # With the PR, STATS C should NOT contain connect line entries (213)
    connect_lines = [m for m in msgs if m.command == "213"]
    assert len(connect_lines) == 0, (
        f"STATS C should show netconf (empty), not connect lines: {connect_lines}"
    )


async def test_stats_c_lowercase_still_returns_connect_lines(ircd_hub, make_client):
    """STATS c (lowercase) must still return server connect lines after the PR.

    The PR should not break the existing STATS c behavior. Connect line
    entries (RPL_STATSCLINE 213) should still appear for lowercase 'c'.
    """
    client = await make_client("nc64c")

    await client.send("OPER testoper operpass")
    await client.wait_for("381")

    await client.send("STATS c")
    msgs = await client.collect_until("219", timeout=5.0)

    # There should be at least one connect line (the hub has server links)
    connect_lines = [m for m in msgs if m.command == "213"]
    assert len(connect_lines) > 0, (
        "STATS c should still return connect lines (RPL_STATSCLINE 213)"
    )


async def test_stats_C_oper_only(ircd_hub, make_client):
    """Non-opers should get ERR_NOPRIVILEGES (481) for STATS C.

    HIS_STATS_C defaults to TRUE with STAT_FLAG_OPERFEAT, so non-opers
    are denied access and receive numeric 481.
    """
    client = await make_client("nc64d")

    # Don't OPER — query as a regular user
    await client.send("STATS C")
    msg = await client.wait_for("481", timeout=5.0)
    assert msg.command == "481", "Non-oper should get ERR_NOPRIVILEGES for STATS C"
