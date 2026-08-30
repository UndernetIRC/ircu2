"""NOTICE nick@server follows the PRIVMSG nick@server rules (commits 0039f1f,
9f28062).

Only service servers (SERVER flag +s) may be addressed with nick@server.
For a non-service server, or an unknown server, the sender gets
ERR_NOSUCHNICK and nothing is delivered.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.single_server


async def test_notice_to_local_non_service_user_is_refused(make_client):
    sender = await make_client("dn1")
    target = await make_client("dnt1")
    await sender.send("NOTICE dnt1@hub.test.net :are you there")
    err = await sender.wait_for("401", timeout=5.0)
    assert err.params[1] == "dnt1@hub.test.net", err.raw
    await target.assert_no_message("NOTICE", timeout=1.0)


async def test_privmsg_to_local_non_service_user_is_refused(make_client):
    """Same rule for PRIVMSG (pre-existing behaviour, kept in sync)."""
    sender = await make_client("dn2")
    target = await make_client("dnt2")
    await sender.send("PRIVMSG dnt2@hub.test.net :are you there")
    err = await sender.wait_for("401", timeout=5.0)
    assert err.params[1] == "dnt2@hub.test.net", err.raw
    await target.assert_no_message("PRIVMSG", timeout=1.0)


async def test_notice_to_unknown_server_is_refused(make_client):
    sender = await make_client("dn3")
    await sender.send("NOTICE somebody@no.such.server :hi")
    err = await sender.wait_for("401", timeout=5.0)
    assert err.params[1] == "somebody@no.such.server", err.raw


async def test_notice_to_service_server_is_forwarded(make_client, ulined_server):
    await ulined_server.introduce_user("DnSvc", modes="+ik")
    sender = await make_client("dn4")
    await sender.send("NOTICE DnSvc@services.test.net :hello service")
    line = await ulined_server.wait_for_token("O", timeout=5.0)
    assert "DnSvc@services.test.net :hello service" in line, line
    await sender.assert_no_message("401", timeout=1.0)


async def test_privmsg_to_service_server_is_forwarded(make_client, ulined_server):
    await ulined_server.introduce_user("DpSvc", modes="+ik")
    sender = await make_client("dn5")
    await sender.send("PRIVMSG DpSvc@services.test.net :hello service")
    line = await ulined_server.wait_for_token("P", timeout=5.0)
    assert "DpSvc@services.test.net :hello service" in line, line


@pytest.mark.multi_server
async def test_notice_to_user_on_non_service_leaf_is_refused(ircd_network, make_client):
    leaf = ircd_network["leaf1"]
    target = await make_client("dnt6", host=leaf["host"], port=leaf["port"])
    sender = await make_client("dn6")
    await sender.send("NOTICE dnt6@leaf1.test.net :leaf?")
    err = await sender.wait_for("401", timeout=5.0)
    assert err.params[1] == "dnt6@leaf1.test.net", err.raw
    await target.assert_no_message("NOTICE", timeout=1.0)
