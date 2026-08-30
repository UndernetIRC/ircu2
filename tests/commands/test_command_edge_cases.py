"""Edge cases for WHOWAS, WHOX fields, CONNECT, PRIVS and remote STATS."""

from __future__ import annotations

import pytest

from common import collect
from irc_client import IRCClient


async def _register_and_quit(hub, nick, username):
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    await client.register(nick, username, "WhoWas Test")
    await client.send("QUIT :bye")
    await client.disconnect()


async def _whowas(client, args):
    await client.send(f"WHOWAS {args}")
    msgs = await client.collect_until("369", timeout=8.0)
    return msgs


@pytest.mark.single_server
async def test_whowas_comma_list_applies_limit_per_nick(ircd_hub, make_client):
    for u in ("a1", "a2"):
        await _register_and_quit(ircd_hub, "wwe_a", u)
    for u in ("b1", "b2", "b3"):
        await _register_and_quit(ircd_hub, "wwe_b", u)
    client = await make_client("wwe_q1")
    msgs = await _whowas(client, "wwe_a,wwe_b 0")
    entries = [m.params[1].lower() for m in msgs if m.command == "314"]
    assert entries.count("wwe_a") == 2 and entries.count("wwe_b") == 3, entries
    msgs = await _whowas(client, "wwe_a,wwe_b 1")
    entries = [m.params[1].lower() for m in msgs if m.command == "314"]
    assert entries.count("wwe_a") == 1 and entries.count("wwe_b") == 1, entries
    assert msgs[-1].params[1].lower() == "wwe_a,wwe_b"


@pytest.mark.multi_server
async def test_whowas_remote_requires_oper(ircd_network, make_client):
    client = await make_client("wwe_q2")
    await client.send("WHOWAS somebody 0 leaf1.test.net")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"


@pytest.mark.multi_server
async def test_whowas_remote_zero_is_unlimited_up_to_cap(ircd_network, oper):
    leaf = ircd_network["leaf1"]
    for u in ("r1", "r2", "r3"):
        await _register_and_quit(leaf, "wwe_rem", u)
    msgs = await _whowas(oper, "wwe_rem 0 leaf1.test.net")
    entries = [m for m in msgs if m.command == "314"]
    assert len(entries) == 3, [m.raw for m in msgs]


@pytest.mark.single_server
async def test_whox_all_fields_keep_idle_before_account(make_client):
    """Field order t,c,u,i,h,s,n,f,d,l,a,r: idle sits right before account."""
    # (the querytype 42 is only echoed when 't' is requested)
    client = await make_client("whoxe1")
    await client.send("WHO whoxe1 %tnla,42")
    msgs = await client.collect_until("315", timeout=5.0)
    rows = [m for m in msgs if m.command == "354"]
    assert len(rows) == 1
    # 354 <me> 42 <nick> <idle> <account>
    assert rows[0].params[1] == "42", rows[0].raw
    assert rows[0].params[2] == "whoxe1", rows[0].raw
    assert rows[0].params[3].isdigit(), rows[0].raw
    assert rows[0].params[4] == "0", rows[0].raw


@pytest.mark.single_server
async def test_whox_idle_of_other_user_hidden_from_non_oper(make_client):
    other = await make_client("whoxe2o")
    client = await make_client("whoxe2")
    await client.send("WHO whoxe2o %nl")
    msgs = await client.collect_until("315", timeout=5.0)
    rows = [m for m in msgs if m.command == "354"]
    assert len(rows) == 1 and rows[0].params[1] == "whoxe2o"
    assert rows[0].params[2] == "0", rows[0].raw


@pytest.mark.multi_server
async def test_remote_connect_with_port_zero(ircd_network, make_client):
    """CONNECT <server> 0 <via> is forwarded and uses the conf port there."""
    from cap_helpers import oper_up

    leaf = ircd_network["leaf1"]
    leaf_oper = await make_client("cone_op1", host=leaf["host"], port=leaf["port"])
    await oper_up(leaf_oper)
    await leaf_oper.send("CONNECT notulined.test.net 0 hub.test.net")
    notices = [m.params[-1] for m in await collect(leaf_oper, 3.0)
               if m.command == "NOTICE" and m.params[-1].startswith(("Connect:", "***"))]
    assert notices, "expected a Connect notice from the hub"
    assert not any("Invalid port" in n or "missing port" in n for n in notices), notices


@pytest.mark.single_server
async def test_connect_unknown_via_server(oper):
    await oper.send("CONNECT notulined.test.net 0 no.such.server")
    err = await oper.wait_for("402", timeout=5.0)
    assert err.params[1] == "no.such.server"


@pytest.mark.single_server
async def test_connect_needs_target(oper):
    await oper.send("CONNECT")
    err = await oper.wait_for("461", timeout=5.0)
    assert err.params[1] == "CONNECT"


@pytest.mark.single_server
async def test_privs_of_non_oper_is_empty(oper, make_client):
    plain = await make_client("prive_plain")
    await oper.send("PRIVS prive_plain")
    msg = await oper.wait_for("270", timeout=5.0)
    assert msg.params[-1].strip() == "", msg.raw


@pytest.mark.multi_server
async def test_privs_remote_oper(ircd_network, oper, make_client):
    from cap_helpers import oper_up

    leaf = ircd_network["leaf1"]
    leaf_oper = await make_client("prive_lop", host=leaf["host"], port=leaf["port"])
    await oper_up(leaf_oper)
    await oper.send("PRIVS prive_lop")
    msg = await oper.wait_for("270", timeout=5.0)
    privs = {p.lower() for p in msg.params[-1].split()}
    assert "unlimit_query" in privs, privs


@pytest.mark.multi_server
async def test_remote_stats_requires_privileges(ircd_network, make_client):
    client = await make_client("state_plain")
    await client.send("STATS u leaf1.test.net")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"


@pytest.mark.multi_server
async def test_remote_stats_unknown_server(ircd_network, oper):
    await oper.send("STATS P no.such.server 6668")
    err = await oper.wait_for("402", timeout=5.0)
    assert err.params[1] == "no.such.server"


@pytest.mark.multi_server
async def test_remote_stats_p_port_filter_no_match(ircd_network, oper):
    await oper.send("STATS P leaf1.test.net 1234")
    msgs = await oper.collect_until("219", timeout=8.0)
    assert not [m for m in msgs if m.command == "217"]
    assert msgs[-1].params[1] == "P"
