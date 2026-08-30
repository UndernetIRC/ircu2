"""WHOWAS <nick> 0 means "no limit" (commit c121933)."""

from __future__ import annotations

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def _register_and_quit(hub, nick, username):
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    await client.register(nick, username, "WhoWas Test")
    await client.send("QUIT :bye")
    await client.disconnect()


async def _whowas(client, nick, arg=None):
    await client.send(f"WHOWAS {nick}" + (f" {arg}" if arg is not None else ""))
    msgs = await client.collect_until("369", timeout=5.0)
    return [m for m in msgs if m.command == "314"]


async def test_whowas_zero_returns_all_entries(ircd_hub, make_client):
    for username in ("wwone", "wwtwo", "wwthree"):
        await _register_and_quit(ircd_hub, "wwzero1", username)
    client = await make_client("wwq1")

    all_entries = await _whowas(client, "wwzero1")
    assert len(all_entries) == 3
    assert [m.params[2].lstrip("~") for m in all_entries] == ["wwthree", "wwtwo", "wwone"]

    limited = await _whowas(client, "wwzero1", 1)
    assert len(limited) == 1 and limited[0].params[2].lstrip("~") == "wwthree"

    two = await _whowas(client, "wwzero1", 2)
    assert len(two) == 2

    unlimited = await _whowas(client, "wwzero1", 0)
    assert len(unlimited) == 3, "WHOWAS <nick> 0 must not stop after the first entry"


async def test_whowas_negative_count_is_unlimited(ircd_hub, make_client):
    for username in ("nega", "negb"):
        await _register_and_quit(ircd_hub, "wwneg2", username)
    client = await make_client("wwq2")
    assert len(await _whowas(client, "wwneg2", -1)) == 2


async def test_whowas_unknown_nick(make_client):
    client = await make_client("wwq3")
    await client.send("WHOWAS nobody_ever_here 0")
    msgs = await client.collect_until("369", timeout=5.0)
    assert any(m.command == "406" for m in msgs)
