"""Edge cases for the server parser and G-line updates (commits 30d035b,
9cad720, 37a02bc, 8375a80)."""

from __future__ import annotations

import asyncio
import time

import pytest

from common import whois
from p10_server import P10Server

pytestmark = pytest.mark.single_server


async def _link(hub, name="notulined.test.net", numeric=5) -> P10Server:
    srv = P10Server(name=name, numeric=numeric, password="testpass", server_flags="")
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    return srv


async def _alive(srv, make_client, nick):
    await srv.introduce_user(nick, realname="Alive")
    client = await make_client(nick + "c")
    assert "311" in await whois(client, nick)


async def test_numeric_999_to_local_user(ircd_hub, make_client):
    client = await make_client("s2se_1")
    srv = await _link(ircd_hub)
    try:
        numnick = await srv.wait_for_user("s2se_1")
        await srv._send(f"{srv.server_numnick} 999 {numnick} :edge numeric")
        reply = await client.wait_for("999", timeout=5.0)
        assert reply.params[-1] == "edge numeric"
    finally:
        await srv.disconnect()


async def test_numeric_to_unknown_target_is_ignored(ircd_hub, make_client):
    srv = await _link(ircd_hub)
    try:
        await srv._send(f"{srv.server_numnick} 391 ZZZZZ :nobody")
        await asyncio.sleep(0.2)
        await _alive(srv, make_client, "s2se_2")
    finally:
        await srv.disconnect()


async def test_mixed_digit_letter_token_is_not_a_numeric(ircd_hub, make_client):
    srv = await _link(ircd_hub)
    try:
        await srv._send(f"{srv.server_numnick} 00A AB :not numeric")
        await srv._send(f"{srv.server_numnick} 0_1 AB :not numeric")
        await asyncio.sleep(0.2)
        await _alive(srv, make_client, "s2se_3")
    finally:
        await srv.disconnect()


async def test_empty_and_whitespace_lines_are_ignored(ircd_hub, make_client):
    srv = await _link(ircd_hub)
    try:
        await srv._send("")
        await srv._send("   ")
        await srv._send(f"{srv.server_numnick}")
        await asyncio.sleep(0.2)
        await _alive(srv, make_client, "s2se_4")
    finally:
        await srv.disconnect()


async def test_gline_seven_param_form_updates_lifetime_and_reason(oper, ulined_server):
    num = ulined_server.server_numnick
    mask = "*@192.0.4.*"
    lastmod = int(time.time())
    await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod} :seven one")
    await asyncio.sleep(0.3)
    try:
        life = lastmod + 9000
        await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod + 1} {life} :seven two")
        await asyncio.sleep(0.3)
        await oper.send(f"GLINE {mask}")
        msgs = await oper.collect_until("281", timeout=5.0)
        entries = [m for m in msgs if m.command == "280"]
        assert len(entries) == 1, [m.raw for m in msgs]
        assert entries[0].params[-1] == "seven two"
        assert int(entries[0].params[4]) == life
    finally:
        await ulined_server._send(f"{num} GL * -{mask} {lastmod + 10}")
        await asyncio.sleep(0.3)


async def test_gline_deactivate_and_reactivate(oper, ulined_server):
    num = ulined_server.server_numnick
    mask = "*@192.0.5.*"
    lastmod = int(time.time())
    await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod} :toggle")
    await asyncio.sleep(0.3)

    async def state():
        await oper.send(f"GLINE {mask}")
        msgs = await oper.collect_until("281", timeout=5.0)
        entries = [m for m in msgs if m.command == "280"]
        assert len(entries) == 1, [m.raw for m in msgs]
        return entries[0]

    try:
        e = await state()
        assert e.params[-1] == "toggle"
        await ulined_server._send(f"{num} GL * -{mask} {lastmod + 1}")
        await asyncio.sleep(0.3)
        e = await state()
        assert "-" in e.params[5:8] or e.params[5].startswith("-") or "-" in "".join(e.params[5:8]), e.raw
        await ulined_server._send(f"{num} GL * +{mask} {lastmod + 2}")
        await asyncio.sleep(0.3)
        e = await state()
        assert "+" in "".join(e.params[5:8]), e.raw
    finally:
        await ulined_server._send(f"{num} GL * -{mask} {lastmod + 10}")
        await asyncio.sleep(0.3)


async def test_gline_reason_with_leading_digits_kept(oper, ulined_server):
    """A reason such as "3 strikes" must not be parsed as a lifetime."""
    num = ulined_server.server_numnick
    mask = "*@192.0.6.*"
    lastmod = int(time.time())
    await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod} :first")
    await asyncio.sleep(0.3)
    try:
        await ulined_server._send(f"{num} GL * +{mask} 3600 {lastmod + 1} :3 strikes")
        await asyncio.sleep(0.3)
        await oper.send(f"GLINE {mask}")
        msgs = await oper.collect_until("281", timeout=5.0)
        entries = [m for m in msgs if m.command == "280"]
        assert entries and entries[0].params[-1] == "3 strikes"
    finally:
        await ulined_server._send(f"{num} GL * -{mask} {lastmod + 10}")
        await asyncio.sleep(0.3)
