"""Verify @time= on the P10 wire for client-visible vs other commands."""

from __future__ import annotations

import asyncio
import re

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.multi_server

_TIME_PREFIX = re.compile(r"^@time=\d{4}-\d{2}-\d{2}T[\d:.]+Z ")


@pytest.fixture
async def services(ircd_network):
    hub = ircd_network["hub"]
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


async def _wait_s2s(
    services: P10Server,
    token: str,
    *,
    contain: str | None = None,
    timeout: float = 8.0,
) -> str:
    """Wait for a P10 line with the given token; return the raw wire line."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        line = await services._recv(timeout=max(remaining, 0.1))
        if services._get_token(line) != token:
            continue
        if contain is not None and contain not in line:
            continue
        return line
    raise TimeoutError(f"timed out waiting for S2S token {token!r} contain={contain!r}")


def _assert_has_time(line: str, label: str) -> None:
    assert _TIME_PREFIX.match(line), f"{label}: expected @time= prefix, got: {line}"


def _assert_no_time(line: str, label: str) -> None:
    assert not line.lstrip().startswith("@"), f"{label}: unexpected tags: {line}"
    assert "@time=" not in line, f"{label}: unexpected @time=: {line}"


async def test_s2s_time_on_client_event_commands(ircd_network, services):
    """PRIVMSG/NOTICE/NICK/MODE/TOPIC must carry @time= on P10."""
    hub = ircd_network["hub"]
    channel = "#s2scmds"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("cmduser", "testuser", "Cmd User")

    try:
        # Local user creates the channel first so they are op for MODE/TOPIC.
        await user.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)

        down_num = await services.send_downstream_server("down.cmds.test", 93)
        await services.send_downstream_nick(
            down_num, "CmdBot", server_numeric=93, client_num=1,
        )
        await services.send_downstream_join("CmdBot", channel)
        await asyncio.sleep(0.3)

        # PRIVMSG (P)
        await user.send(f"PRIVMSG {channel} :privmsg wire")
        priv = await _wait_s2s(services, "P", contain="privmsg wire")
        _assert_has_time(priv, "PRIVMSG")

        # NOTICE (O)
        await user.send(f"NOTICE {channel} :notice wire")
        notice = await _wait_s2s(services, "O", contain="notice wire")
        _assert_has_time(notice, "NOTICE")

        # MODE (M)
        await user.send(f"MODE {channel} +t")
        mode = await _wait_s2s(services, "M", contain=channel)
        _assert_has_time(mode, "MODE")

        # TOPIC (T)
        await user.send(f"TOPIC {channel} :topic wire")
        topic = await _wait_s2s(services, "T", contain="topic wire")
        _assert_has_time(topic, "TOPIC")

        # NICK (N) — nick change is client-visible
        await user.send("NICK cmduser2")
        nick = await _wait_s2s(services, "N", contain="cmduser2")
        _assert_has_time(nick, "NICK")
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_s2s_time_on_stats(ircd_network, services):
    """STATS query/response on P10 must carry @time= (client-visible traffic)."""
    hub = ircd_network["hub"]

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("statsop", "oper", "Oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)

    try:
        await oper.send("STATS u services.test.net")
        stats = await _wait_s2s(services, "R", timeout=8.0)
        _assert_has_time(stats, "STATS")
    finally:
        try:
            await oper.send("QUIT :cleanup")
        except Exception:
            pass
        await oper.disconnect()


async def test_client_ping_pong_gets_server_time(ircd_network):
    """PING/PONG with a local client must carry server-time."""
    hub = ircd_network["hub"]

    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    await client.negotiate_cap(["server-time", "message-tags"])
    await client.register("pingcli", "testuser", "Ping Client")

    try:
        await client.send("PING :clientping")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.tags.startswith("time="), pong.raw
        assert re.match(r"time=\d{4}-\d{2}-\d{2}T", pong.tags), pong.tags
    finally:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()
