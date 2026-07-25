"""Shared helpers for IRCv3 CAP / S2S burst feature tests."""

from __future__ import annotations

import asyncio
import re

import pytest

from irc_client import IRCClient
from p10_server import P10Server, strip_msg_tags


async def make_cap_client(
    host: str,
    port: int,
    nick: str,
    caps: list[str] | None = None,
    username: str = "testuser",
    realname: str = "Test User",
) -> IRCClient:
    """Connect, optionally negotiate CAPs, then register."""
    client = IRCClient()
    await client.connect(host, port)
    if caps:
        acked = await client.negotiate_cap(caps)
        missing = [c for c in caps if c not in acked]
        if missing:
            await client.disconnect()
            pytest.skip(f"CAP(s) not available: {missing} (acked={acked})")
    await client.register(nick, username, realname)
    return client


async def oper_up(client: IRCClient, name: str = "testoper", password: str = "operpass"):
    await client.send(f"OPER {name} {password}")
    while True:
        msg = await client.recv(timeout=10.0)
        if msg.command == "381":
            return msg
        if msg.command in ("491", "464", "465"):
            raise AssertionError(f"OPER failed: {msg}")


async def connect_services(hub: dict) -> P10Server:
    """Connect U:lined services to the hub and complete the handshake."""
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    return srv


def burst_lines(srv: P10Server, token: str) -> list[str]:
    """Return handshake-received lines whose P10 token matches ``token``."""
    out = []
    for line in srv.received:
        payload = strip_msg_tags(line)
        parts = payload.split()
        if len(parts) >= 2 and parts[1] == token:
            out.append(payload)
    return out


def nick_burst_modes(line: str) -> str:
    """Extract the +modes / account field section from a P10 NICK line."""
    payload = strip_msg_tags(line)
    if " :" in payload:
        head, _ = payload.rsplit(" :", 1)
    else:
        head = payload
    parts = head.split()
    # <server> N <nick> <hop> <ts> <user> <host> [+modes account...] <ip> <numnick>
    if len(parts) < 9:
        return ""
    return " ".join(parts[7:-2])


_NUMERIC_RE = re.compile(r"^[A-Za-z0-9\[\]]+\(\d+\)$")


def is_human_numeric(token: str) -> bool:
    """True if token looks like the human-readable ``AB(1)`` stats-v form."""
    return bool(_NUMERIC_RE.match(token))


async def drain_briefly(client: IRCClient, seconds: float = 0.4):
    """Consume whatever is already buffered / arrives briefly."""
    deadline = asyncio.get_running_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return
        try:
            await client.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            return


async def collect_wallops(client: IRCClient, seconds: float = 2.0) -> list[str]:
    """Collect WALLOPS texts (protocol_violation uses WALLOPS to +g opers)."""
    texts: list[str] = []
    deadline = asyncio.get_running_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            msg = await client.recv(timeout=remaining)
        except (asyncio.TimeoutError, ConnectionError):
            break
        if msg.command.upper() == "WALLOPS" and msg.params:
            texts.append(msg.params[-1])
    return texts


async def make_debug_oper(server: dict, nick: str) -> IRCClient:
    """Oper with +g so protocol_violation WALLOPS are visible."""
    oper = await make_cap_client(server["host"], server["port"], nick)
    await oper_up(oper)
    await oper.send(f"MODE {nick} +g")
    await asyncio.sleep(0.2)
    await drain_briefly(oper, 0.3)
    return oper
