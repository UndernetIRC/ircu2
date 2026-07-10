"""Helpers shared by TLS integration tests."""

from __future__ import annotations

import asyncio

from irc_client import IRCClient, Message


async def oper_up(client: IRCClient, name: str = "testoper", password: str = "operpass"):
    """Authenticate as a global operator."""
    await client.send(f"OPER {name} {password}")
    while True:
        msg = await client.recv(timeout=10.0)
        if msg.command in ("381", "491"):
            return msg
        if msg.command in ("464", "465", "467"):
            raise AssertionError(f"OPER failed: {msg}")


async def links_contains(client: IRCClient, server_name: str, timeout: float = 15.0) -> bool:
    """Return True if LINKS output mentions server_name."""
    await client.send("LINKS")
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return False
        msg = await client.recv(timeout=remaining)
        if msg.command == "364" and any(server_name in p for p in msg.params):
            return True
        if msg.command == "365":
            return False


async def wait_for_server_link(
    client: IRCClient, server_name: str, timeout: float = 30.0
) -> None:
    """Wait until LINKS shows an active server link."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await links_contains(client, server_name, timeout=5.0):
            return
        await asyncio.sleep(1.0)
    raise TimeoutError(f"Server link to {server_name!r} not seen in LINKS")


async def connect_link(
    client: IRCClient, peer: str, port: int, timeout: float = 30.0
) -> None:
    """As an operator, initiate an outbound server link and wait for it.

    Drives linking explicitly via CONNECT rather than relying on autoconnect.
    The test configs disable autoconnect on these blocks because both servers
    autoconnecting at once collides and, with connectfreq at production
    values, does not recover within the test window. If the link already
    exists (a prior test brought it up in the shared session), CONNECT is a
    harmless no-op and the link is observed immediately.
    """
    await client.send(f"CONNECT {peer} {port}")
    await wait_for_server_link(client, peer, timeout=timeout)


async def collect_until_error_or_close(reader, timeout: float = 5.0) -> str:
    """Read one line from a raw asyncio stream."""
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return ""
    return raw.decode("utf-8", errors="replace").strip()


def is_error(msg: Message | str) -> bool:
    """Return True if the server signalled an ERROR."""
    if isinstance(msg, str):
        return msg.upper().startswith("ERROR")
    return msg.command == "ERROR"
