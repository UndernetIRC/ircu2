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


# ---------------------------------------------------------------------------
# Busy-channel helpers for TLS NAMES / sendq stress
# ---------------------------------------------------------------------------

NAMES_BURST_CHANNELS = [f"#burst{i}" for i in range(4)]
NAMES_BURST_CROWD = 30  # plaintext fillers; Local class maxlinks=100


async def register_and_join_channels(
    host: str, port: int, nick: str, channels: list[str]
) -> IRCClient:
    """Plaintext register, JOIN channels, wait for every RPL_ENDOFNAMES."""
    c = IRCClient()
    await c.connect(host, port)
    msgs = await c.register(nick, "crowd", "TLS burst crowd")
    assert any(m.command == "001" for m in msgs), nick
    await c.send("JOIN " + ",".join(channels))
    pending = {ch.lower() for ch in channels}
    while pending:
        msg = await c.recv(timeout=20.0)
        if msg.command == "366" and len(msg.params) >= 2:
            pending.discard(msg.params[1].lower())
    return c


async def populate_channels(
    hub: dict,
    channels: list[str] | None = None,
    crowd: int = NAMES_BURST_CROWD,
) -> list[IRCClient]:
    """Fill channels with many nicks so JOIN NAMES replies are large."""
    channels = channels or NAMES_BURST_CHANNELS
    clients: list[IRCClient] = []
    batch = 10
    for start in range(0, crowd, batch):
        chunk = await asyncio.gather(
            *[
                register_and_join_channels(
                    hub["host"], hub["port"], f"crwd{i:02d}", channels
                )
                for i in range(start, min(start + batch, crowd))
            ]
        )
        clients.extend(chunk)
    return clients


async def drain_channel_joins(
    victim: IRCClient, channels: list[str], timeout: float
) -> None:
    """JOIN all channels and wait for every RPL_ENDOFNAMES (366)."""
    pending = {c.lower() for c in channels}
    await victim.send("JOIN " + ",".join(channels))

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while pending:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError(
                f"NAMES burst incomplete; still waiting for {sorted(pending)}"
            )
        try:
            msg = await victim.recv(timeout=remaining)
        except ConnectionError as exc:
            raise AssertionError(
                f"TLS link died mid-NAMES burst (pending={sorted(pending)}): {exc}"
            ) from exc

        if msg.command == "PING":
            await victim.send(f"PONG :{msg.params[-1]}")
            continue
        if msg.command == "ERROR":
            raise AssertionError(f"ERROR during NAMES burst: {msg.raw}")
        if msg.command == "366" and len(msg.params) >= 2:
            pending.discard(msg.params[1].lower())


async def assert_client_alive(victim: IRCClient, token: str = "tlsburstalive") -> None:
    """Client PING must get a matching PONG."""
    await victim.send(f"PING :{token}")
    while True:
        msg = await victim.recv(timeout=15.0)
        if msg.command == "PING":
            await victim.send(f"PONG :{msg.params[-1]}")
            continue
        if msg.command == "PONG" and token in msg.params[-1]:
            return
        if msg.command == "ERROR":
            raise AssertionError(f"ERROR after ping probe: {msg.raw}")
