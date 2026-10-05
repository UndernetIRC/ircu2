"""Shared helpers for the IPcheck integration tests."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from irc_client import IRCClient, Message

# IPcheck_connect_succeeded() tells every local client the registry state
# for its address: "on <connected> ca <attempts>(<limit>) ft <free>(<start>)"
# with a trailing " tr" when target history was inherited.
IPCHECK_NOTICE = re.compile(
    r"^on (?P<on>\d+) ca (?P<ca>\d+)\((?P<limit>\d+)\) "
    r"ft (?P<ft>\d+)\((?P<start>\d+)\)(?P<tr> tr)?$"
)

THROTTLE_ERROR = "ERROR :Your host is trying to (re)connect too fast -- throttled"


@dataclass
class IPcheckNotice:
    connected: int
    attempts: int
    limit: int
    free_targets: int
    start_targets: int
    inherited: bool

    @classmethod
    def parse(cls, msg: Message) -> "IPcheckNotice | None":
        if msg.command != "NOTICE" or not msg.params:
            return None
        m = IPCHECK_NOTICE.match(msg.params[-1])
        if not m:
            return None
        return cls(
            connected=int(m["on"]),
            attempts=int(m["ca"]),
            limit=int(m["limit"]),
            free_targets=int(m["ft"]),
            start_targets=int(m["start"]),
            inherited=bool(m["tr"]),
        )


def find_notice(msgs: list[Message]) -> IPcheckNotice | None:
    for msg in msgs:
        parsed = IPcheckNotice.parse(msg)
        if parsed:
            return parsed
    return None


async def register_with_notice(
    host: str, port: int, nick: str, timeout: float = 5.0
) -> tuple[IRCClient, IPcheckNotice]:
    """Connect + register and return the client with its IPcheck notice."""
    client = IRCClient()
    await client.connect(host, port)
    msgs = await client.register(nick, "ipcuser", "IPcheck test")
    notice = find_notice(msgs)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while notice is None and loop.time() < deadline:
        msg = await client.recv(timeout=deadline - loop.time())
        notice = IPcheckNotice.parse(msg)
    assert notice is not None, f"{nick}: no IPcheck notice after registration"
    return client, notice


async def register_expect_no_notice(
    host: str, port: int, nick: str, quiet: float = 1.0
) -> IRCClient:
    """Connect + register and assert no IPcheck notice arrives (exempt IP)."""
    client = IRCClient()
    await client.connect(host, port)
    msgs = await client.register(nick, "ipcuser", "IPcheck test")
    assert find_notice(msgs) is None, f"{nick}: exempt address got an IPcheck notice"
    try:
        while True:
            msg = await client.recv(timeout=quiet)
            assert IPcheckNotice.parse(msg) is None, (
                f"{nick}: exempt address got an IPcheck notice: {msg.raw}"
            )
    except asyncio.TimeoutError:
        pass
    return client


async def raw_connect_first_line(host: str, port: int, timeout: float = 5.0) -> str:
    """Open a TCP connection and return the first line the server sends.

    A throttled connection gets the ERROR line and EOF before any command
    is read, so nothing needs to be sent.
    """
    reader, writer = await asyncio.open_connection(host, port)
    try:
        data = await asyncio.wait_for(reader.readline(), timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return data.decode(errors="replace").rstrip("\r\n")


async def register_expect_throttled(host: str, port: int) -> None:
    line = await raw_connect_first_line(host, port)
    assert line == THROTTLE_ERROR, f"expected throttle ERROR, got {line!r}"


async def userip(oper: IRCClient, nick: str) -> str:
    """Return the IP the server recorded for \\a nick (RPL_USERIP)."""
    await oper.send(f"USERIP {nick}")
    msg = await oper.wait_for("340", timeout=5.0)
    # "<nick>[*]=[+-]<user>@<ip>"
    return msg.params[-1].strip().rsplit("@", 1)[1]


async def disconnect_all(*clients: IRCClient | None) -> None:
    for c in clients:
        if c is None:
            continue
        try:
            await c.send("QUIT :ipcheck test cleanup")
        except Exception:
            pass
        try:
            await c.disconnect()
        except Exception:
            pass
