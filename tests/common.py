"""Small shared helpers for the integration tests."""

from __future__ import annotations

import asyncio

from irc_client import IRCClient, Message


async def join(client: IRCClient, channel: str, timeout: float = 5.0) -> Message:
    """JOIN a channel and wait for the server to echo our own JOIN."""
    await client.send(f"JOIN {channel}")
    return await wait_for_join(client, channel, client.nick, timeout=timeout)


async def wait_for_join(
    client: IRCClient, channel: str, nick: str, timeout: float = 5.0
) -> Message:
    """Wait for a JOIN to ``channel`` from ``nick`` (case-insensitive)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"no JOIN {channel} from {nick}")
        msg = await client.wait_for("JOIN", timeout=remaining)
        if (
            msg.prefix
            and msg.prefix.split("!", 1)[0].lower() == nick.lower()
            and msg.params
            and msg.params[0].lower() == channel.lower()
        ):
            return msg


async def drain(client: IRCClient, seconds: float = 0.4) -> list[Message]:
    """Consume (and return) whatever arrives within ``seconds``."""
    out: list[Message] = []
    deadline = asyncio.get_running_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return out
        try:
            out.append(await client.recv(timeout=remaining))
        except (asyncio.TimeoutError, ConnectionError):
            return out


async def collect(client: IRCClient, seconds: float, command: str | None = None) -> list[Message]:
    """Collect messages for ``seconds``, optionally filtered by command."""
    msgs = await drain(client, seconds)
    if command is None:
        return msgs
    return [m for m in msgs if m.command.upper() == command.upper()]


def sender_nick(msg: Message) -> str:
    """Nick part of a user prefix ('' for server-prefixed messages)."""
    if not msg.prefix or "!" not in msg.prefix:
        return ""
    return msg.prefix.split("!", 1)[0]


async def whois(client: IRCClient, nick: str, timeout: float = 5.0) -> dict[str, Message]:
    """Send WHOIS and return the numeric replies keyed by numeric."""
    await client.send(f"WHOIS {nick}")
    msgs = await client.collect_until("318", timeout=timeout)
    return {m.command: m for m in msgs}


async def chan_modes(client: IRCClient, channel: str) -> str:
    """Channel mode letters from RPL_CHANNELMODEIS (without the leading '+')."""
    modes = await client.chan_modes(channel)
    return modes.lstrip("+")


async def get_feature(oper: IRCClient, name: str, timeout: float = 10.0) -> str:
    """Return the value text of a feature ("TRUE", "FALSE", an int or string).

    Any pending RPL_FEATURE replies (e.g. from an earlier SET) are discarded
    first so the answer really belongs to this GET.
    """
    await drain(oper, 0.2)
    await oper.send(f"GET {name}")
    msg = await oper.wait_for("284", timeout=timeout)
    # ":Boolean value of NAME: TRUE" / ":Integer value of NAME: 5" /
    # ":String value of NAME: text"
    return msg.params[-1].split(f"of {name}: ", 1)[1]


async def set_feature(oper: IRCClient, name: str, value: str, timeout: float = 10.0) -> None:
    """SET a feature and wait until the server has applied it.

    SET only answers (with RPL_FEATURE) when the value actually changes, and
    ircu may defer a client's commands for a couple of seconds once its flood
    penalty builds up, so a fixed sleep after SET is racy.  Compare first,
    then wait for the reply that proves the change was processed.
    """
    current = await get_feature(oper, name, timeout=timeout)
    if current.upper() == value.upper() or (
        current in ("TRUE", "FALSE") and value in ("1", "0")
        and (current == "TRUE") == (value == "1")
    ):
        return
    await oper.send(f"SET {name} {value}")
    msg = await oper.wait_for("284", timeout=timeout)
    assert f"of {name}: " in msg.params[-1], msg.raw
