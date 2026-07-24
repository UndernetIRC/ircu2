"""Shared helpers for the secure-path test modules."""

from __future__ import annotations

from irc_client import IRCClient, Message
from tls.helpers import oper_up


async def collect_whois(client: IRCClient, target: str, timeout: float = 10.0) -> list[Message]:
    await client.send(f"WHOIS {target}")
    return await client.collect_until("318", timeout=timeout)


def whois_secure_text(msgs: list[Message]) -> str | None:
    for msg in msgs:
        if msg.command == "671":
            return msg.params[-1] if msg.params else None
    return None


async def join(client: IRCClient, channel: str) -> None:
    await client.send(f"JOIN {channel}")
    await client.wait_for("JOIN", timeout=5.0)


async def channel_mode_flags(client: IRCClient, channel: str) -> str | None:
    await client.send(f"MODE {channel}")
    msgs = await client.collect_until("324", timeout=5.0)
    for msg in msgs:
        if msg.command == "324" and len(msg.params) >= 3:
            return msg.params[2]
    return None


async def make_oper(hub: dict, nick: str) -> IRCClient:
    op = IRCClient()
    await op.connect(hub["host"], hub["port"])
    await op.register(nick, "oper", "Oper")
    await oper_up(op)
    return op
