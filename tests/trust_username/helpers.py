"""Shared helpers for trust-username (+x display) integration tests."""

import asyncio

from irc_client import IRCClient
from p10_server import P10Server

HIDDEN_HOST_SUFFIX = "users.undernet.org"


def hidden_host(account: str) -> str:
    return f"{account}.{HIDDEN_HOST_SUFFIX}"


def user_from_prefix(prefix: str | None) -> str | None:
    if not prefix or "!" not in prefix:
        return None
    user_host = prefix.split("!", 1)[1]
    if "@" not in user_host:
        return None
    return user_host.split("@", 1)[0]


async def oper_up(client: IRCClient, name: str = "testoper", password: str = "operpass"):
    await client.send(f"OPER {name} {password}")
    msg = await client.wait_for("381", timeout=5.0)
    return msg


async def hide_via_services(
    services: P10Server,
    nick: str,
    account: str = "HideAcct",
    *,
    set_x_first: bool = False,
) -> str:
    """Set account and +x on a user via the U:lined services server."""
    numnick = await services.wait_for_user(nick)
    if set_x_first:
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.3)
        await services.send_account(numnick, account)
    else:
        await services.send_account(numnick, account)
        await asyncio.sleep(0.3)
        await services.send_opmode(numnick, "+x")
    await asyncio.sleep(0.5)
    return account


async def whois_userline(observer: IRCClient, nick: str) -> tuple[str, str]:
    await observer.send(f"WHOIS {nick}")
    msgs = await observer.collect_until("318", timeout=5.0)
    whois = [m for m in msgs if m.command == "311"]
    assert len(whois) == 1, f"Expected one RPL_WHOISUSER, got: {msgs}"
    return whois[0].params[2], whois[0].params[3]


async def add_gline(oper: IRCClient, mask: str, reason: str = "trust username test",
                   *, operforce: bool = False):
    """Add a global G-line on the hub (target *)."""
    prefix = "!" if operforce else ""
    await oper.send(f"GLINE +{prefix}{mask} * 100000 :{reason}")
    for _ in range(8):
        msg = await oper.recv(timeout=3.0)
        if msg.command == "NOTICE" and any("GLINE" in p for p in msg.params):
            return
        if msg.command.startswith("4") or msg.command.startswith("5"):
            raise AssertionError(f"GLINE rejected: {msg}")
    raise AssertionError(f"GLINE for {mask!r} produced no confirmation NOTICE")


async def remove_gline(oper: IRCClient, mask: str):
    """Remove a global G-line (deactivate with ``GLINE -mask *``).

    This ircu build needs a three-command sequence before deactivation
    succeeds; a single ``GLINE -mask *`` is ignored after add.
    """
    try:
        while True:
            await oper.recv(timeout=0.2)
    except asyncio.TimeoutError:
        pass

    await oper.send(f"GLINE -{mask} * 100000 :cleanup")
    try:
        while True:
            await oper.recv(timeout=0.5)
    except asyncio.TimeoutError:
        pass
    await oper.send(f"GLINE -{mask} * :cleanup")
    try:
        while True:
            msg = await oper.recv(timeout=1.0)
            if msg.command == "515":
                break
    except asyncio.TimeoutError:
        pass
    await oper.send(f"GLINE -{mask} *")
    for _ in range(8):
        try:
            msg = await oper.recv(timeout=3.0)
        except asyncio.TimeoutError:
            break
        if msg.command == "NOTICE" and any("GLINE" in p for p in msg.params):
            return
        if msg.command in ("465", "ERROR"):
            continue
        if msg.command == "512":
            return  # already removed
        if msg.command.startswith("4") or msg.command.startswith("5"):
            raise AssertionError(f"GLINE remove rejected: {msg}")
