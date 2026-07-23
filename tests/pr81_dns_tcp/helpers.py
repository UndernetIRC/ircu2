"""Helpers for DNS resolver integration tests."""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request

from irc_client import IRCClient, Message

DNS_CONTROL_URL = "http://127.0.0.1:8053"

AUTH_FOUND = "Found your hostname"
AUTH_FAIL = "Couldn't look up your hostname"
AUTH_MISMATCH = "forward and reverse DNS do not match"


def wait_for_dns_control(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            get_stats()
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(0.5)
    raise TimeoutError(f"DNS control API not ready at {DNS_CONTROL_URL}")


def _request(method: str, path: str) -> dict:
    req = urllib.request.Request(
        f"{DNS_CONTROL_URL}{path}",
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode())


def get_stats() -> dict:
    return _request("GET", "/stats")


def reset_stats() -> None:
    _request("POST", "/reset")


def set_scenario(name: str) -> None:
    _request("POST", f"/scenario/{name}")


def notice_text(msg: Message) -> str:
    return " ".join(msg.params)


async def register_collect_auth_notices(
    host: str,
    port: int,
    nick: str,
    *,
    stop_on: str | None = None,
    timeout: float = 45.0,
) -> list[str]:
    """Connect, send NICK/USER, and collect NOTICE AUTH lines."""
    client = IRCClient()
    await client.connect(host, port)
    notices: list[str] = []
    try:
        await client.send(f"NICK {nick}")
        await client.send("USER dnstest 0 * :DNS test client")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = await client.recv(timeout=5.0)
            if msg.command == "NOTICE":
                text = notice_text(msg)
                notices.append(text)
                if stop_on and stop_on in text:
                    break
            if msg.command in ("376", "422"):
                break
    finally:
        try:
            await client.send("QUIT :dns test cleanup")
        except Exception:
            pass
        await client.disconnect()
    return notices


def notice_blob(notices: list[str]) -> str:
    return "\n".join(notices)


async def trigger_oper_connect(host: str, port: int, server: str) -> None:
    """Register, oper up, and CONNECT to trigger server hostname DNS lookup."""
    client = IRCClient()
    await client.connect(host, port)
    try:
        await client.send("NICK conop")
        await client.send("USER connect 0 * :DNS connect test")
        await client.wait_for("001", timeout=30.0)
        await client.send("OPER testoper operpass")
        await client.wait_for("381", timeout=10.0)
        await client.send(f"CONNECT {server}")
        await asyncio.sleep(3.0)
    finally:
        try:
            await client.send("QUIT :connect test cleanup")
        except Exception:
            pass
        await client.disconnect()
