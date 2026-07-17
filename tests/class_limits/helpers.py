"""Helpers for class sendq/maxflood integration tests."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from irc_client import IRCClient

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CONF_PATH = REPO_ROOT / "tests/class_limits/ircd-limits.conf"

# Limits from ircd-limits.conf (kept low enough that one TCP segment can
# exceed maxflood and trigger Excess Flood on loopback).
LOCAL_FLOOD = 1024
OPER_FLOOD = 1200
REMOTE_OPER_FLOOD = 1200
DEFAULT_FLOOD = 1024  # FEAT_CLIENT_FLOOD value in config

# Margins for behavioral flood tests.
FLOOD_SURVIVE_MARGIN = 200
FLOOD_KILL_MARGIN = 500


# ---------------------------------------------------------------------------
# Flood-based behavioral helpers
# ---------------------------------------------------------------------------

async def assert_killed_by_flood(client: IRCClient, flood_bytes: int, *,
                                  timeout: float = 5.0) -> None:
    """Send flood_bytes of data in one burst and assert the client gets killed.

    The server kills a client with "Excess Flood" when the receive queue
    exceeds maxflood in a single read.  Data is sent without CRLF so it
    accumulates in the recv queue rather than being parsed line-by-line.
    """
    payload = _build_flood_payload(flood_bytes)
    await _send_raw_bytes(client, payload)
    killed = await _wait_for_kill(client, timeout=timeout)
    assert killed, (
        f"Expected client to be killed after {flood_bytes} bytes flood, "
        "but connection stayed open"
    )


async def assert_survives_flood(client: IRCClient, flood_bytes: int, *,
                                 timeout: float = 5.0) -> None:
    """Send flood_bytes of raw data and assert the client is not disconnected."""
    payload = _build_flood_payload(flood_bytes)
    await _send_raw_bytes(client, payload)
    await asyncio.sleep(0.2)
    try:
        raw = await asyncio.wait_for(client._reader.read(1), timeout=timeout)
        if raw == b"":
            raise ConnectionError("Connection closed by server")
        # Unexpected data is fine; put it back is not possible, but EOF is the kill signal.
    except asyncio.TimeoutError:
        return  # still connected
    except ConnectionError as exc:
        raise AssertionError(
            f"Client was killed after {flood_bytes} bytes flood "
            f"(expected survival): {exc}"
        ) from exc


def _build_flood_payload(total_bytes: int) -> bytes:
    """Return *total_bytes* of raw data with no CRLF.

    Data without newlines stays in the server's receive queue until the
    flood limit is evaluated, instead of being parsed line-by-line.
    """
    if total_bytes < 1:
        total_bytes = 1
    return b"X" * total_bytes


async def _send_raw_bytes(client: IRCClient, data: bytes) -> None:
    """Write raw bytes to the client's underlying stream in one shot."""
    if not client._writer:
        raise ConnectionError("Not connected")
    client._writer.write(data)
    await client._writer.drain()


async def _wait_for_kill(client: IRCClient, *, timeout: float = 5.0) -> bool:
    """Return True if the connection is closed or an ERROR is received."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        remaining = deadline - loop.time()
        if client._writer.is_closing():
            return True
        transport = client._writer.transport
        if transport is not None and transport.is_closing():
            return True
        try:
            raw = await asyncio.wait_for(
                client._reader.read(4096), timeout=min(remaining, 0.25)
            )
            if not raw:
                return True
            text = raw.decode("utf-8", errors="replace")
            if text.startswith("ERROR") or "Excess Flood" in text:
                return True
        except asyncio.TimeoutError:
            pass
        except (ConnectionError, OSError, BrokenPipeError):
            return True
        try:
            client._writer.write(b"")
            await asyncio.wait_for(client._writer.drain(), timeout=0.25)
        except (ConnectionError, OSError, BrokenPipeError, asyncio.TimeoutError):
            return True
    return False


# ---------------------------------------------------------------------------
# Config manipulation helpers
# ---------------------------------------------------------------------------

def read_config() -> str:
    return CONF_PATH.read_text()


def write_config(text: str) -> None:
    CONF_PATH.write_text(text)


def patch_config(**replacements: str) -> str:
    """Apply substring replacements and write the config file."""
    text = read_config()
    for old, new in replacements.items():
        if old not in text:
            raise ValueError(f"patch_config: pattern not found: {old!r}")
        text = text.replace(old, new, 1)
    write_config(text)
    return text


def restore_config(text: str) -> None:
    write_config(text)


async def rehash_config(oper: IRCClient) -> None:
    """Trigger a full configuration reload."""
    await oper.send("REHASH")
    msg = await oper.wait_for("382", timeout=10.0)
    assert "Rehashing" in msg.params[-1], f"Unexpected REHASH reply: {msg}"


async def make_oper(ircd_limits: dict) -> IRCClient:
    from tls.helpers import oper_up
    oper = IRCClient()
    await oper.connect(ircd_limits["host"], ircd_limits["port"])
    await oper.register("limitsoper", "testuser", "Limits Oper")
    await oper_up(oper)
    return oper
