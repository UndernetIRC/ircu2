"""Stress Excess Flood for body (CLIENT_FLOOD) vs tag (CLIENT_TAG_FLOOD) budgets.

Body flood counts RFC1459 line bodies only (dbuf_flood_length). Tag flood
counts leading `@… ` prefixes (DBufLength − body flood length). Both disconnect with
"Excess Flood". Defaults: CLIENT_FLOOD=1024, CLIENT_TAG_FLOOD=8192.

TCP tests can leave incomplete lines in recvQ (no CRLF). WebSocket frames
are terminated with a newline by the server on FIN, so WS cases use complete
lines / multi-line bursts sized to trip the same ceilings.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient
from websockets.exceptions import ConnectionClosed

pytestmark = pytest.mark.single_server

BODY_FLOOD = 1024
TAG_FLOOD = 8192
WS_PORT = 7000
# Exempt class (maxflood=262144, FLAG_EXEMPT_THROTTLE) — hub.conf Port 7002.
WS_EXEMPT_PORT = 7002

# Margins so one write clearly lands on one side of the limit.
BODY_KILL = BODY_FLOOD + 400
BODY_SAFE = BODY_FLOOD - 200
TAG_KILL = TAG_FLOOD + 400
TAG_SAFE = TAG_FLOOD - 500  # still large; under CLIENT_TAG_FLOOD


async def _cleanup(*clients):
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        try:
            await c.disconnect()
        except Exception:
            pass


async def _register_tcp(hub, nick: str, *, caps: list[str] | None = None) -> IRCClient:
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    if caps:
        await c.negotiate_cap(caps)
    await c.register(nick, "testuser", "Flood Test")
    return c


async def _register_ws(
    hub, nick: str, *, caps: list[str] | None = None, port: int = WS_PORT
) -> IRCWebSocketClient:
    c = IRCWebSocketClient()
    await c.connect(f"ws://{hub['host']}:{port}/")
    if caps:
        await c.negotiate_cap(caps)
    await c.register(nick, "testuser", "Flood Test")
    return c


async def _oper(hub, nick: str) -> IRCClient:
    c = await _register_tcp(hub, nick)
    await c.send("OPER testoper operpass")
    await c.wait_for("381", timeout=10.0)
    return c


async def _send_raw(client: IRCClient, data: bytes) -> None:
    if not client._writer:
        raise ConnectionError("Not connected")
    client._writer.write(data)
    await client._writer.drain()


async def _wait_for_kill(client, *, timeout: float = 5.0) -> str | None:
    """Return received text if Excess Flood / ERROR / close; else None."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    reader = getattr(client, "_reader", None)
    writer = getattr(client, "_writer", None)
    ws = getattr(client, "_ws", None)
    buf = ""

    while loop.time() < deadline:
        remaining = deadline - loop.time()
        if writer is not None:
            if writer.is_closing() or (
                writer.transport is not None and writer.transport.is_closing()
            ):
                return buf or "closed"
        if ws is not None and getattr(ws, "closed", False):
            return buf or "closed"
        try:
            if reader is not None:
                raw = await asyncio.wait_for(
                    reader.read(4096), timeout=min(remaining, 0.25)
                )
                if not raw:
                    return buf or "closed"
                buf += raw.decode("utf-8", errors="replace")
                if "Excess Flood" in buf or buf.startswith("ERROR"):
                    return buf
            elif ws is not None:
                raw = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 0.25))
                text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                buf += text
                if "Excess Flood" in buf or text.startswith("ERROR"):
                    return buf
        except asyncio.TimeoutError:
            pass
        except (ConnectionError, OSError, BrokenPipeError):
            return buf or "closed"
    return None


async def _assert_killed(client, *, what: str) -> None:
    got = await _wait_for_kill(client)
    assert got is not None, f"Expected Excess Flood kill ({what}), connection stayed open"
    assert "Excess Flood" in got, (
        f"Expected quit reason Excess Flood ({what}), got: {got!r}"
    )


async def _assert_alive(client: IRCClient, *, what: str) -> None:
    """Prove the link still answers PING (retries: junk may eat the first)."""
    try:
        for _ in range(5):
            await client.send("PING :flood-liveness")
            try:
                await client.wait_for("PONG", timeout=2.0)
                return
            except (TimeoutError, asyncio.TimeoutError):
                continue
        raise AssertionError(f"No PONG after {what} (open but unresponsive)")
    except (ConnectionError, OSError, BrokenPipeError) as exc:
        raise AssertionError(f"Killed after {what} (expected survival): {exc!r}") from exc


async def _assert_alive_ws(client: IRCWebSocketClient, *, what: str) -> None:
    try:
        for _ in range(5):
            await client.send("PING :flood-liveness")
            try:
                await client.wait_for("PONG", timeout=2.0)
                return
            except (TimeoutError, asyncio.TimeoutError):
                continue
        raise AssertionError(f"No PONG after {what} (open but unresponsive)")
    except (ConnectionError, OSError, BrokenPipeError) as exc:
        raise AssertionError(f"Killed after {what} (expected survival): {exc!r}") from exc


# ---------------------------------------------------------------------------
# TCP: body flood (untagged)
# ---------------------------------------------------------------------------

async def test_tcp_untagged_body_flood_kills(ircd_hub):
    """Incomplete untagged junk above CLIENT_FLOOD → Excess Flood."""
    c = await _register_tcp(ircd_hub, "bfloodk")
    try:
        await _send_raw(c, b"X" * BODY_KILL)
        await _assert_killed(c, what=f"untagged body {BODY_KILL}")
    finally:
        await _cleanup(c)


async def test_tcp_untagged_body_flood_survives(ircd_hub):
    """Incomplete untagged junk under CLIENT_FLOOD stays connected."""
    c = await _register_tcp(ircd_hub, "bfloods")
    try:
        await _send_raw(c, b"X" * BODY_SAFE)
        await asyncio.sleep(0.2)
        await _assert_alive(c, what=f"untagged body {BODY_SAFE}")
    finally:
        await _cleanup(c)


async def test_tcp_body_burst_trips_body_flood(ircd_hub):
    """After throttle engages, queued complete lines trip CLIENT_FLOOD (body)."""
    c = await _register_tcp(ircd_hub, "bburst")
    try:
        # ~15-byte bodies; after cli_since blocks drain, >1024 body octets queue.
        burst = b"".join(f"PING :body{i:04d}\r\n".encode() for i in range(120))
        assert burst.count(b"\n") * 15 > BODY_FLOOD
        await _send_raw(c, burst)
        await _assert_killed(c, what="tcp untagged line body burst")
    finally:
        await _cleanup(c)


# ---------------------------------------------------------------------------
# TCP: tag flood
# ---------------------------------------------------------------------------

async def test_tcp_tag_prefix_flood_kills(ircd_hub):
    """Incomplete @-prefix above CLIENT_TAG_FLOOD → Excess Flood (body stays 0)."""
    c = await _register_tcp(ircd_hub, "tfloodk", caps=["message-tags"])
    try:
        # No separating space → entire payload is tag section for flood accounting.
        await _send_raw(c, b"@" + b"t" * TAG_KILL)
        await _assert_killed(c, what=f"tag prefix {TAG_KILL}")
    finally:
        await _cleanup(c)


async def test_tcp_tag_prefix_under_limit_survives(ircd_hub):
    """Large incomplete @-prefix under CLIENT_TAG_FLOOD does not kill."""
    c = await _register_tcp(ircd_hub, "tfloods", caps=["message-tags"])
    try:
        await _send_raw(c, b"@" + b"t" * TAG_SAFE)
        await asyncio.sleep(0.2)
        await _assert_alive(c, what=f"tag prefix {TAG_SAFE}")
    finally:
        await _cleanup(c)


async def test_tcp_tagged_body_still_trips_body_flood(ircd_hub):
    """Short tag prefix + oversized body still hits CLIENT_FLOOD, not tag flood."""
    c = await _register_tcp(ircd_hub, "tbflood", caps=["message-tags"])
    try:
        # Tags = "@x " (3); body = BODY_KILL octets of X — no CRLF.
        await _send_raw(c, b"@x " + b"X" * BODY_KILL)
        await _assert_killed(c, what=f"tagged body {BODY_KILL}")
    finally:
        await _cleanup(c)


async def test_tcp_large_tags_excluded_from_body_budget(ircd_hub):
    """Tags that would inflate a total-length check past CLIENT_FLOOD do not.

    Old accounting (DBufLength > maxflood) would kill; body-only must survive.
    """
    c = await _register_tcp(ircd_hub, "tbodyok", caps=["message-tags"])
    try:
        # tags ≈ 5002, body = 500 → total > 1024 but body under CLIENT_FLOOD.
        await _send_raw(c, b"@" + b"e" * 5000 + b" " + b"Y" * 500)
        await asyncio.sleep(0.2)
        await _assert_alive(c, what="5KB tags + 500 body (no CRLF)")
    finally:
        await _cleanup(c)


async def test_tcp_complete_large_tag_line_under_limits_survives(ircd_hub):
    """One complete line with ~4KB tags and a tiny body stays under both ceilings."""
    c = await _register_tcp(ircd_hub, "tlineok", caps=["message-tags"])
    try:
        # TAGDATA_CLIENT_MAX is 4094; stay under that and under TAG_FLOOD.
        tags = "a" * 4000
        await _send_raw(c, f"@{tags} PING :tag-ok\r\n".encode())
        await asyncio.sleep(0.2)
        await _assert_alive(c, what="complete 4KB-tag PING")
    finally:
        await _cleanup(c)


async def test_tcp_multi_line_tag_burst_trips_tag_flood(ircd_hub):
    """After throttle engages, further large-tag lines trip CLIENT_TAG_FLOOD."""
    c = await _register_tcp(ircd_hub, "tburst", caps=["message-tags"])
    try:
        # A few lines clear before the 10s cli_since gate; the rest queue.
        # Three queued ~4KB prefixes exceed 8192.
        tag = "b" * 4000
        burst = b"".join(
            f"@{tag} PING :burst{i}\r\n".encode() for i in range(10)
        )
        await _send_raw(c, burst)
        await _assert_killed(c, what="tcp large-tag line burst")
    finally:
        await _cleanup(c)


async def test_tcp_queued_complete_tag_chunk_trips_tag_flood(ircd_hub):
    """Prime throttle, then one write of several complete tagged lines.

    Unlike a bare multi-line write (racy if lines drain one-at-a-time), the
    primed cli_since gate keeps the chunk undrained so tags accumulate.
    """
    c = await _register_tcp(ircd_hub, "tchunk", caps=["message-tags"])
    try:
        tag = "d" * 4000
        await _send_raw(c, f"@{tag} PING :prime\r\n".encode())
        await asyncio.sleep(0.15)
        # Three more complete lines ≈ 12KB tags > CLIENT_TAG_FLOOD.
        chunk = b"".join(
            f"@{tag} PING :chunk{i}\r\n".encode() for i in range(3)
        )
        assert 3 * (1 + 4000 + 1) > TAG_FLOOD
        await _send_raw(c, chunk)
        await _assert_killed(c, what="primed + 3×4KB-tag chunk")
    finally:
        await _cleanup(c)


async def test_tcp_tag_flood_zero_disables_tag_ceiling(ircd_hub):
    """CLIENT_TAG_FLOOD 0 disables the tag ceiling; body flood still applies."""
    oper = await _oper(ircd_hub, "tf0oper")
    try:
        await oper.send("SET CLIENT_TAG_FLOOD 0")
        await oper.wait_for("284", timeout=8.0)

        c = await _register_tcp(ircd_hub, "tf0user", caps=["message-tags"])
        try:
            await _send_raw(c, b"@" + b"z" * TAG_KILL)
            await asyncio.sleep(0.2)
            await _assert_alive(c, what="TAG_KILL with CLIENT_TAG_FLOOD=0")
        finally:
            await _cleanup(c)

        c2 = await _register_tcp(ircd_hub, "tf0body", caps=["message-tags"])
        try:
            # Huge tags (ignored) + body over CLIENT_FLOOD → still Excess Flood.
            await _send_raw(c2, b"@" + b"z" * TAG_KILL + b" " + b"X" * BODY_KILL)
            await _assert_killed(c2, what="body kill with tag ceiling off")
        finally:
            await _cleanup(c2)
    finally:
        await oper.send("RESET CLIENT_TAG_FLOOD")
        try:
            await oper.wait_for("284", timeout=8.0)
        except (TimeoutError, asyncio.TimeoutError, ConnectionError):
            pass
        await _cleanup(oper)


# ---------------------------------------------------------------------------
# WebSocket: same ceilings (server appends \\n on FIN)
# ---------------------------------------------------------------------------

async def test_ws_untagged_body_flood_kills(ircd_hub):
    c = await _register_ws(ircd_hub, "wsbfk")
    try:
        await c.send("X" * BODY_KILL)
        await _assert_killed(c, what=f"ws untagged body {BODY_KILL}")
    finally:
        await _cleanup(c)


async def test_ws_untagged_body_flood_survives(ircd_hub):
    c = await _register_ws(ircd_hub, "wsbfs")
    try:
        await c.send("X" * BODY_SAFE)
        await asyncio.sleep(0.3)
        await _assert_alive_ws(c, what=f"ws untagged body {BODY_SAFE}")
    finally:
        await _cleanup(c)


async def test_ws_tagged_body_still_trips_body_flood(ircd_hub):
    c = await _register_ws(ircd_hub, "wstbf", caps=["message-tags"])
    try:
        await c.send("@x " + "X" * BODY_KILL)
        await _assert_killed(c, what=f"ws tagged body {BODY_KILL}")
    finally:
        await _cleanup(c)


async def test_ws_tag_prefix_flood_kills(ircd_hub):
    """WS frame `@`+big with no space; server adds \\n — still all tags for flood."""
    c = await _register_ws(ircd_hub, "wstfk", caps=["message-tags"])
    try:
        await c.send("@" + "t" * TAG_KILL)
        await _assert_killed(c, what=f"ws tag prefix {TAG_KILL}")
    finally:
        await _cleanup(c)


async def test_ws_tag_prefix_under_limit_survives(ircd_hub):
    c = await _register_ws(ircd_hub, "wstfs", caps=["message-tags"])
    try:
        # Incomplete tags + server \\n → tag section with no space; under TAG_FLOOD.
        await c.send("@" + "t" * TAG_SAFE)
        await asyncio.sleep(0.3)
        await _assert_alive_ws(c, what=f"ws tag prefix {TAG_SAFE}")
    finally:
        await _cleanup(c)


async def test_ws_body_burst_trips_body_flood(ircd_hub):
    """Throttle queue of complete WS frames trips CLIENT_FLOOD on body octets."""
    c = await _register_ws(ircd_hub, "wsbburst")
    try:
        try:
            for i in range(120):
                await c.send(f"PING :wsbody{i:04d}")
        except ConnectionClosed:
            # Server closed mid-burst — Excess Flood already fired.
            return
        await _assert_killed(c, what="ws untagged body frame burst")
    finally:
        await _cleanup(c)


async def test_ws_multi_frame_tag_burst_trips_tag_flood(ircd_hub):
    """After throttle engages, further large-tag frames trip CLIENT_TAG_FLOOD."""
    c = await _register_ws(ircd_hub, "wsburst", caps=["message-tags"])
    try:
        tag = "c" * 4000
        # ~5 lines clear before the 10s cli_since gate; the rest queue.  Three
        # queued 4KB prefixes exceed CLIENT_TAG_FLOOD (8192).
        for i in range(10):
            await c.send(f"@{tag} PING :wsburst{i}")
        await _assert_killed(c, what="ws large-tag frame burst")
    finally:
        await _cleanup(c)


async def test_ws_exempt_maxflood_body_survives_tag_still_kills(ircd_hub):
    """Raised class maxflood does not raise CLIENT_TAG_FLOOD (feature-only).

    Port 7002 → Exempt class (maxflood=262144). Body of BODY_KILL survives;
    tag prefix of TAG_KILL still Excess Flood.
    """
    c = await _register_ws(ircd_hub, "wsexb", port=WS_EXEMPT_PORT)
    try:
        await c.send("X" * BODY_KILL)
        await asyncio.sleep(0.3)
        await _assert_alive_ws(c, what=f"exempt class body {BODY_KILL}")
    finally:
        await _cleanup(c)

    c2 = await _register_ws(
        ircd_hub, "wsext", caps=["message-tags"], port=WS_EXEMPT_PORT
    )
    try:
        await c2.send("@" + "t" * TAG_KILL)
        await _assert_killed(c2, what="exempt class still tag-flooded")
    finally:
        await _cleanup(c2)
