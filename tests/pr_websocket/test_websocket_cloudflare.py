"""
WebSocket Cloudflare proxy integration tests.

Verifies CF-Connecting-IP handling, IPcheck placement, and ident policy on
``cloudflare = yes`` websocket listeners vs plain websocket/TCP ports.

  pytest test_websocket_cloudflare.py -v --timeout=120
"""

from __future__ import annotations

import asyncio
import os
import random
import struct
import time

import pytest

from irc_client import IRCClient, parse_message

pytestmark = pytest.mark.single_server

HOST = "127.0.0.1"
NORMAL_PORT = 6667
WS_PORT = 7000
CF_WS_PORT = 7001

# RFC 5737 documentation range — not routed on the public internet.
CF_CLIENT_IP = "203.0.113.50"
SPOOF_IP = "203.0.113.99"

_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="


def _raw_ws_handshake(*extra_header_lines: bytes) -> bytes:
    lines = [
        b"GET / HTTP/1.1\r\n",
        b"Host: 127.0.0.1\r\n",
        b"Upgrade: websocket\r\n",
        b"Connection: Upgrade\r\n",
        b"Sec-WebSocket-Key: " + _WS_KEY.encode() + b"\r\n",
        b"Sec-WebSocket-Version: 13\r\n",
        b"Sec-WebSocket-Protocol: text.ircv3.net\r\n",
    ]
    lines.extend(extra_header_lines)
    lines.append(b"\r\n")
    return b"".join(lines)


def _masked_client_frame(opcode: int, payload: bytes) -> bytes:
    pl = len(payload)
    b0 = (0x80 | (opcode & 0x0F)) & 0xFF
    if pl <= 125:
        hdr = struct.pack("!BB", b0, 0x80 | pl)
    elif pl < 65536:
        hdr = struct.pack("!BBH", b0, 0x80 | 126, pl)
    else:
        hdr = struct.pack("!BB", b0, 0x80 | 127) + b"\x00\x00\x00\x00" + struct.pack("!I", pl)
    key = os.urandom(4)
    masked = bytes(payload[i] ^ key[i % 4] for i in range(pl))
    return hdr + key + masked


def _masked_text_frame(line: str) -> bytes:
    return _masked_client_frame(0x1, (line + "\r\n").encode("utf-8"))


async def _read_http_response(r: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5.0)


async def _read_one_unmasked_server_ws_frame(
    r: asyncio.StreamReader, *, read_timeout: float
) -> tuple[int, bytes]:
    """Read next server→client WebSocket frame (unmasked). Returns (opcode, payload)."""
    b0, b1 = await asyncio.wait_for(r.readexactly(2), timeout=read_timeout)
    pl = b1 & 0x7F
    if pl == 126:
        pl = int.from_bytes(await asyncio.wait_for(r.readexactly(2), timeout=read_timeout), "big")
    elif pl == 127:
        ext = await asyncio.wait_for(r.readexactly(8), timeout=read_timeout)
        pl = int.from_bytes(ext[4:8], "big")
    payload = await asyncio.wait_for(r.readexactly(pl), timeout=read_timeout) if pl else b""
    return b0 & 0x0F, payload


async def _attempt_ws_handshake(
    port: int,
    *,
    extra_headers: tuple[bytes, ...] = (),
) -> tuple[bool, bytes]:
    """Return (upgraded, response_prefix). Rejected handshakes close with an ERROR line."""
    reader, writer = await asyncio.open_connection(HOST, port)
    try:
        writer.write(_raw_ws_handshake(*extra_headers))
        await writer.drain()
        try:
            http = await _read_http_response(reader)
        except asyncio.IncompleteReadError as exc:
            return False, exc.partial or b""
        return b"101" in http, http
    finally:
        writer.close()


async def _ws_register_collect_notices(
    port: int,
    nick: str,
    *,
    extra_headers: tuple[bytes, ...] = (),
    stop_after_notices: bool = False,
    keep_open: bool = False,
) -> tuple[list[str], list[str], asyncio.StreamWriter | None]:
    """Complete a WS handshake and registration; return (notice texts, raw lines, writer).

    When ``keep_open`` is true the WebSocket connection stays up until the caller
    closes ``writer`` (used when another client will WHOIS this session).
    """
    reader, writer = await asyncio.open_connection(HOST, port)
    try:
        writer.write(_raw_ws_handshake(*extra_headers))
        await writer.drain()
        http = await _read_http_response(reader)
        if b"101" not in http:
            raise AssertionError(f"expected HTTP 101 on port {port}, got {http[:300]!r}")

        writer.write(_masked_text_frame(f"NICK {nick}"))
        writer.write(_masked_text_frame("USER wsuser 0 * :Cloudflare WS test"))
        await writer.drain()

        notices: list[str] = []
        raw_lines: list[str] = []
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            slot = min(5.0, max(0.25, deadline - time.monotonic()))
            try:
                opcode, payload = await _read_one_unmasked_server_ws_frame(
                    reader, read_timeout=slot
                )
            except asyncio.TimeoutError:
                continue
            if opcode == 0x8:
                break
            if opcode == 0x9:
                writer.write(_masked_client_frame(0xA, payload))
                await writer.drain()
                continue
            if opcode != 0x1:
                continue
            line = payload.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            raw_lines.append(line)
            msg = parse_message(line)
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
                if stop_after_notices and "Checking Ident" in " ".join(msg.params):
                    if keep_open:
                        return notices, raw_lines, writer
                    return notices, raw_lines, None
            if msg.command.upper() == "PING":
                writer.write(_masked_text_frame(f"PONG :{msg.params[-1]}"))
                await writer.drain()
                continue
            if msg.command in ("376", "422"):
                if keep_open:
                    return notices, raw_lines, writer
                return notices, raw_lines, None
        raise AssertionError("registration ended without MOTD")
    finally:
        if not keep_open:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _whois_userhost(observer: IRCClient, nick: str) -> tuple[str, str]:
    """Return (username, host) from RPL_WHOISUSER."""
    await observer.send(f"WHOIS {nick}")
    while True:
        msg = await observer.recv(timeout=10.0)
        if msg.command == "311":
            return msg.params[2], msg.params[3]
        if msg.command in ("318", "401"):
            raise AssertionError(f"WHOIS for {nick} failed: {msg}")


async def _whois_host(observer: IRCClient, nick: str) -> str:
    _, host = await _whois_userhost(observer, nick)
    return host


@pytest.mark.asyncio
async def test_cloudflare_port_uses_cf_connecting_ip(ircd_hub, make_client):
    """CF-Connecting-IP becomes the client address on a cloudflare websocket port."""
    observer = await make_client("cfwho")
    nick = f"cfok{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
    _, _, ws_writer = await _ws_register_collect_notices(
        CF_WS_PORT, nick, extra_headers=headers, keep_open=True
    )
    assert ws_writer is not None
    try:
        host = await _whois_host(observer, nick)
        assert host == CF_CLIENT_IP, f"expected WHOIS host {CF_CLIENT_IP}, got {host!r}"
    finally:
        ws_writer.write(_masked_text_frame("QUIT :done"))
        await ws_writer.drain()
        ws_writer.close()
        await observer.send("QUIT :done")


@pytest.mark.asyncio
async def test_plain_websocket_ignores_cf_connecting_ip(ircd_hub, make_client):
    """CF-Connecting-IP is ignored on websocket ports without cloudflare = yes."""
    observer = await make_client("wswho")
    nick = f"wsno{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + SPOOF_IP.encode() + b"\r\n",)
    _, _, ws_writer = await _ws_register_collect_notices(
        WS_PORT, nick, extra_headers=headers, keep_open=True
    )
    assert ws_writer is not None
    try:
        host = await _whois_host(observer, nick)
        assert host != SPOOF_IP, (
            f"plain websocket port must not trust CF-Connecting-IP; WHOIS host was {host!r}"
        )
    finally:
        ws_writer.write(_masked_text_frame("QUIT :done"))
        await ws_writer.drain()
        ws_writer.close()
        await observer.send("QUIT :done")


@pytest.mark.asyncio
async def test_cloudflare_port_rejects_missing_cf_connecting_ip(ircd_hub):
    """cloudflare = yes requires a valid CF-Connecting-IP header at handshake."""
    upgraded, response = await _attempt_ws_handshake(CF_WS_PORT)
    assert not upgraded, f"handshake should fail without CF-Connecting-IP, got {response[:200]!r}"


@pytest.mark.asyncio
async def test_cloudflare_port_rejects_invalid_cf_connecting_ip(ircd_hub):
    upgraded, response = await _attempt_ws_handshake(
        CF_WS_PORT, extra_headers=(b"CF-Connecting-IP: not-an-ip\r\n",)
    )
    assert not upgraded, f"invalid CF-Connecting-IP must be rejected, got {response[:200]!r}"


def _notice_blob(notices: list[str]) -> str:
    return "\n".join(notices)


@pytest.mark.asyncio
async def test_cloudflare_websocket_keeps_tilde_without_ident(ircd_hub, make_client):
    """Skipping ident on cloudflare ports must not trust the USER username.

    Clients still get a leading ~ unless iauth/WEBIRC (or a successful
    ident, which cannot run here) explicitly trusts the name.
    """
    observer = await make_client("cftil")
    nick = f"cftu{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
    _, _, ws_writer = await _ws_register_collect_notices(
        CF_WS_PORT, nick, extra_headers=headers, keep_open=True
    )
    assert ws_writer is not None
    try:
        username, host = await _whois_userhost(observer, nick)
        assert host == CF_CLIENT_IP, f"expected CF IP host, got {host!r}"
        assert username.startswith("~"), (
            f"cloudflare WS without trusted username must keep tilde, got {username!r}"
        )
        assert username == "~wsuser", f"unexpected username {username!r}"
    finally:
        ws_writer.write(_masked_text_frame("QUIT :done"))
        await ws_writer.drain()
        ws_writer.close()
        await observer.send("QUIT :done")


@pytest.mark.asyncio
async def test_cloudflare_websocket_skips_ident_lookup(ircd_hub):
    """Ident is not queried for cloudflare websocket clients."""
    nick = f"cfid{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
    notices, _, _ = await _ws_register_collect_notices(CF_WS_PORT, nick, extra_headers=headers)
    blob = _notice_blob(notices)
    assert "Checking Ident" not in blob, f"cloudflare WS should skip ident, got notices: {blob!r}"


@pytest.mark.asyncio
async def test_plain_websocket_runs_ident_lookup(ircd_hub):
    """Plain websocket ports still attempt ident when enabled in config."""
    nick = f"wsid{random.randint(0, 999_999)}"
    notices, _, _ = await _ws_register_collect_notices(
        WS_PORT, nick, stop_after_notices=True
    )
    blob = _notice_blob(notices)
    assert "Checking Ident" in blob, f"plain WS should attempt ident, got notices: {blob!r}"


@pytest.mark.asyncio
async def test_plain_tcp_runs_ident_lookup(ircd_hub):
    """Normal TCP user ports attempt ident when enabled in config."""
    nick = f"tcpid{random.randint(0, 999_999)}"
    client = IRCClient()
    await client.connect(HOST, NORMAL_PORT)
    notices: list[str] = []
    try:
        await client.send(f"NICK {nick}")
        await client.send("USER tcpuser 0 * :TCP ident test")
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            msg = await client.recv(timeout=5.0)
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
                if "Checking Ident" in " ".join(msg.params):
                    break
            if msg.command in ("376", "422"):
                break
    finally:
        await client.disconnect()

    blob = _notice_blob(notices)
    assert "Checking Ident" in blob, f"TCP port should attempt ident, got notices: {blob!r}"


@pytest.mark.asyncio
async def test_cloudflare_defers_ipcheck_until_handshake(ircd_hub):
    """Many TCP accepts from one socket IP do not throttle before CF IP is applied."""
    # Without deferred IPcheck, repeated connects from the same peer could hit
    # limits at accept time. Cloudflare ports defer until CF-Connecting-IP.
    for i in range(6):
        upgraded, http = await _attempt_ws_handshake(
            CF_WS_PORT,
            extra_headers=(b"CF-Connecting-IP: " + f"203.0.113.{10 + i}".encode() + b"\r\n",),
        )
        assert upgraded, f"connect {i}: expected 101, got {http[:120]!r}"
