"""
WebSocket-over-TLS (WSS) integration tests.

Requires the tls-hub Docker service (``ircd_tls_network``) with WSS ports
6700 (plain WSS) and 6701 (WSS + cloudflare).

  TLS_BACKEND=openssl pytest test_websocket_wss.py -v --timeout=300
"""

from __future__ import annotations

import asyncio
import os
import random
import struct

import pytest

from irc_client import IRCClient, parse_message
from irc_ws_client import IRCWebSocketClient
from tls_certs import client_ssl_context

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

CF_CLIENT_IP = "203.0.113.50"

_WS_KEY = b"dGhlIHNhbXBsZSBub25jZQ=="


def _raw_ws_handshake(*extra_header_lines: bytes) -> bytes:
    lines = [
        b"GET / HTTP/1.1\r\n",
        b"Host: 127.0.0.1\r\n",
        b"Upgrade: websocket\r\n",
        b"Connection: Upgrade\r\n",
        b"Sec-WebSocket-Key: " + _WS_KEY + b"\r\n",
        b"Sec-WebSocket-Version: 13\r\n",
        b"Sec-WebSocket-Protocol: text.ircv3.net\r\n",
    ]
    lines.extend(extra_header_lines)
    lines.append(b"\r\n")
    return b"".join(lines)


def _masked_text_frame(line: str) -> bytes:
    payload = (line + "\r\n").encode("utf-8")
    pl = len(payload)
    b0 = 0x81
    if pl <= 125:
        hdr = struct.pack("!BB", b0, 0x80 | pl)
    elif pl < 65536:
        hdr = struct.pack("!BBH", b0, 0x80 | 126, pl)
    else:
        hdr = struct.pack("!BB", b0, 0x80 | 127) + b"\x00\x00\x00\x00" + struct.pack("!I", pl)
    key = os.urandom(4)
    masked = bytes(payload[i] ^ key[i % 4] for i in range(pl))
    return hdr + key + masked


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


async def _read_http_response(reader: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)


async def _read_server_ws_frame(
    reader: asyncio.StreamReader, *, timeout: float = 5.0
) -> tuple[int, bytes]:
    """Read next server→client WebSocket frame. Returns (opcode, payload)."""
    b0, b1 = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    pl = b1 & 0x7F
    if pl == 126:
        pl = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), timeout=timeout), "big")
    elif pl == 127:
        ext = await asyncio.wait_for(reader.readexactly(8), timeout=timeout)
        pl = int.from_bytes(ext[4:8], "big")
    payload = await asyncio.wait_for(reader.readexactly(pl), timeout=timeout) if pl else b""
    return b0 & 0x0F, payload


async def test_wss_registration(ircd_tls_network):
    """Register over wss:// on a tls + websocket port."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    url = f"wss://{hub['host']}:{hub['wss_port']}/"
    client = IRCWebSocketClient()
    await client.connect(url, ssl=ctx)
    try:
        nick = f"w{random.randint(0, 999_999)}"
        msgs = await client.register(nick, "wssuser", "WSS Test")
        assert any(m.command == "001" for m in msgs), msgs
    finally:
        await client.disconnect()


async def test_wss_and_plain_irc_ports(ircd_tls_network):
    """WSS client registers; plain IRC still works on the tls-hub cleartext port."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()

    ws = IRCWebSocketClient()
    nick = f"m{random.randint(0, 999_999)}"
    await ws.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=ctx)
    try:
        ws_msgs = await ws.register(nick, "wssmix", "WSS mix test")
        assert any(m.command == "001" for m in ws_msgs)
    finally:
        await ws.disconnect()

    irc = IRCClient()
    await irc.connect(hub["host"], hub["port"])
    try:
        msgs = await irc.register(f"i{random.randint(0, 999_999)}", "ircuser", "Plain IRC")
        assert any(m.command == "001" for m in msgs)
    finally:
        await irc.disconnect()


async def test_ws_to_wss_port_fails(ircd_tls_network):
    """Cleartext WebSocket handshake on a TLS-only WSS port must not upgrade."""
    hub = ircd_tls_network["hub"]
    reader, writer = await asyncio.open_connection(hub["host"], hub["wss_port"])
    try:
        writer.write(_raw_ws_handshake())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=3.0)
        assert b"101" not in data
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def test_wss_cloudflare_handshake_and_registration(ircd_tls_network):
    """WSS on a cloudflare port accepts CF-Connecting-IP and completes registration."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    nick = f"c{random.randint(0, 999_999)}"
    headers = (f"CF-Connecting-IP: {CF_CLIENT_IP}\r\n".encode(),)

    reader, writer = await asyncio.open_connection(
        hub["host"], hub["wss_cf_port"], ssl=ctx
    )
    try:
        writer.write(_raw_ws_handshake(*headers))
        await writer.drain()
        http = await _read_http_response(reader)
        assert b"101" in http.split(b"\r\n", 1)[0]

        writer.write(_masked_text_frame(f"NICK {nick}"))
        writer.write(_masked_text_frame("USER wsuser 0 * :WSS CF test"))
        await writer.drain()

        deadline = asyncio.get_running_loop().time() + 45.0
        got_welcome = False
        while asyncio.get_running_loop().time() < deadline:
            slot = min(5.0, deadline - asyncio.get_running_loop().time())
            try:
                opcode, payload = await _read_server_ws_frame(reader, timeout=slot)
            except TimeoutError:
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
            msg = parse_message(line)
            if msg.command.upper() == "PING":
                writer.write(_masked_text_frame(f"PONG :{msg.params[-1]}"))
                await writer.drain()
                continue
            if msg.command == "001":
                got_welcome = True
                break
            if msg.command == "ERROR":
                pytest.fail(f"unexpected ERROR during WSS CF registration: {line!r}")
        assert got_welcome, "expected 001 over WSS with CF-Connecting-IP"
    finally:
        writer.write(_masked_text_frame("QUIT :done"))
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def test_wss_cloudflare_rejects_missing_cf_ip(ircd_tls_network):
    """cloudflare WSS ports reject handshakes without CF-Connecting-IP."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context()
    reader, writer = await asyncio.open_connection(
        hub["host"], hub["wss_cf_port"], ssl=ctx
    )
    try:
        writer.write(_raw_ws_handshake())
        await writer.drain()
        http = await asyncio.wait_for(reader.read(512), timeout=5.0)
        assert b"101" not in http
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
