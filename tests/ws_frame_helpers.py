"""Raw RFC 6455 frame helpers for byte-level WebSocket tests.

These bypass the ``websockets`` library so tests can control framing,
masking, fragmentation, and how bytes are split across TCP writes.
"""

from __future__ import annotations

import asyncio
import os
import struct

HOST = "127.0.0.1"
WS_PORT = 7000
WS_CF_PORT = 7001

# Minimal RFC 6455 opening handshake (key is the example from the RFC).
RAW_HANDSHAKE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Protocol: text.ircv3.net\r\n"
    b"\r\n"
)


def masked_ws_frame(opcode: int, payload: bytes, *, fin: bool = True) -> bytes:
    """Build one client->server masked frame (RFC 6455)."""
    pl = len(payload)
    b0 = ((0x80 if fin else 0x00) | (opcode & 0x0F)) & 0xFF
    if pl <= 125:
        hdr = struct.pack("!BB", b0, 0x80 | pl)
    elif pl < 65536:
        hdr = struct.pack("!BBH", b0, 0x80 | 126, pl)
    else:
        # ircd reads a 32-bit length at buf[6..9]; buf[2..5] are left zero.
        hdr = struct.pack("!BB", b0, 0x80 | 127) + b"\x00\x00\x00\x00" + struct.pack("!I", pl)
    key = os.urandom(4)
    masked = bytes(payload[i] ^ key[i % 4] for i in range(pl))
    return hdr + key + masked


def masked_text_frame(payload: bytes, *, fin: bool = True) -> bytes:
    """One client->server masked text frame (opcode 0x1)."""
    return masked_ws_frame(0x1, payload, fin=fin)


async def read_http_101(r: asyncio.StreamReader) -> bytes:
    """Consume the HTTP upgrade response; assert it is a 101."""
    http = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5.0)
    if b"101" not in http:
        raise AssertionError(f"expected HTTP 101, got {http[:400]!r}")
    return http


async def raw_ws_connect(port: int = WS_PORT):
    """TCP-connect to a WS port, complete the handshake, return (reader, writer)."""
    r, w = await asyncio.open_connection(HOST, port)
    w.write(RAW_HANDSHAKE)
    await w.drain()
    await read_http_101(r)
    return r, w


async def read_server_frame(r: asyncio.StreamReader, *, timeout: float = 5.0):
    """Read one server->client frame. Returns (opcode, payload bytes)."""
    b0, b1 = await asyncio.wait_for(r.readexactly(2), timeout=timeout)
    masked = (b1 & 0x80) != 0
    pl = b1 & 0x7F
    if pl == 126:
        pl = int.from_bytes(await asyncio.wait_for(r.readexactly(2), timeout=timeout), "big")
    elif pl == 127:
        ext = await asyncio.wait_for(r.readexactly(8), timeout=timeout)
        pl = int.from_bytes(ext[4:8], "big")
    if masked:
        key = await asyncio.wait_for(r.readexactly(4), timeout=timeout)
        raw = await asyncio.wait_for(r.readexactly(pl), timeout=timeout) if pl else b""
        payload = bytes(raw[i] ^ key[i % 4] for i in range(pl))
    else:
        payload = await asyncio.wait_for(r.readexactly(pl), timeout=timeout) if pl else b""
    return b0 & 0x0F, payload


async def register_over_raw_ws(r, w, nick: str, *, timeout: float = 15.0) -> bool:
    """Drive NICK/USER over already-open raw WS; return True once RPL_WELCOME (001) seen.

    Replies to IRC PING and RFC 6455 Ping frames encountered along the way.
    """
    w.write(masked_text_frame(f"NICK {nick}\r\n".encode()))
    w.write(masked_text_frame(f"USER {nick} 0 * :{nick}\r\n".encode()))
    await w.drain()
    return await wait_for_numeric(r, w, "001", timeout=timeout)


async def wait_for_numeric(r, w, numeric: str, *, timeout: float = 15.0) -> bool:
    """Read server frames until an IRC line with the given numeric/command appears.

    Answers IRC PING (text) and RFC 6455 Ping (opcode 0x9) so registration can complete.
    Returns True if seen before timeout, else False.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            opcode, payload = await read_server_frame(r, timeout=deadline - loop.time())
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return False
        if opcode == 0x9:  # RFC 6455 Ping -> Pong
            w.write(masked_ws_frame(0xA, payload))
            await w.drain()
            continue
        if opcode == 0x8:  # Close
            return False
        if opcode not in (0x1, 0x2):
            continue
        text = payload.decode("utf-8", errors="replace")
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("PING"):
                token = line[4:].strip()
                w.write(masked_text_frame(f"PONG {token}\r\n".encode()))
                await w.drain()
                continue
            parts = line.split()
            cmd = parts[1] if line.startswith(":") and len(parts) > 1 else parts[0]
            if cmd == numeric:
                return True
    return False
