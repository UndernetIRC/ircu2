import asyncio
import os
import random
import ssl
import struct
import time

import pytest
import websockets
from irc_ws_client import IRCWebSocketClient


# Ports must match your ircd config and docker-compose.yml
NORMAL_PORT = 6667
WS_PORT = 7000
HOST = "127.0.0.1"
WS_URL = f"ws://{HOST}:{WS_PORT}/"

from irc_client import IRCClient, parse_message
from irc_ws_client import parse_message as parse_ws_irc_line

# Same minimal GET as tests/test_websocket_protocol_confusion.py (RFC 6455 example key)
_RAW_WS_HANDSHAKE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Protocol: text.ircv3.net\r\n"
    b"\r\n"
)


def _masked_ws_client_frame(opcode: int, payload: bytes) -> bytes:
    """One client→server masked frame (FIN set)."""
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


async def _read_http_101_ws(r: asyncio.StreamReader) -> None:
    # readuntil leaves any bytes after \r\n\r\n in the StreamReader buffer
    # (safe if the server coalesces 101 Switching Protocols with the first WS frame).
    http = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5.0)
    if b"101" not in http:
        raise AssertionError(f"expected HTTP 101, got {http[:400]!r}")


async def _read_one_unmasked_server_ws_frame(r: asyncio.StreamReader, *, read_timeout: float):
    """Read next server→client WebSocket frame (unmasked). Returns (opcode, payload)."""
    b0, b1 = await asyncio.wait_for(r.readexactly(2), timeout=read_timeout)
    masked = (b1 & 0x80) != 0
    pl = b1 & 0x7F
    if pl == 126:
        pl = int.from_bytes(await asyncio.wait_for(r.readexactly(2), timeout=read_timeout), "big")
    elif pl == 127:
        ext = await asyncio.wait_for(r.readexactly(8), timeout=read_timeout)
        pl = int.from_bytes(ext[4:8], "big")
    if masked:
        key = await asyncio.wait_for(r.readexactly(4), timeout=read_timeout)
        raw = await asyncio.wait_for(r.readexactly(pl), timeout=read_timeout)
        payload = bytes(raw[i] ^ key[i % 4] for i in range(pl))
    else:
        payload = (
            await asyncio.wait_for(r.readexactly(pl), timeout=read_timeout) if pl else b""
        )
    opcode = b0 & 0x0F
    return opcode, payload

@pytest.mark.asyncio
async def test_websocket_and_normal_ports(make_client):
    # 1. Normal client to normal port (should succeed)
    client1 = IRCClient()
    await client1.connect(HOST, NORMAL_PORT)
    await client1.send("NICK norm1")
    await client1.send("USER norm1 0 * :Normal 1")
    msg = await client1.wait_for("001", timeout=5.0)
    assert msg.command == "001"
    await client1.disconnect()

    # 2a. WebSocket client to WebSocket port (text mode, should succeed)
    try:
        ws_client_text = IRCWebSocketClient()
        await ws_client_text.connect(WS_URL, subprotocols=["text.ircv3.net"])
        await ws_client_text.send("NICK ws1")
        await ws_client_text.send("USER ws1 0 * :WebSocket 1")
        # Check the raw frame type
        raw_text = await asyncio.wait_for(ws_client_text._ws.recv(), timeout=5.0)
        assert isinstance(raw_text, str), f"Expected text frame, got {type(raw_text)}: {raw_text!r}"
        # Assert that the frame does not contain a raw \r\n sequence (should be split per frame)
        assert "\r\n" not in raw_text, f"WebSocket frame contains unexpected CRLF: {raw_text!r}"
        await ws_client_text.disconnect()
    except Exception as e:
        pytest.fail(f"WebSocket handshake or IRC registration failed (text): {e}")

    # 2b. WebSocket client to WebSocket port (binary mode, should succeed)
    try:
        ws_client_bin = IRCWebSocketClient(binary=True)
        await ws_client_bin.connect(WS_URL, subprotocols=["binary.ircv3.net"])
        await ws_client_bin.send("NICK ws2")
        await ws_client_bin.send("USER ws2 0 * :WebSocket 2")
        # Check the raw frame type
        raw_bin = await asyncio.wait_for(ws_client_bin._ws.recv(), timeout=5.0)
        assert isinstance(raw_bin, bytes), f"Expected binary frame, got {type(raw_bin)}: {raw_bin!r}"
        await ws_client_bin.disconnect()
    except Exception as e:
        pytest.fail(f"WebSocket handshake or IRC registration failed (binary): {e}")

    # 4. Normal client to WebSocket port (should fail handshake or protocol)
    client2 = IRCClient()
    try:
        await client2.connect(HOST, WS_PORT)
        await client2.send("NICK norm2")
        await client2.send("USER norm2 0 * :Normal 2")
        # Should not get a 001 welcome; expect disconnect or error
        with pytest.raises((asyncio.TimeoutError, ConnectionError)):
            await client2.wait_for("001", timeout=2.0)
    finally:
        await client2.disconnect()

    # 4. WebSocket client to normal port (should fail handshake)
    bad_ws_url = f"ws://{HOST}:{NORMAL_PORT}/"
    with pytest.raises(Exception):
        async with websockets.connect(bad_ws_url, subprotocols=["text.ircv3.net"]) as ws:
            await ws.send("NICK ws2\r\nUSER ws2 0 * :WebSocket 2\r\n")
            await asyncio.wait_for(ws.recv(), timeout=2)


@pytest.mark.asyncio
async def test_wss_to_plain_websocket_port_tls_fails(ircd_hub):
    """Docker hub serves cleartext WS on 7000; wss:// must fail TLS (no silent 101)."""
    wss_url = f"wss://{HOST}:{WS_PORT}/"
    with pytest.raises(Exception) as exc:
        async with websockets.connect(
            wss_url,
            subprotocols=["text.ircv3.net"],
            open_timeout=5.0,
            close_timeout=2.0,
        ) as ws:
            await ws.recv()
    err = exc.value
    # Typical: SSLError (wrong data from non-TLS peer) or wrapped transport error
    chain = [err]
    c = err.__cause__
    while c is not None and len(chain) < 5:
        chain.append(c)
        c = c.__cause__
    assert any(
        isinstance(e, ssl.SSLError)
        or isinstance(e, (ConnectionError, OSError))
        or "ssl" in type(e).__name__.lower()
        for e in chain
    ), f"expected TLS/transport failure, got {err!r} chain={chain!r}"


@pytest.mark.asyncio
async def test_websocket_keepalive_server_rfc6455_ping(ircd_hub):
    """Docker hub sets WEBSOCKET_KEEPALIVE=2; server sends empty RFC6455 Ping (0x89 0x00).

    The ``websockets`` library answers transport Pings internally, so this test uses
    raw TCP to assert the wire bytes. Client replies with a masked Pong (0xA).
    """
    nick = f"k{random.randint(0, 999_999)}"
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    try:
        w.write(_RAW_WS_HANDSHAKE)
        await w.drain()
        await _read_http_101_ws(r)

        w.write(_masked_ws_client_frame(0x1, f"NICK {nick}\r\n".encode()))
        w.write(_masked_ws_client_frame(0x1, f"USER {nick} 0 * :ws keepalive test\r\n".encode()))
        await w.drain()

        seen_001 = False
        saw_ping = False
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            slot = min(8.0, max(0.25, deadline - time.monotonic()))
            opcode, payload = await _read_one_unmasked_server_ws_frame(r, read_timeout=slot)
            if opcode == 0x9:
                assert payload == b"", f"expected empty Ping payload, got {payload!r}"
                saw_ping = True
                w.write(_masked_ws_client_frame(0xA, payload))
                await w.drain()
                break
            if opcode == 0x1:
                line = payload.decode("utf-8", errors="replace").strip()
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "001":
                    seen_001 = True
                msg = parse_ws_irc_line(line)
                if msg.command.upper() == "PING":
                    w.write(_masked_ws_client_frame(0x1, f"PONG :{msg.params[-1]}\r\n".encode()))
                    await w.drain()
            elif opcode == 0x8:
                pytest.fail(f"server closed WebSocket before Ping: code/payload {payload!r}")

        assert seen_001, "never saw IRC 001 (registration)"
        assert saw_ping, (
            "timed out waiting for RFC6455 Ping; check WEBSOCKET_KEEPALIVE and PINGFREQUENCY "
            "in tests/docker/ircd-hub.conf (check_pings must run before keepalive is sent)"
        )
    finally:
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass

