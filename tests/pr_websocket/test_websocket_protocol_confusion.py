"""
Protocol-mismatch and malformed-input tests: plain TCP on the WS port, WS-ish
bytes on the IRC port, oversized frames, illegal frames.

Goal: the hub must keep accepting normal registrations after each abuse (no crash).

Requires Docker hub (``ircd_hub``). Marked ``websocket_stress``.

  pytest test_websocket_protocol_confusion.py -v --timeout=300
"""

from __future__ import annotations

import asyncio
import os
import random
import struct

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.websocket_stress

HOST = "127.0.0.1"
NORMAL_PORT = 6667
WS_PORT = 7000

# Minimal RFC 6455 opening handshake (key is example from RFC)
_RAW_HANDSHAKE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Protocol: text.ircv3.net\r\n"
    b"\r\n"
)


async def _assert_hub_accepts_registration() -> None:
    """Prove ircd still serves normal TCP IRC after abusive connections."""
    nick = f"alive{random.randint(0, 999_999)}"
    c = IRCClient()
    await c.connect(HOST, NORMAL_PORT)
    try:
        await c.register(nick, "h", "post-abuse health")
        await c.send("QUIT :ok")
    finally:
        await c.disconnect()


def _masked_ws_frame(opcode: int, payload: bytes, *, fin: bool = True) -> bytes:
    """Client→server masked frame (RFC 6455); server requires mask bit from clients."""
    pl = len(payload)
    b0 = ((0x80 if fin else 0x00) | (opcode & 0x0F)) & 0xFF
    if pl <= 125:
        hdr = struct.pack("!BB", b0, 0x80 | pl)
    elif pl < 65536:
        hdr = struct.pack("!BBH", b0, 0x80 | 126, pl)
    else:
        # ircd uses 32-bit length at buf[6..9] with buf[2..5] ignored
        hdr = struct.pack("!BB", b0, 0x80 | 127) + b"\x00\x00\x00\x00" + struct.pack("!I", pl)
    key = os.urandom(4)
    masked = bytes(payload[i] ^ key[i % 4] for i in range(pl))
    return hdr + key + masked


def _masked_ws_frame_127_junk_high32(payload: bytes, opcode: int = 0x1) -> bytes:
    """127-length form with non-zero buf[2..5] (64-bit path); length only from buf[6..9]."""
    pl = len(payload)
    b0 = (0x80 | (opcode & 0x0F)) & 0xFF
    hdr = struct.pack("!BB", b0, 0x80 | 127) + struct.pack("!I", 0xDEADBEEF) + struct.pack("!I", pl)
    key = os.urandom(4)
    masked = bytes(payload[i] ^ key[i % 4] for i in range(pl))
    return hdr + key + masked


def _masked_text_frame(payload: bytes) -> bytes:
    """Build one client→server masked text frame (FIN, opcode 1)."""
    return _masked_ws_frame(0x1, payload, fin=True)


async def _read_http_101(r: asyncio.StreamReader) -> bytes:
    buf = b""
    for _ in range(50):
        chunk = await asyncio.wait_for(r.read(4096), timeout=5.0)
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf:
            break
    if b"101" not in buf:
        raise AssertionError(f"expected HTTP 101, got: {buf[:500]!r}")
    return buf


async def _raw_ws_connect():
    """TCP to WS port; complete handshake; return (reader, writer)."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(_RAW_HANDSHAKE)
    await w.drain()
    await _read_http_101(r)
    return r, w


@pytest.mark.asyncio
async def test_plain_irc_bytes_on_websocket_port_then_hub_ok(ircd_hub):
    """Send cleartext IRC (no HTTP upgrade) on port 7000; ircd must survive."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(b"NICK plain\r\nUSER plain 0 * :Plain TCP on WS port\r\n")
    await w.drain()
    await asyncio.sleep(0.4)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_http_terminator_without_ws_headers_on_ws_port(ircd_hub):
    """Double-CRLF blob that is not a WebSocket upgrade (handshake should fail)."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(b"NICK x\r\nUSER x 0 * :y\r\n\r\n")
    await w.drain()
    await asyncio.sleep(0.4)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_large_preamble_no_double_crlf_on_ws_port(ircd_hub):
    """Fill handshake buffer without completing HTTP; then close (no excess flood)."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(b"A" * 2000)
    await w.drain()
    await asyncio.sleep(0.2)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_oversize_handshake_accumulation_on_ws_port(ircd_hub):
    """Push past WEBSOCKET_MAX_HEADER (~4096) to trigger excess-flood path on that socket."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(b"X" * 5000)
    await w.drain()
    await asyncio.sleep(0.3)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_http_upgrade_blob_on_normal_irc_port_then_hub_ok(ircd_hub):
    """Send a WebSocket-style HTTP GET on 6667 (plain IRC); must not kill the daemon."""
    r, w = await asyncio.open_connection(HOST, NORMAL_PORT)
    w.write(_RAW_HANDSHAKE)
    await w.drain()
    await asyncio.sleep(0.4)
    w.write(b"QUIT :bye\r\n")
    await w.drain()
    await asyncio.sleep(0.2)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_masked_ws_frame_bytes_on_normal_irc_port(ircd_hub):
    """Binary-looking masked frame on cleartext IRC port."""
    r, w = await asyncio.open_connection(HOST, NORMAL_PORT)
    junk = _masked_text_frame(b"PRIVMSG #x :not a websocket port\r\n")
    w.write(junk)
    await w.drain()
    await asyncio.sleep(0.3)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_long_masked_text_frame_valid_ws(ircd_hub):
    """After real handshake, one huge text frame (server truncates IRC line to buffer)."""
    r, w = await _raw_ws_connect()
    # ~18 KiB payload in one frame; ircd copies at most ~512 bytes per frame into dbuf
    payload = b"A" * 18000
    w.write(_masked_text_frame(payload))
    await w.drain()
    await asyncio.sleep(0.4)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_very_long_masked_frame_64k_valid_ws(ircd_hub):
    """64 KiB text frame — stresses length decoding and loop."""
    r, w = await _raw_ws_connect()
    payload = bytes((i * 17 + 41) & 0xFF for i in range(65536))
    w.write(_masked_text_frame(payload))
    await w.drain()
    await asyncio.sleep(0.6)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_unmasked_client_frame_on_ws_port(ircd_hub):
    """RFC violation: client sends unmasked text frame (server may mis-parse)."""
    r, w = await _raw_ws_connect()
    pl = b"NICK bad\r\n"
    # FIN+text, unmasked, length 9
    w.write(bytes([0x81, len(pl)]) + pl)
    await w.drain()
    await asyncio.sleep(0.4)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_truncated_ws_frame_on_ws_port(ircd_hub):
    """Only first byte of a frame, then hang up."""
    r, w = await _raw_ws_connect()
    w.write(b"\x81")
    await w.drain()
    await asyncio.sleep(0.2)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_split_handshake_across_writes_on_ws_port(ircd_hub):
    """Upgrade sent in tiny chunks (still valid)."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    for chunk in (_RAW_HANDSHAKE[i : i + 7] for i in range(0, len(_RAW_HANDSHAKE), 7)):
        w.write(chunk)
        await w.drain()
        await asyncio.sleep(0.02)
    await _read_http_101(r)
    w.write(_masked_text_frame(b"QUIT :split\r\n"))
    await w.drain()
    await asyncio.sleep(0.2)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_max_length_sec_websocket_key_header_on_ws_port(ircd_hub):
    """Key value fills sec_ws_key[128] via strncpy; must stay NUL-terminated (no %s over-read in SHA1 path)."""
    long_key = b"K" * 127
    hdr = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: "
        + long_key
        + b"\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(hdr)
    await w.drain()
    await _read_http_101(r)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_max_length_sec_websocket_protocol_header_on_ws_port(ircd_hub):
    """Subprotocol list fills subprotocols[256]; strtok_r must not scan past buffer."""
    # 255 chars after "Sec-WebSocket-Protocol: " — fills strncpy(..., 255) slot with trailing NUL
    proto_val = b"x" * 255
    hdr = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Protocol: "
        + proto_val
        + b"\r\n\r\n"
    )
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(hdr)
    await w.drain()
    await _read_http_101(r)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_handshake_duplicate_sec_websocket_key_lines(ircd_hub):
    """Two key headers: parser overwrites; must 101 and not UB."""
    hdr = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(hdr)
    await w.drain()
    await _read_http_101(r)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_handshake_sec_websocket_key_no_space_after_colon(ircd_hub):
    """Tight header spelling (no SP after colon) still matches strncasecmp prefix."""
    hdr = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key:dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(hdr)
    await w.drain()
    await _read_http_101(r)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_handshake_embedded_nul_in_junk_header_line(ircd_hub):
    """Binary NUL inside a line can truncate C line parsing; hub must not crash."""
    hdr = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"X-Fuzz: aa\x00bb\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(hdr)
    await w.drain()
    # strtok_r may stop at embedded NUL before Upgrade; 101 is optional.
    await asyncio.sleep(0.35)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_extended_length_127_masked_junk_high32(ircd_hub):
    """127-encoded length uses only low 32 bits at buf[6..9]; high quad non-zero."""
    r, w = await _raw_ws_connect()
    pl = b"PING :frob\r\n"
    w.write(_masked_ws_frame_127_junk_high32(pl, opcode=0x1))
    await w.drain()
    await asyncio.sleep(0.35)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_two_text_frames_one_tcp_write(ircd_hub):
    """Back-to-back masked text frames in a single write (parse loop)."""
    r, w = await _raw_ws_connect()
    w.write(_masked_text_frame(b"NICK two1\r\n") + _masked_text_frame(b"QUIT :two\r\n"))
    await w.drain()
    await asyncio.sleep(0.45)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_binary_opcode_frame(ircd_hub):
    """Opcode 2 (binary) still feeds IRC line bytes into dbuf."""
    hdr = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Protocol: binary.ircv3.net\r\n"
        b"\r\n"
    )
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(hdr)
    await w.drain()
    await _read_http_101(r)
    w.write(_masked_ws_frame(0x2, b"QUIT :bin\r\n"))
    await w.drain()
    await asyncio.sleep(0.35)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_close_pong_reserved_opcode_skipped(ircd_hub):
    """Control / reserved opcodes with payload are skipped by length (no crash)."""
    r, w = await _raw_ws_connect()
    junk = b"\xff\xfe"
    blob = (
        _masked_ws_frame(0x8, b"", fin=True)  # close, empty
        + _masked_ws_frame(0xA, junk, fin=True)  # pong
        + _masked_ws_frame(0xB, junk, fin=True)  # reserved
        + _masked_text_frame(b"QUIT :ctl\r\n")
    )
    w.write(blob)
    await w.drain()
    await asyncio.sleep(0.45)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_masked_ping_burst_max_125_payload(ircd_hub):
    """Many max-size masked pings in one write (cheap server skip path stress)."""
    r, w = await _raw_ws_connect()
    pl = b"x" * 125
    w.write(b"".join(_masked_ws_frame(0x9, pl) for _ in range(120)))
    await w.drain()
    w.write(_masked_text_frame(b"QUIT :pingstorm\r\n"))
    await w.drain()
    await asyncio.sleep(0.5)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_fragmented_text_fin_then_continuation(ircd_hub):
    """FIN=0 text + FIN continuation: server may not merge; must survive."""
    r, w = await _raw_ws_connect()
    w.write(
        _masked_ws_frame(0x1, b"PART", fin=False)
        + _masked_ws_frame(0x0, b"IAL #x\r\n", fin=True)
    )
    await w.drain()
    await asyncio.sleep(0.4)
    w.write(_masked_text_frame(b"QUIT :frag\r\n"))
    await w.drain()
    await asyncio.sleep(0.3)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()


@pytest.mark.asyncio
async def test_ws_frame_split_across_two_tcp_writes(ircd_hub):
    """Partial frame then remainder: exercises cross-read reassembly (or safe drop)."""
    r, w = await asyncio.open_connection(HOST, WS_PORT)
    w.write(_RAW_HANDSHAKE)
    await w.drain()
    await _read_http_101(r)
    rest = _masked_text_frame(b"QUIT :split2\r\n")
    w.write(rest[:3])
    await w.drain()
    await asyncio.sleep(0.08)
    w.write(rest[3:])
    await w.drain()
    await asyncio.sleep(0.45)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    await _assert_hub_accepts_registration()
