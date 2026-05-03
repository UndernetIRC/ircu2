"""
Aggressive WebSocket integration / stress tests (hub Docker, port 7000).

Run selectively:
  pytest test_websocket_stress.py -v --timeout=300
  pytest test_websocket_stress.py -m websocket_stress -v --timeout=600
"""

from __future__ import annotations

import asyncio
import random
import string

import pytest

from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient

pytestmark = pytest.mark.websocket_stress

HOST = "127.0.0.1"
NORMAL_PORT = 6667
WS_PORT = 7000
WS_URL = f"ws://{HOST}:{WS_PORT}/"

# Raw RFC6455 opening handshake (same key as tests/test_websocket_protocol_confusion.py)
_WS_RAW_UPGRADE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Protocol: text.ircv3.net\r\n"
    b"\r\n"
)

# Stay under typical ircu line limits for “valid” long lines; oversize test uses more.
MAX_LINE_TRY = 480


async def _drain_background(ws: IRCWebSocketClient, stop: asyncio.Event) -> None:
    """Keep recv queue empty while flooding (handles PING, numerics, etc.)."""
    while not stop.is_set():
        try:
            await ws.recv(timeout=0.25)
        except asyncio.TimeoutError:
            continue
        except (ConnectionError, OSError):
            break


async def _drain_until_idle_tcp(tcp: IRCClient, idle_rounds: int = 3) -> None:
    """Read until several consecutive timeouts (burst traffic drained)."""
    quiet = 0
    while quiet < idle_rounds:
        try:
            await tcp.recv(timeout=0.08)
            quiet = 0
        except asyncio.TimeoutError:
            quiet += 1


async def _drain_until_idle_ws(ws: IRCWebSocketClient, idle_rounds: int = 3) -> None:
    quiet = 0
    while quiet < idle_rounds:
        try:
            await ws.recv(timeout=0.08)
            quiet = 0
        except asyncio.TimeoutError:
            quiet += 1


@pytest.mark.asyncio
async def test_ws_stress_parallel_clients(ircd_hub):
    """Many WebSocket clients register, join one channel, chatter, quit."""

    async def one_client(idx: int) -> None:
        nick = f"wss{idx:02d}{random.randint(0, 9999)}"
        c = IRCWebSocketClient()
        await c.connect(WS_URL, subprotocols=["text.ircv3.net"])
        try:
            await c.register(nick, "t", "Stress")
            await c.send("JOIN #wspar")
            for k in range(15):
                await c.send(f"PRIVMSG #wspar :{nick} burst {k}")
            await c.send("QUIT :stress done")
        finally:
            await c.disconnect()

    n = 10
    await asyncio.wait_for(asyncio.gather(*(one_client(i) for i in range(n))), timeout=120.0)


@pytest.mark.asyncio
async def test_ws_stress_rapid_privmsg_with_background_drain(ircd_hub):
    """High rate of sends while a task drains incoming (PING + numerics)."""
    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register("wsflood", "t", "Flood")
    await ws.send("JOIN #wsflood")

    stop = asyncio.Event()
    drainer = asyncio.create_task(_drain_background(ws, stop))
    try:
        for i in range(250):
            await ws.send(f"PRIVMSG #wsflood :n{i} " + "x" * 40)
            if i % 50 == 0:
                await asyncio.sleep(0)  # yield for drainer / server
    finally:
        stop.set()
        drainer.cancel()
        try:
            await drainer
        except asyncio.CancelledError:
            pass
        await ws.send("QUIT :stress")
        await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_long_valid_utf8_privmsg(ircd_hub):
    """Long trailing text (valid UTF-8) through text-mode WebSocket."""
    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register("wslong", "t", "Long")
    await ws.send("JOIN #wslong")
    payload = "é" * 120 + "Ω" * 120 + "字" * 80  # 2- and 3-byte UTF-8
    await ws.send(f"PRIVMSG #wslong :{payload}")
    # Consume a few replies without requiring PRIVMSG echo (depends on echo-message).
    for _ in range(20):
        try:
            await ws.recv(timeout=0.5)
        except asyncio.TimeoutError:
            break
    await ws.send("QUIT :stress")
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_tcp_and_ws_cross_talk(ircd_hub):
    """TCP user and WebSocket user stress the same channel (bursts + drain, no dual recv)."""
    rid = random.randint(0, 999_999)
    tcp = IRCClient()
    await tcp.connect(HOST, NORMAL_PORT)
    await tcp.register(f"tx{rid}", "t", "TCP")

    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register(f"wx{rid}", "t", "WS")

    await tcp.send("JOIN #xcross")
    await ws.send("JOIN #xcross")
    await asyncio.sleep(0.5)
    await _drain_until_idle_tcp(tcp)
    await _drain_until_idle_ws(ws)

    for i in range(35):
        await tcp.send(f"PRIVMSG #xcross :tcp-{i}")
    await _drain_until_idle_tcp(tcp)

    for i in range(35):
        await ws.send(f"PRIVMSG #xcross :ws-{i}")
    await _drain_until_idle_ws(ws)

    await tcp.send("QUIT :done")
    await ws.send("QUIT :done")
    await tcp.disconnect()
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_join_part_hammer(ircd_hub):
    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register("wsjp", "t", "JP")
    for _ in range(40):
        await ws.send("JOIN #jphammer")
        await ws.send("PART #jphammer :x")
    await ws.send("QUIT :stress")
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_binary_burst(ircd_hub):
    """Binary subprotocol: many frames with ASCII IRC lines as octets."""
    ws = IRCWebSocketClient(binary=True)
    await ws.connect(WS_URL, subprotocols=["binary.ircv3.net"])
    await ws.register("wsbin", "t", "Bin")
    await ws.send("JOIN #wsbin")
    for i in range(100):
        line = f"PRIVMSG #wsbin :binary burst {i}\r\n".encode("ascii")
        await ws.send_bytes(line)
    await ws.send("QUIT :stress")
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_binary_chunked_line(ircd_hub):
    """One logical IRC line split across two binary WebSocket frames (server reassembly)."""
    ws = IRCWebSocketClient(binary=True)
    await ws.connect(WS_URL, subprotocols=["binary.ircv3.net"])
    await ws.register("wschunk", "t", "Chunk")
    await ws.send("JOIN #chunk")
    part1 = b"PRIVMSG #chunk :hello "
    part2 = b"world\r\n"
    await ws.send_bytes(part1)
    await ws.send_bytes(part2)
    await asyncio.sleep(0.2)
    await ws.send("QUIT :stress")
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_almost_max_line(ircd_hub):
    """Single PRIVMSG line as long as the IRCd is likely to accept (may get 417 etc.)."""
    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register("wsmax", "t", "Max")
    await ws.send("JOIN #maxline")
    pad = "".join(random.choices(string.ascii_letters + string.digits, k=MAX_LINE_TRY))
    await ws.send(f"PRIVMSG #maxline :{pad}")
    for _ in range(30):
        try:
            await ws.recv(timeout=1.0)
        except asyncio.TimeoutError:
            break
    await ws.send("QUIT :stress")
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_oversize_line_survival(ircd_hub):
    """Oversized line: connection should survive (server may ERR or drop)."""
    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register("wsov", "t", "Ov")
    huge = "X" * 8000
    await ws.send(f"PRIVMSG nobody :{huge}")
    try:
        for _ in range(15):
            await ws.recv(timeout=0.5)
    except asyncio.TimeoutError:
        pass
    assert ws.connected
    await ws.send("QUIT :stress")
    await ws.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_giant_single_ws_frame_many_commands(ircd_hub):
    """One WebSocket text frame with newlines is unusual; server should not crash."""
    ws = IRCWebSocketClient()
    await ws.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws.register("wsbatch", "t", "Batch")
    # Single WS text message; payload contains many CRLF — exercises frame vs line parsing.
    batch = "\r\n".join(f"PRIVMSG #nobody :embed-{i}" for i in range(20)) + "\r\n"
    await ws._ws.send(batch)
    await asyncio.sleep(0.3)
    await ws.send("QUIT :stress")
    await ws.disconnect()


async def _tcp_registration_sanity() -> None:
    nick = f"churn{random.randint(0, 999_999)}"
    c = IRCClient()
    await c.connect(HOST, NORMAL_PORT)
    try:
        await c.register(nick, "t", "churn-check")
        await c.send("QUIT :ok")
    finally:
        await c.disconnect()


@pytest.mark.asyncio
async def test_ws_stress_raw_http_upgrade_churn(ircd_hub):
    """Many HTTP 101 upgrades on the WS port then FIN (no websockets.py client)."""
    for _ in range(24):
        r, w = await asyncio.open_connection(HOST, WS_PORT)
        try:
            w.write(_WS_RAW_UPGRADE)
            await w.drain()
            await asyncio.wait_for(r.read(4096), timeout=8.0)
        finally:
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=4.0)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                pass
        await asyncio.sleep(0.02)
    await _tcp_registration_sanity()


@pytest.mark.asyncio
async def test_ws_stress_tcp_open_close_before_handshake(ircd_hub):
    """Open TCP to WS port and drop without sending bytes (listener churn)."""
    for _ in range(35):
        _r, w = await asyncio.open_connection(HOST, WS_PORT)
        w.close()
        try:
            await w.wait_closed()
        except (ConnectionError, OSError):
            pass
    await _tcp_registration_sanity()


@pytest.mark.asyncio
async def test_ws_stress_partial_handshake_one_line_then_close(ircd_hub):
    """Single HTTP line then FIN — handshake buffer partial paths."""
    for _ in range(18):
        _r, w = await asyncio.open_connection(HOST, WS_PORT)
        w.write(b"GET / HTTP/1.1\r\n")
        await w.drain()
        w.close()
        try:
            await w.wait_closed()
        except (ConnectionError, OSError):
            pass
    await _tcp_registration_sanity()
