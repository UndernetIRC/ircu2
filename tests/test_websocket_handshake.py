import pytest
import asyncio
import websockets
from irc_ws_client import IRCWebSocketClient


# Ports must match your ircd config and docker-compose.yml
NORMAL_PORT = 6667
WS_PORT = 7000
HOST = "127.0.0.1"
WS_URL = f"ws://{HOST}:{WS_PORT}/"

from irc_client import IRCClient, parse_message

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

