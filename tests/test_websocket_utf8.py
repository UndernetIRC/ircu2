import pytest
import asyncio

from irc_ws_client import IRCWebSocketClient
from irc_client import IRCClient

NORMAL_PORT = 6667
WS_PORT = 7000
HOST = "127.0.0.1"
WS_URL = f"ws://{HOST}:{WS_PORT}/"

# Channel name octets on the TCP wire: lone 0xFF is ill-formed UTF-8.
# (``send()`` would UTF-8-encode U+00FF as C3 BF; we need the raw byte FF.)
INVALID_UTF8_CHAN_LINE = b"JOIN #test\xffchan"


@pytest.mark.asyncio
async def test_websocket_text_never_illformed_utf8_after_bad_channel_octets(make_client):
    """IRC channel name uses invalid UTF-8 octets on plain TCP; WebSocket text must stay UTF-8.

    ``send_raw`` puts a lone 0xFF in the JOIN line (ill-formed UTF-8 as a byte
    sequence). ``send()`` would have UTF-8-encoded U+00FF as two bytes instead.

    RFC 6455: Text frames must be UTF-8. :class:`IRCWebSocketClient` reads each
    frame with     ``recv(decode=False)`` and decodes the payload with
    ``bytes.decode("utf-8", "strict")``, so every line proves the server sent
    well-formed UTF-8 on the wire—not only that WHOIS ended.

    Reaching RPL_ENDOFWHOIS (318) without :exc:`UnicodeDecodeError` /
    :exc:`ConnectionError` from that path is the integration assertion.
    """
    client = IRCClient()
    await client.connect(HOST, NORMAL_PORT)
    await client.register("normal", "testuser", "Test User")

    ws_client = IRCWebSocketClient()
    await ws_client.connect(WS_URL, subprotocols=["text.ircv3.net"])
    await ws_client.register("websocket", "testuser", "WebSocket UTF8")

    try:
        await client.send_raw(INVALID_UTF8_CHAN_LINE)
        await client.wait_for("366")

        await ws_client.send("WHOIS normal")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + 10.0
        saw_endofwhois = False
        while loop.time() < deadline:
            try:
                # recv() strict-UTF-8-decodes raw text frame bytes in IRCWebSocketClient
                msg = await ws_client.recv(timeout=0.5)
            except asyncio.TimeoutError:
                break
            if msg.command == "318":
                saw_endofwhois = True
                break

        assert saw_endofwhois, (
            "expected WHOIS to complete (318); each prior recv() already strict-UTF-8–decoded "
            "the frame payload in IRCWebSocketClient._recv_from_ws"
        )

    finally:
        for c in (client, ws_client):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
