"""Minimal async IRC WebSocket client for testing ircu2."""

import asyncio
import logging
import websockets
from collections import namedtuple

Message = namedtuple("Message", ["prefix", "command", "params"])

def parse_message(line: str) -> Message:
    prefix = None
    trailing = None
    if line.startswith(":"):
        prefix, line = line[1:].split(" ", 1)
    if " :" in line:
        line, trailing = line.split(" :", 1)
    parts = line.split()
    command = parts[0] if parts else ""
    params = parts[1:]
    if trailing is not None:
        params.append(trailing)
    return Message(prefix=prefix, command=command, params=params)

class IRCWebSocketClient:
    """Async IRC client over WebSocket for protocol-level testing."""
    def __init__(self, binary: bool = False):
        self._ws = None
        self._buffer = []
        self.nick = None
        self.connected = False
        self.received_messages = []
        self._logger = logging.getLogger("irc_ws_client")
        self.binary = binary

    async def connect(self, url, subprotocols=None):
        if subprotocols is None:
            subprotocols = ["text.ircv3.net"] if not self.binary else ["binary.ircv3.net"]
        self._ws = await websockets.connect(url, subprotocols=subprotocols)
        self.connected = True
        self._logger.debug("Connected to %s", url)

    async def disconnect(self):
        if self._ws:
            await self._ws.close()
        self.connected = False
        self._logger.debug("Disconnected")

    async def send(self, line: str):
        if not self._ws:
            raise ConnectionError("Not connected")
        self._logger.debug(">> %s", line)
        if self.binary:
            await self._ws.send((line).encode("utf-8"))
        else:
            await self._ws.send(line)

    async def send_bytes(self, data: bytes):
        """Send one binary WebSocket message (binary subprotocol only)."""
        if not self._ws:
            raise ConnectionError("Not connected")
        if not self.binary:
            raise ValueError("send_bytes requires binary WebSocket client")
        self._logger.debug(">> %d bytes", len(data))
        await self._ws.send(data)

    async def recv(self, timeout: float = 5.0) -> Message:
        if self._buffer:
            return self._buffer.pop(0)
        return await self._recv_from_ws(timeout)

    async def register(self, nick: str, username: str, realname: str):
        """Send NICK and USER, wait for end of registration burst.

        Consumes all registration messages through RPL_ENDOFMOTD (376)
        or ERR_NOMOTD (422). Returns the collected messages.
        """
        self.nick = nick
        await self.send(f"NICK {nick}")
        await self.send(f"USER {username} 0 * :{realname}")
        msgs = []
        while True:
            msg = await self.recv(timeout=10.0)
            msgs.append(msg)
            if msg.command in ("376", "422"):  # End of MOTD or no MOTD
                return msgs

    async def _recv_from_ws(self, timeout: float = 5.0) -> Message:
        if not self._ws:
            raise ConnectionError("Not connected")
        # Raw Text/Binary frame payload octets. For text mode we strict-decode UTF-8
        # here so tests fail loudly if the server violates RFC 6455.
        raw_b = await asyncio.wait_for(self._ws.recv(decode=False), timeout=timeout)
        if not isinstance(raw_b, bytes):
            raise ConnectionError("Expected frame payload as bytes")
        if self.binary:
            line = raw_b.decode("utf-8", errors="replace").strip()
        else:
            try:
                line = raw_b.decode("utf-8", "strict").strip()
            except UnicodeDecodeError as e:
                raise ConnectionError(
                    f"WebSocket text frame is not valid UTF-8 (RFC 6455): {e}"
                ) from e
        self._logger.debug("<< %s", line)
        # Auto-respond to PING
        if line.startswith("PING"):
            pong = "PONG" + line[4:]
            await self.send(pong)
            return await self._recv_from_ws(timeout)
        msg = parse_message(line)
        self.received_messages.append(msg)
        return msg

    async def wait_for(self, command: str, timeout: float = 5.0) -> Message:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        for i, msg in enumerate(self._buffer):
            if msg.command == command or msg.command.upper() == command.upper():
                self._buffer = self._buffer[:i] + self._buffer[i + 1:]
                return msg
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError(f"Timed out waiting for {command}")
            msg = await self._recv_from_ws(timeout=remaining)
            if msg.command == command or msg.command.upper() == command.upper():
                return msg
            self._buffer.append(msg)

    async def send_and_expect(self, line: str, command: str, timeout: float = 5.0) -> Message:
        await self.send(line)
        return await self.wait_for(command, timeout=timeout)
