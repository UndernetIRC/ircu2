"""Minimal async IRC WebSocket client for testing ircu2."""

import asyncio
import logging

import websockets

from irc_client import Message, parse_message


class IRCWebSocketClient:
    """Async IRC client over WebSocket for protocol-level testing.

    Mirrors :class:`irc_client.IRCClient` for CAP, registration, tagged
    PINGs, and IRCv3 message-tags so the same scenarios can run over WS.
    """

    def __init__(self, binary: bool = False):
        self._ws = None
        self._buffer: list[Message] = []
        self.nick = None
        self.connected = False
        self.received_messages: list[Message] = []
        self._logger = logging.getLogger("irc_ws_client")
        self.binary = binary

    async def connect(self, url, subprotocols=None, ssl=None):
        if subprotocols is None:
            subprotocols = (
                ["text.ircv3.net"] if not self.binary else ["binary.ircv3.net"]
            )
        kwargs = {"subprotocols": subprotocols}
        if ssl is not None:
            kwargs["ssl"] = ssl
        self._ws = await websockets.connect(url, **kwargs)
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
        # IRCv3 WebSocket: one frame = one IRC line, no trailing CRLF.
        line = line.rstrip("\r\n")
        self._logger.debug(">> %s", line)
        if self.binary:
            await self._ws.send(line.encode("utf-8"))
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
        while self._buffer:
            msg = self._buffer.pop(0)
            if await self._maybe_pong(msg):
                continue
            return msg
        return await self._recv_from_ws(timeout)

    async def _maybe_pong(self, msg: Message) -> bool:
        """Auto-reply to PING (including tag-prefixed ones)."""
        if msg.command != "PING":
            return False
        cookie = msg.params[-1] if msg.params else ""
        await self.send(f"PONG :{cookie}" if cookie else "PONG")
        return True

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

        msg = parse_message(line)
        if await self._maybe_pong(msg):
            return await self._recv_from_ws(timeout)

        self.received_messages.append(msg)
        return msg

    async def register(self, nick: str, username: str, realname: str):
        """Send NICK and USER, wait for end of registration burst."""
        self.nick = nick
        await self.send(f"NICK {nick}")
        await self.send(f"USER {username} 0 * :{realname}")
        msgs = []
        while True:
            msg = await self.recv(timeout=10.0)
            msgs.append(msg)
            if msg.command in ("376", "422"):
                return msgs

    async def negotiate_cap(self, caps: list[str], timeout: float = 5.0) -> list[str]:
        """Negotiate IRC capabilities before registration (same as IRCClient)."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        await self.send("CAP LS 302")
        ls_caps = []
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Timed out waiting for CAP LS reply")
            msg = await self._recv_from_ws(timeout=remaining)
            if msg.command == "CAP" and len(msg.params) >= 3:
                sub = msg.params[1]
                if sub == "LS":
                    ls_caps.extend(msg.params[-1].split())
                    if msg.params[2] != "*":
                        break
            else:
                self._buffer.append(msg)

        available = [c for c in caps if c in ls_caps]
        if not available:
            await self.send("CAP END")
            return []

        await self.send(f"CAP REQ :{' '.join(available)}")

        acked = []
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Timed out waiting for CAP ACK/NAK")
            msg = await self._recv_from_ws(timeout=remaining)
            if msg.command == "CAP" and len(msg.params) >= 3:
                sub = msg.params[1]
                if sub == "ACK":
                    acked = msg.params[-1].strip().split()
                    break
                elif sub == "NAK":
                    break
            else:
                self._buffer.append(msg)

        await self.send("CAP END")
        return acked

    async def wait_for(self, command: str, timeout: float = 5.0) -> Message:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        for i, msg in enumerate(self._buffer):
            if msg.command == command or msg.command.upper() == command.upper():
                self._buffer = self._buffer[:i] + self._buffer[i + 1 :]
                return msg
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError(f"Timed out waiting for {command}")
            msg = await self._recv_from_ws(timeout=remaining)
            if msg.command == command or msg.command.upper() == command.upper():
                return msg
            self._buffer.append(msg)

    async def collect_until(self, command: str, timeout: float = 5.0) -> list[Message]:
        collected = []
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError(f"Timed out waiting for {command}")
            msg = await self.recv(timeout=remaining)
            collected.append(msg)
            if msg.command == command or msg.command.upper() == command.upper():
                return collected

    async def send_and_expect(
        self, line: str, command: str, timeout: float = 5.0
    ) -> Message:
        await self.send(line)
        return await self.wait_for(command, timeout=timeout)
