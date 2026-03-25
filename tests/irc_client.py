"""Minimal async IRC client for testing ircu2."""

import asyncio
import logging
from collections import namedtuple

Message = namedtuple("Message", ["prefix", "command", "params"])


def parse_message(line: str) -> Message:
    """Parse a raw IRC message into a Message namedtuple.

    Follows RFC 1459 message format:
      [':' prefix SPACE] command {SPACE param} [SPACE ':' trailing]
    """
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


class IRCClient:
    """Async IRC client for protocol-level testing.

    Provides raw access to IRC protocol with helpers for common operations
    like registration, CAP negotiation, and waiting for specific responses.
    """

    def __init__(self):
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._buffer: list[Message] = []
        self.nick: str | None = None
        self.connected: bool = False
        self.received_messages: list[Message] = []
        self._logger = logging.getLogger("irc_client")

    async def connect(self, host: str, port: int):
        """Open a TCP connection to an IRC server."""
        self._reader, self._writer = await asyncio.open_connection(host, port)
        self.connected = True
        self._logger.debug("Connected to %s:%d", host, port)

    async def connect_tls(self, host: str, port: int, ssl_context=None):
        """Open a TLS connection to an IRC server."""
        raise NotImplementedError("TLS support not yet implemented")

    async def disconnect(self):
        """Close the connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self.connected = False
        self._logger.debug("Disconnected")

    async def send(self, line: str):
        """Send a raw IRC line (appends CRLF)."""
        if not self._writer:
            raise ConnectionError("Not connected")
        self._logger.debug(">> %s", line)
        self._writer.write((line + "\r\n").encode("utf-8"))
        await self._writer.drain()

    async def recv(self, timeout: float = 5.0) -> Message:
        """Read and parse the next IRC message.

        If there are buffered messages (from wait_for stashing), return
        the oldest one first. Otherwise read from the stream.
        """
        if self._buffer:
            return self._buffer.pop(0)
        return await self._recv_from_stream(timeout)

    async def _recv_from_stream(self, timeout: float = 5.0) -> Message:
        """Read one line from the stream and parse it."""
        if not self._reader:
            raise ConnectionError("Not connected")
        raw = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        if not raw:
            raise ConnectionError("Connection closed by server")
        line = raw.decode("utf-8", errors="replace").strip()
        self._logger.debug("<< %s", line)

        # Auto-respond to PING
        if line.startswith("PING"):
            pong = "PONG" + line[4:]
            await self.send(pong)
            return await self._recv_from_stream(timeout)

        msg = parse_message(line)
        self.received_messages.append(msg)
        return msg

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

    async def negotiate_cap(self, caps: list[str]) -> list[str]:
        """Negotiate IRC capabilities before registration.

        Sends CAP LS 302, requests the given caps, waits for ACK,
        then sends CAP END. Returns list of acknowledged capabilities.
        """
        await self.send("CAP LS 302")
        # Collect CAP LS response(s)
        ls_caps = []
        while True:
            msg = await self.recv(timeout=5.0)
            if msg.command == "CAP" and len(msg.params) >= 3:
                sub = msg.params[1]
                if sub == "LS":
                    # params might be [nick, "LS", "*", "cap1 cap2"] for multi-line
                    # or [nick, "LS", "cap1 cap2"] for single line
                    cap_str = msg.params[-1]
                    ls_caps.extend(cap_str.split())
                    if msg.params[2] != "*":
                        break  # No more LS lines
            else:
                self._buffer.append(msg)

        # Request the caps the server supports
        available = [c for c in caps if c in ls_caps]
        if not available:
            await self.send("CAP END")
            return []

        await self.send(f"CAP REQ :{' '.join(available)}")

        # Wait for ACK or NAK
        acked = []
        while True:
            msg = await self.recv(timeout=5.0)
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

    async def authenticate_sasl(self, mechanism: str, credentials: str):
        """Authenticate via SASL."""
        raise NotImplementedError("SASL support not yet implemented")

    async def wait_for(self, command: str, timeout: float = 5.0) -> Message:
        """Consume messages until one matching command is found.

        Non-matching messages are stashed in the buffer for later retrieval.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        # First check buffered messages
        for i, msg in enumerate(self._buffer):
            if msg.command == command or msg.command.upper() == command.upper():
                self._buffer = self._buffer[:i] + self._buffer[i + 1:]
                return msg
        # Then read from stream
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError(
                    f"Timed out waiting for {command}"
                )
            msg = await self._recv_from_stream(timeout=remaining)
            if msg.command == command or msg.command.upper() == command.upper():
                return msg
            self._buffer.append(msg)

    async def collect_until(self, command: str, timeout: float = 5.0) -> list[Message]:
        """Collect all messages until one matching command is seen.

        Returns the full list including the terminator message.
        """
        collected = []
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError(
                    f"Timed out waiting for {command}"
                )
            msg = await self.recv(timeout=remaining)
            collected.append(msg)
            if msg.command == command or msg.command.upper() == command.upper():
                return collected

    async def send_and_expect(self, line: str, command: str, timeout: float = 5.0) -> Message:
        """Send a line and wait for a specific response command."""
        await self.send(line)
        return await self.wait_for(command, timeout=timeout)
