"""Minimal async IRC client for testing ircu2."""

import asyncio
import logging
import ssl
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


def is_server_msg(msg: Message) -> bool:
    """True if a Message originates from a server, not a user.

    Server messages have a plain server-name prefix (no user!ident@host),
    e.g. the "on 1 ca 2(4) ft 10(10)" target-throttle NOTICE sent after
    registration. Those must not be mistaken for delivered messages.
    """
    return msg.prefix is None or "!" not in msg.prefix


def parse_mode_string(modestring: str) -> dict[str, str]:
    """Parse a modestring like "+xR-c" into {char: sign} pairs."""
    result = {}
    sign = "+"
    for ch in modestring:
        if ch in "+-":
            sign = ch
        else:
            result[ch] = sign
    return result


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

    async def connect_tls(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None = None,
    ):
        """Open a TLS connection to an IRC server."""
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        self._reader, self._writer = await asyncio.open_connection(
            host, port, ssl=ssl_context
        )
        self.connected = True
        self._logger.debug("Connected with TLS to %s:%d", host, port)

    async def read_raw_line(self, timeout: float = 5.0) -> str:
        """Read a single raw line without IRC parsing or PING handling."""
        if not self._reader:
            raise ConnectionError("Not connected")
        raw = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        if not raw:
            raise ConnectionError("Connection closed")
        line = raw.decode("utf-8", errors="replace").strip()
        self._logger.debug("<< %s", line)
        return line

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

    async def send_raw(self, line: bytes):
        """Send one IRC line as exact octets, then CRLF.

        Use this to emit byte sequences that are not valid UTF-8 (e.g. a lone
        0xFF in a channel name). ``send()`` always UTF-8-encodes its string.
        """
        if not self._writer:
            raise ConnectionError("Not connected")
        if b"\r" in line or b"\n" in line:
            raise ValueError("line must not contain CR or LF")
        self._logger.debug(">> %r", line)
        self._writer.write(line + b"\r\n")
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

    async def negotiate_cap(self, caps: list[str], timeout: float = 5.0) -> list[str]:
        """Negotiate IRC capabilities before registration.

        Sends CAP LS 302, requests the given caps, waits for ACK,
        then sends CAP END. Returns list of acknowledged capabilities.

        Non-CAP messages (e.g. "NOTICE AUTH" ident/DNS progress lines) are
        stashed in the buffer for later retrieval. They must be read from
        the stream, never via recv(): recv() pops the buffer first, so a
        stashed message would be popped and re-stashed forever without
        ever reading the socket again (and without yielding to the event
        loop, so no timeout could fire).
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        await self.send("CAP LS 302")
        # Collect CAP LS response(s)
        ls_caps = []
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Timed out waiting for CAP LS reply")
            msg = await self._recv_from_stream(timeout=remaining)
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
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Timed out waiting for CAP ACK/NAK")
            msg = await self._recv_from_stream(timeout=remaining)
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

    async def wait_for_user_msg(self, command: str, timeout: float = 5.0) -> Message:
        """Wait for a PRIVMSG/NOTICE/etc that comes from a user, skipping server ones."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError(f"no user-originated {command}")
            msg = await self.wait_for(command, timeout=remaining)
            if not is_server_msg(msg):
                return msg

    async def wait_for_message_with_text(
        self, command: str, text: str, timeout: float = 5.0
    ) -> Message:
        """Wait for a message of the given command whose last param equals text.

        Used when the expected message is itself server-prefixed (e.g. a
        server-sourced NOTICE under an IsServer(source) exemption), so the
        is_server_msg-based filter in wait_for_user_msg can't tell it apart
        from unrelated server-injected messages like the post-registration
        throttle NOTICE.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError(f"no {command} with text {text!r}")
            msg = await self.wait_for(command, timeout=remaining)
            if msg.params[-1] == text:
                return msg

    async def assert_no_message(self, command: str = "PRIVMSG", timeout: float = 2.0):
        """Assert that no message of the given command arrives within timeout.

        Numeric replies (e.g. "477") are always server-prefixed, so they're
        checked directly. PRIVMSG/NOTICE/INVITE are checked via
        wait_for_user_msg() to ignore unrelated server-injected messages
        (e.g. the post-registration target-throttle NOTICE) -- using the
        server-vs-user filter for a numeric would make this vacuously pass,
        since every numeric reply IS server-originated.
        """
        try:
            if command.isdigit():
                msg = await self.wait_for(command, timeout=timeout)
            else:
                msg = await self.wait_for_user_msg(command, timeout=timeout)
        except asyncio.TimeoutError:
            return
        raise AssertionError(f"Unexpected {command} delivered: {msg}")

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

    async def set_umode(self, modes: str, nick: str | None = None) -> Message:
        """Send MODE <nick> <modes>, wait for the echo, and verify it applied.

        `modes` is a modestring like "+R" or "-x" (multiple flags/signs
        are fine too, e.g. "+x-c"). The server only sends a MODE reply
        when the requested modes actually change something. Setting a
        mode that's already set (or clearing one already clear) is a
        silent no-op with no reply at all, so only call this when a real
        change is expected.
        """
        nick = nick or self.nick
        await self.send(f"MODE {nick} {modes}")
        msg = await self.wait_for("MODE")
        applied = parse_mode_string(msg.params[-1])
        requested = parse_mode_string(modes)
        for ch, sign in requested.items():
            if applied.get(ch) != sign:
                raise AssertionError(
                    f"MODE {modes} not applied as expected: requested "
                    f"{sign}{ch}, got {msg.params[-1]!r}"
                )
        return msg

    async def silence(self, pattern: str, timeout: float = 5.0) -> Message:
        """Send SILENCE +<pattern>, waiting for the server's echo.

        Only call this for a genuinely new entry: if the resulting mask is
        already on the silence list, the server sends no SILENCE reply at all,
        and this will hang until timeout.
        """
        await self.send(f"SILENCE +{pattern}")
        return await self.wait_for("SILENCE", timeout=timeout)

    async def chan_modes(self, channel: str, timeout: float = 5.0) -> str:
        """Return a channel's mode string (e.g. "+ntu") from RPL_CHANNELMODEIS."""
        msg = await self.send_and_expect(f"MODE {channel}", "324", timeout=timeout)
        return next((p for p in msg.params if p.startswith("+")), "")
