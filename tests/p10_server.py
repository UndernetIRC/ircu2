"""Lightweight P10 fake server for testing ircu2 S2S behavior.

Connects to an ircd as a server, completes the P10 handshake (PASS,
SERVER, burst, EB/EA), and exposes methods to send S2S protocol
messages like OPMODE and ACCOUNT.

Usage:
    server = P10Server("services.test.net", numeric=4, password="testpass")
    await server.connect("127.0.0.1", 4400)
    await server.handshake()
    # Now send S2S commands:
    await server.send_opmode(user_numnick, "+x")
    await server.send_account(user_numnick, "AccountName")
    await server.disconnect()
"""

import asyncio
import logging
import time

logger = logging.getLogger("p10_server")

# P10 base64 character set
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]"
_B64_VAL = {c: i for i, c in enumerate(_B64)}


def int_to_b64(value: int, width: int) -> str:
    """Encode an integer as a P10 base64 string of fixed width."""
    chars = []
    for _ in range(width):
        chars.append(_B64[value & 63])
        value >>= 6
    return "".join(reversed(chars))


def b64_to_int(s: str) -> int:
    """Decode a P10 base64 string to an integer."""
    result = 0
    for c in s:
        result = (result << 6) | _B64_VAL[c]
    return result


def server_numeric(num: int) -> str:
    """Encode a server numeric as 2-char P10 base64."""
    return int_to_b64(num, 2)


def client_numnick(server_num: int, client_num: int) -> str:
    """Encode a full SSCCC numnick (2-char server + 3-char client)."""
    return server_numeric(server_num) + int_to_b64(client_num, 3)


def parse_numnick(numnick: str) -> tuple[int, int]:
    """Parse a 5-char numnick into (server_numeric, client_numeric)."""
    return b64_to_int(numnick[:2]), b64_to_int(numnick[2:])


class P10Server:
    """A fake IRC server speaking the P10 protocol.

    Connects to an ircd on its server port, performs the full P10
    handshake, then allows sending arbitrary S2S messages.
    """

    def __init__(
        self,
        name: str = "services.test.net",
        numeric: int = 4,
        password: str = "testpass",
        max_clients: int = 64,
        description: str = "Test Services",
    ):
        self.name = name
        self.numeric = numeric
        self.password = password
        self.max_clients = max_clients
        self.description = description

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self.burst_complete = False

        # Our server's base64 numeric prefix (2 chars)
        self._num = server_numeric(numeric)
        # Numnick mask: server numeric (2) + max clients (3)
        self._numnick_mask = self._num + int_to_b64(max_clients, 3)

        # Users we've seen, keyed by nick (lowercase)
        self.users: dict[str, dict] = {}
        # All raw messages received
        self.received: list[str] = []

    async def connect(self, host: str, port: int):
        """Open a TCP connection to the ircd's server port."""
        self._reader, self._writer = await asyncio.open_connection(host, port)
        self.connected = True
        logger.debug("Connected to %s:%d", host, port)

    async def disconnect(self):
        """Send SQUIT and close the connection."""
        if self._writer:
            try:
                await self._send(f"{self._num} SQ {self.name} 0 :Test done")
            except Exception:
                pass
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self.connected = False

    async def _send(self, line: str):
        """Send a raw line to the ircd."""
        if not self._writer:
            raise ConnectionError("Not connected")
        logger.debug(">> %s", line)
        self._writer.write((line + "\r\n").encode("utf-8"))
        await self._writer.drain()

    async def _recv_raw(self, timeout: float = 10.0) -> str:
        """Read one raw line from the ircd."""
        if not self._reader:
            raise ConnectionError("Not connected")
        raw = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        if not raw:
            raise ConnectionError("Connection closed by server")
        line = raw.decode("utf-8", errors="replace").strip()
        logger.debug("<< %s", line)
        self.received.append(line)
        return line

    async def _recv(self, timeout: float = 10.0) -> str:
        """Read one line, auto-handling PINGs and parsing NICKs.

        Returns the line. PINGs are answered automatically and skipped
        (the next line is returned instead).
        """
        while True:
            line = await self._recv_raw(timeout=timeout)
            tokens = line.split()

            # Handle PING in both forms:
            #   PING :<origin>                    (unprefixed, pre-handshake)
            #   <prefix> G !<cookie> <target> ... (token form, post-handshake)
            if tokens[0] == "PING":
                origin = tokens[1].lstrip(":")
                await self._send(f"{self._num} Z {self._num} :{origin}")
                continue
            if len(tokens) >= 2 and tokens[1] == "G":
                # PONG format: <our_num> Z <our_num> :<cookie>
                # The cookie is the second token (after G), strip the !
                cookie = tokens[2].lstrip("!") if len(tokens) > 2 else tokens[-1]
                await self._send(f"{self._num} Z {self._num} :{cookie}")
                continue

            # Parse NICK (N) messages to track users
            if len(tokens) >= 2 and tokens[1] == "N":
                self._parse_nick(line)

            return line

    def _get_token(self, line: str) -> str | None:
        """Extract the P10 token (second space-delimited word) from a line."""
        parts = line.split(" ", 2)
        return parts[1] if len(parts) >= 2 else None

    async def handshake(self, timeout: float = 15.0):
        """Perform the full P10 server handshake.

        Sends PASS + SERVER, reads the hub's PASS + SERVER + burst,
        sends our EB, waits for EA, sends EA.
        """
        now = int(time.time())

        # Send our credentials
        await self._send(f"PASS :{self.password}")
        await self._send(
            f"SERVER {self.name} 1 {now} {now} J10 {self._numnick_mask} "
            f"+s :{self.description}"
        )

        # Read hub's burst until we see EB (end of burst)
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for end of burst")
            line = await self._recv(timeout=remaining)
            tok = self._get_token(line)
            if tok == "EB" or line == "EB":
                break

        # Send our (empty) burst + end of burst
        await self._send(f"{self._num} EB")

        # Wait for EA (end of burst ack)
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for EA")
            line = await self._recv(timeout=remaining)
            tok = self._get_token(line)
            if tok == "EA" or line == "EA":
                break

        # Send our EA
        await self._send(f"{self._num} EA")
        self.burst_complete = True
        logger.info("P10 handshake complete, connected as %s (%s)", self.name, self._num)

    def _parse_nick(self, line: str):
        """Parse a P10 N (NICK) message and store user info.

        Format: <server> N <nick> <hop> <ts> <user> <host> [+modes] [<b64ip>] <numnick> :<realname>
        """
        if " :" in line:
            head, realname = line.rsplit(" :", 1)
        else:
            head = line
            realname = ""

        parts = head.split()
        if len(parts) < 6:
            return

        nick = parts[2]
        username = parts[5] if len(parts) > 5 else "unknown"
        host = parts[6] if len(parts) > 6 else "unknown"

        # The numnick is the last token in head (before the :realname)
        numnick = parts[-1]

        # Detect modes - look for a token starting with +
        modes = ""
        for p in parts[7:-1]:
            if p.startswith("+"):
                modes = p
                break

        self.users[nick.lower()] = {
            "nick": nick,
            "numnick": numnick,
            "username": username,
            "host": host,
            "modes": modes,
            "realname": realname,
        }

    def get_user_numnick(self, nick: str) -> str | None:
        """Look up a user's 5-char numnick by their nick."""
        info = self.users.get(nick.lower())
        return info["numnick"] if info else None

    async def send_opmode(self, target_numnick: str, mode: str):
        """Send an OPMODE for a user mode change.

        Format: <our_numeric> OM <target_numnick> <mode>
        """
        await self._send(f"{self._num} OM {target_numnick} {mode}")

    async def send_account(self, target_numnick: str, account: str,
                           acc_id: int | None = None, acc_flags: int | None = None):
        """Send an ACCOUNT message to set a user's account.

        Format: <our_numeric> AC <target_numnick> <account> [<acc_id> [<acc_flags>]]
        """
        parts = f"{self._num} AC {target_numnick} {account}"
        if acc_id is not None:
            parts += f" {acc_id}"
            if acc_flags is not None:
                parts += f" {acc_flags}"
        await self._send(parts)

    async def wait_for_user(self, nick: str, timeout: float = 5.0) -> str:
        """Wait until a user with the given nick appears, return their numnick.

        Reads incoming messages (handling PINGs and NICKs) until the
        user is found or timeout expires.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            numnick = self.get_user_numnick(nick)
            if numnick:
                return numnick
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"User {nick!r} not seen. Known: {list(self.users.keys())}"
                )
            try:
                await self._recv(timeout=min(remaining, 1.0))
            except asyncio.TimeoutError:
                continue

    async def recv_until(self, token: str, timeout: float = 5.0) -> list[str]:
        """Read lines until we see one with the given P10 token."""
        collected = []
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for {token}")
            line = await self._recv(timeout=remaining)
            collected.append(line)
            tok = self._get_token(line)
            if tok == token or line.split()[0] == token:
                return collected

    async def drain_messages(self, timeout: float = 0.5):
        """Read and process any pending messages (handles PINGs, tracks NICKs)."""
        while True:
            try:
                await self._recv(timeout=timeout)
            except (asyncio.TimeoutError, TimeoutError):
                break
