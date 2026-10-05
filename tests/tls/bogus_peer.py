"""Misbehaving TLS peers for edge-case testing of ircd's TLS handshake.

Both halves drive OpenSSL through ``ssl.MemoryBIO`` instead of a socket, so
the test -- not the TLS library -- decides which bytes reach the wire and
when.  That is what makes it possible to leave the server parked in exactly
one handshake state (waiting to read, waiting to write, mid-record, ...) and
observe what it does there.

``BogusTLSClient`` connects *to* ircd (client or server TLS port).
``BogusTLSServer`` is the server half; ``SidecarBogusServer`` runs it in a
container on the docker test network (the host firewall may not let
containers reach the host) so ircd can be made to connect *out* to it with
``CONNECT bogus.test.net <port>`` -- see the Connect block in
tests/docker/ircd-tls-hub.conf.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass, field

from tls_certs import cert_path, key_path


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------


async def _open_socket(host: str, port: int, *, rcvbuf: int | None = None):
    """asyncio streams over a socket we configured before connecting."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf is not None:
        # Must be set before connect() so the advertised window is small too.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(sock, (host, port))
    reader, writer = await asyncio.open_connection(sock=sock)
    return reader, writer


async def wait_for_eof(reader: asyncio.StreamReader, timeout: float) -> tuple[bytes, float]:
    """Read until EOF (or timeout).  Returns (bytes received, seconds waited)."""
    start = time.monotonic()
    chunks = []
    try:
        while True:
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                raise asyncio.TimeoutError
            data = await asyncio.wait_for(reader.read(65536), remaining)
            if not data:
                break
            chunks.append(data)
    except asyncio.TimeoutError:
        return b"".join(chunks), -1.0
    except (ConnectionResetError, BrokenPipeError):
        pass
    return b"".join(chunks), time.monotonic() - start


# ---------------------------------------------------------------------------
# Bogus client
# ---------------------------------------------------------------------------


@dataclass
class BogusTLSClient:
    host: str
    port: int
    rcvbuf: int | None = None
    cert: str | None = None  # client certificate name from tests/docker/certs
    reader: asyncio.StreamReader = field(init=False, default=None)
    writer: asyncio.StreamWriter = field(init=False, default=None)
    incoming: ssl.MemoryBIO = field(init=False, default=None)
    outgoing: ssl.MemoryBIO = field(init=False, default=None)
    tls: ssl.SSLObject = field(init=False, default=None)

    async def connect(self) -> None:
        self.reader, self.writer = await _open_socket(
            self.host, self.port, rcvbuf=self.rcvbuf
        )

    def start_tls(self) -> bytes:
        """Create the client-side TLS state and return the ClientHello bytes
        (not yet sent)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if self.cert:
            ctx.load_cert_chain(cert_path(self.cert), key_path(self.cert))
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self.incoming, self.outgoing, server_side=False)
        return self.handshake_step()

    def handshake_step(self) -> bytes:
        """Advance the handshake as far as possible; return bytes to send."""
        try:
            self.tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        return self.outgoing.read()

    def _pending(self) -> bool:
        try:
            self.tls.do_handshake()
            return False
        except ssl.SSLWantReadError:
            return True

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def send_slowly(self, data: bytes, chunk: int, delay: float) -> None:
        for i in range(0, len(data), chunk):
            self.writer.write(data[i:i + chunk])
            await self.writer.drain()
            await asyncio.sleep(delay)

    async def feed(self, timeout: float = 5.0) -> bytes:
        """Read one chunk from the wire into the TLS engine; returns it."""
        data = await asyncio.wait_for(self.reader.read(65536), timeout)
        if data:
            self.incoming.write(data)
        return data

    async def complete_handshake(self, timeout: float = 10.0, *, flush: bool = True) -> bytes:
        """Run the handshake to completion.

        With flush=False the client's final flight (Finished) is left in
        the outgoing BIO and returned instead of sent, so a test can
        coalesce it with application data in a single segment.
        """
        deadline = time.monotonic() + timeout
        out = self.start_tls() if self.tls is None else self.handshake_step()
        if out:
            await self.send_raw(out)
        while self._pending():
            if time.monotonic() > deadline:
                raise asyncio.TimeoutError("TLS handshake did not complete")
            data = await self.feed(timeout=max(0.1, deadline - time.monotonic()))
            if not data:
                raise ConnectionError("EOF during TLS handshake")
            if self._pending():
                out = self.handshake_step()
                if out:
                    await self.send_raw(out)
        final = self.outgoing.read()      # client Finished (TLS 1.3)
        if flush and final:
            await self.send_raw(final)
            return b""
        return final

    def app_bytes(self, text: str) -> bytes:
        """Encrypt `text` and return the record bytes without sending."""
        self.tls.write(text.encode())
        return self.outgoing.read()

    async def send_app(self, text: str) -> None:
        await self.send_raw(self.app_bytes(text))

    async def recv_app(self, timeout: float = 5.0) -> str:
        while True:
            try:
                return self.tls.read(65536).decode(errors="replace")
            except ssl.SSLWantReadError:
                data = await self.feed(timeout)
                if not data:
                    raise ConnectionError("EOF")

    async def close_rst(self) -> None:
        """Abort with RST instead of FIN."""
        sock = self.writer.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.writer.close()

    async def close_fin(self) -> None:
        """Half-close: FIN to the server, keep reading."""
        self.writer.write_eof()

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Bogus server (ircd connects out to it)
# ---------------------------------------------------------------------------


class BogusTLSServer:
    """A TLS 'server' with selectable misbehaviour.

    modes:
      silent            accept, read everything, never send a byte
      close             accept, close immediately
      garbage           accept, send random bytes, keep reading
      truncated_flight  reply to ClientHello with the first `truncate` bytes
                        of the server flight, then go silent
      complete          full handshake with the given cert, then record the
                        decrypted application data ircd sends (PASS/SERVER)
      slow_complete     full handshake, but every server flight is dribbled
                        `chunk` bytes at a time with `chunk_delay` between
                        writes (after an optional `pre_delay`).  With a slow
                        enough drip the handshake is still incomplete when
                        ircd's 5 s deadline fires -- exercising the deadline
                        teardown racing with in-flight handshake data.
      slow_close        dribble a partial server flight, then close mid-drip.
    """

    def __init__(self, mode: str, *, cert: str = "tlspeer", truncate: int = 200,
                 delay: float = 0.0, pre_delay: float = 0.0,
                 chunk: int = 0, chunk_delay: float = 0.0):
        self.mode = mode
        self.cert = cert
        self.truncate = truncate
        # Seconds to wait after accept before misbehaving.  0 hits the peer
        # while ircd is still inside its connect-completion step; ~1 s makes
        # sure ircd has parked in "waiting for the server flight" first.
        self.delay = delay
        # Latency knobs (slow_* modes): pre_delay before the first flight, then
        # each flight written `chunk` bytes at a time with `chunk_delay` between
        # writes (chunk=0 means write the whole flight at once).
        self.pre_delay = pre_delay
        self.chunk = chunk
        self.chunk_delay = chunk_delay
        self.server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self.accepted = asyncio.Event()
        self.received_raw = bytearray()
        self.app_lines: list[str] = []
        self.done = asyncio.Event()
        self._closed = False

    async def start(self, host: str = "0.0.0.0") -> int:
        self.server = await asyncio.start_server(self._handle, host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
            self.server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.accepted.set()
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.mode == "close":
                writer.close()
                return
            if self.mode == "garbage":
                writer.write(os.urandom(512))
                await writer.drain()
                await self._drain_until_eof(reader)
                return
            if self.mode == "silent":
                await self._drain_until_eof(reader)
                return

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path(self.cert), key_path(self.cert))
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = ctx.wrap_bio(incoming, outgoing, server_side=True)

            if self.mode == "truncated_flight":
                # Feed the ClientHello, take the server flight, send a prefix.
                while True:
                    data = await reader.read(65536)
                    if not data:
                        return
                    self.received_raw += data
                    incoming.write(data)
                    try:
                        tls.do_handshake()
                    except ssl.SSLWantReadError:
                        pass
                    flight = outgoing.read()
                    if flight:
                        writer.write(flight[: self.truncate])
                        await writer.drain()
                        break
                await self._drain_until_eof(reader)
                return

            if self.mode in ("slow_complete", "slow_close"):
                if self.pre_delay:
                    await asyncio.sleep(self.pre_delay)
                # Drive the handshake, dribbling each outgoing flight so the
                # peer's SSL_connect sees many small WANT_READ steps; a slow
                # enough drip is still going when ircd's 5 s deadline fires.
                while True:
                    try:
                        tls.do_handshake()
                        break
                    except ssl.SSLWantReadError:
                        out = outgoing.read()
                        if out:
                            if self.mode == "slow_close":
                                await self._write_slow(writer, out[: self.truncate])
                                writer.close()
                                return
                            await self._write_slow(writer, out)
                        data = await reader.read(65536)
                        if not data:
                            return
                        self.received_raw += data
                        incoming.write(data)
                out = outgoing.read()
                if out:
                    await self._write_slow(writer, out)
                # Handshake done -> behave like `complete`: decrypt app lines.
                buf = ""
                while True:
                    try:
                        chunk = tls.read(65536)
                        if not chunk:
                            return
                        buf += chunk.decode(errors="replace")
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            self.app_lines.append(line.rstrip("\r"))
                            self.done.set()
                    except ssl.SSLWantReadError:
                        data = await reader.read(65536)
                        if not data:
                            return
                        incoming.write(data)
                    except ssl.SSLZeroReturnError:
                        return

            if self.mode == "complete":
                # Full handshake, then decrypt whatever ircd sends.
                while True:
                    try:
                        tls.do_handshake()
                        break
                    except ssl.SSLWantReadError:
                        out = outgoing.read()
                        if out:
                            writer.write(out)
                            await writer.drain()
                        data = await reader.read(65536)
                        if not data:
                            return
                        self.received_raw += data
                        incoming.write(data)
                out = outgoing.read()
                if out:
                    writer.write(out)
                    await writer.drain()
                buf = ""
                while True:
                    try:
                        chunk = tls.read(65536)
                        if not chunk:
                            return
                        buf += chunk.decode(errors="replace")
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            self.app_lines.append(line.rstrip("\r"))
                            self.done.set()
                    except ssl.SSLWantReadError:
                        data = await reader.read(65536)
                        if not data:
                            return
                        incoming.write(data)
                    except ssl.SSLZeroReturnError:
                        return
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            self.done.set()
            writer.close()

    async def _write_slow(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        """Write `data`, dribbling `self.chunk` bytes at a time with
        `self.chunk_delay` between writes (whole write when chunk<=0)."""
        if self.chunk and self.chunk > 0:
            for i in range(0, len(data), self.chunk):
                writer.write(data[i:i + self.chunk])
                await writer.drain()
                if self.chunk_delay:
                    await asyncio.sleep(self.chunk_delay)
        else:
            writer.write(data)
            await writer.drain()

    async def _drain_until_eof(self, reader: asyncio.StreamReader) -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            self.received_raw += data


# ---------------------------------------------------------------------------
# Sidecar: the bogus server inside the docker test network
# ---------------------------------------------------------------------------

SIDECAR_IMAGE = "python:3-alpine"
SIDECAR_NAME = "ircu-bogus-tls"
SIDECAR_IP = "10.55.0.40"          # Connect { name = "bogus.test.net" } in ircd-tls-hub.conf
SIDECAR_PORT = 4500
TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _test_network() -> str:
    out = subprocess.run(
        ["docker", "network", "ls", "--filter", "name=ircu-test-net", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=30,
    )
    names = [n for n in out.stdout.split() if n]
    if not names:
        raise RuntimeError("ircu-test-net docker network not found (is the TLS topology up?)")
    return names[0]


class SidecarBogusServer:
    """BogusTLSServer running in a container on the test network.

    The host firewall may drop container->host traffic, so the server runs
    where the hub can reach it.  Events are read back from the container's
    stdout as JSON lines (see bogus_server_main.py).
    """

    def __init__(self, mode: str, *, truncate: int = 200, cert: str = "tlspeer",
                 delay: float = 0.0, pre_delay: float = 0.0,
                 chunk: int = 0, chunk_delay: float = 0.0):
        self.mode = mode
        self.truncate = truncate
        self.cert = cert
        self.delay = delay
        self.pre_delay = pre_delay
        self.chunk = chunk
        self.chunk_delay = chunk_delay
        self.port = SIDECAR_PORT
        self.ip = SIDECAR_IP
        self.events: list[dict] = []
        self._started = False

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._start_blocking)
        self._started = True
        await self.wait_event("listening", 20.0)
        return self.port

    def _start_blocking(self) -> None:
        subprocess.run(["docker", "rm", "-f", SIDECAR_NAME], capture_output=True, timeout=30)
        net = _test_network()
        cmd = [
            "docker", "run", "-d", "--name", SIDECAR_NAME,
            "--network", net, "--ip", self.ip,
            "-v", f"{TESTS_DIR}:/tests:ro", "-e", "PYTHONPATH=/tests", "-w", "/tests",
            SIDECAR_IMAGE, "python", "-u", "tls/bogus_server_main.py",
            "--mode", self.mode, "--port", str(self.port),
            "--truncate", str(self.truncate), "--cert", self.cert,
            "--delay", str(self.delay),
            "--pre-delay", str(self.pre_delay),
            "--chunk", str(self.chunk), "--chunk-delay", str(self.chunk_delay),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            raise RuntimeError(f"sidecar start failed: {r.stderr.strip()}")

    def _poll_events(self) -> list[dict]:
        r = subprocess.run(["docker", "logs", SIDECAR_NAME], capture_output=True, text=True, timeout=30)
        events = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
        return events

    async def wait_event(self, name: str, timeout: float) -> dict:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            self.events = await loop.run_in_executor(None, self._poll_events)
            for ev in self.events:
                if ev.get("event") == name:
                    return ev
            if loop.time() > deadline:
                raise asyncio.TimeoutError(f"sidecar: no {name!r} event; got {self.events[-5:]}")
            await asyncio.sleep(0.3)

    @property
    def received_raw(self) -> bytes:
        data = b""
        for ev in self.events:
            if ev.get("event") == "raw":
                data += bytes.fromhex(ev["hex"])
        return data

    @property
    def app_lines(self) -> list[str]:
        return [ev["text"] for ev in self.events if ev.get("event") == "line"]

    async def stop(self) -> None:
        if not self._started:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(["docker", "rm", "-f", SIDECAR_NAME], capture_output=True, timeout=30),
        )
        self._started = False


# ---------------------------------------------------------------------------
# Observers
# ---------------------------------------------------------------------------


def container_cpu_percent(container: str) -> float | None:
    """One `docker stats` sample of the container's CPU usage, or None."""
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", container],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    value = out.stdout.strip().rstrip("%")
    try:
        return float(value)
    except ValueError:
        return None


async def sample_cpu(container: str, seconds: float) -> list[float]:
    """Sample CPU% repeatedly for `seconds` (each sample takes ~1-2 s)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    samples: list[float] = []
    while loop.time() < deadline:
        value = await loop.run_in_executor(None, container_cpu_percent, container)
        if value is not None:
            samples.append(value)
    return samples
