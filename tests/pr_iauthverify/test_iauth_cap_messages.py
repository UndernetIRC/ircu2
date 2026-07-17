"""TDD tests for the iauthverify branch: CAP start/end notifications to iauth.

The branch introduces two new ircd->iauth messages: "c" when a client
enters capability negotiation and "e" when it finishes. auth_cap_start()
only sends "c" the first time (guarded by AR_CAP_PENDING), but
auth_cap_done() sends "e" unconditionally: a client that sends CAP END
without ever starting CAP produces a stray "e", and repeated CAP END
produces duplicate "e" messages. An iauth instance tracking CAP state
per client would get confused by both.

These tests run the locally built ircd with an iauth stub that logs the
raw message stream, drive clients through CAP sequences, and assert on
the logged "c"/"e" messages. They need ircd/ircd compiled for this host
(run `make` first); they skip if it is missing.
"""

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
IRCD_BIN = REPO_ROOT / "ircd" / "ircd"
STUB = Path(__file__).resolve().parent / "iauth_stub.py"

pytestmark = pytest.mark.skipif(
    not IRCD_BIN.exists(), reason="local ircd binary not built"
)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spath():
    """Read the compiled-in SPATH from config.h (ircd checks it on boot)."""
    for line in (REPO_ROOT / "config.h").read_text().splitlines():
        if line.startswith("#define SPATH "):
            return Path(line.split('"')[1])
    return None


@pytest.fixture
def ensure_spath():
    """ircd refuses to start unless SPATH exists; symlink it if missing."""
    spath = _spath()
    created = False
    if spath and not spath.exists() and spath.parent.is_dir():
        spath.symlink_to(IRCD_BIN)
        created = True
    yield
    if created:
        spath.unlink(missing_ok=True)


CONF_TEMPLATE = """\
General {{
        name = "iauthcap.example.net";
        vhost = "127.0.0.1";
        description = "iauth cap test server";
        numeric = 99;
}};
Admin {{
        Location = "test";
        Location = "test";
        Contact = "test@example.net";
}};
Class {{
        name = "Local";
        pingfreq = 90 seconds;
        sendq = 160000;
        maxlinks = 100;
}};
Client {{ ip = "127.*"; class = "Local"; }};
Port {{ port = {port}; }};
IAuth {{ program = "{python}" "{stub}" "{log}"; }};
"""


@pytest.fixture
def local_ircd(tmp_path, ensure_spath):
    """Spawn a local ircd with the logging iauth stub attached."""
    port = _free_port()
    log = tmp_path / "iauth.log"
    log.touch()
    conf = tmp_path / "ircd.conf"
    conf.write_text(
        CONF_TEMPLATE.format(
            port=port,
            python=sys.executable,
            stub=STUB,
            log=log,
        )
    )
    proc = subprocess.Popen(
        [str(IRCD_BIN), "-n", "-f", str(conf), "-d", str(tmp_path)],
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("ircd exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("ircd did not start listening")
        yield {"port": port, "log": log}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _run_client(port, pre_registration_lines, nick):
    """Connect, send the given lines, register, and wait for 001."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    async def send(line):
        writer.write((line + "\r\n").encode())
        await writer.drain()

    for line in pre_registration_lines:
        await send(line)
    await send(f"NICK {nick}")
    await send(f"USER testuser 0 * :Test User")

    deadline = asyncio.get_event_loop().time() + 15
    try:
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            raw = await asyncio.wait_for(reader.readline(), timeout=remaining)
            if not raw:
                raise ConnectionError("server closed connection")
            line = raw.decode(errors="replace").strip()
            if line.startswith("PING"):
                await send("PONG " + line.split(" ", 1)[1])
            parts = line.split()
            if len(parts) > 1 and parts[1] == "001":
                return
    finally:
        writer.write(b"QUIT :done\r\n")
        try:
            await writer.drain()
        except OSError:
            pass
        writer.close()


def _cap_messages(log_path):
    """Return the list of 'c'/'e' iauth messages, e.g. ['c', 'e']."""
    msgs = []
    for line in log_path.read_text().splitlines():
        parts = line.split(" ")
        if len(parts) >= 2 and parts[1] in ("c", "e"):
            msgs.append(parts[1])
    return msgs


async def test_cap_end_without_cap_start_sends_no_e(local_ircd):
    """A bare CAP END (no CAP LS/REQ first) must not send "e" to iauth.

    The client never entered capability negotiation, so iauth never got
    a "c" for it; sending "e" anyway confuses iauth's session tracking.
    """
    await _run_client(local_ircd["port"], ["CAP END"], "iavcap1")
    await asyncio.sleep(0.5)
    assert _cap_messages(local_ircd["log"]) == []


async def test_repeated_cap_end_sends_single_e(local_ircd):
    """CAP END sent twice must produce exactly one "c" and one "e"."""
    await _run_client(
        local_ircd["port"],
        ["CAP LS 302", "CAP END", "CAP END"],
        "iavcap2",
    )
    await asyncio.sleep(0.5)
    assert _cap_messages(local_ircd["log"]) == ["c", "e"]
