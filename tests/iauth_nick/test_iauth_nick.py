"""Tests for iauth forced nickname assignment (f command).

These tests run the locally built ircd with an iauth stub that rewrites
nicknames during registration.  Rebuild with `make` if sources change.

Scenarios covered:
  - SASL OK / FAIL / absent, with and without nick forcing (testnick -> Guest001)
  - Client NICK changes attempted while iauth is still pending
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from irc_client import IRCClient
from p10_server import P10Server


REPO_ROOT = Path(__file__).resolve().parents[2]
IRCD_BIN = REPO_ROOT / "ircd" / "ircd"
STUB = Path(__file__).resolve().parent / "iauth_stub.py"


def _ircd_bin_is_stale() -> bool:
    if not IRCD_BIN.exists():
        return False
    built = IRCD_BIN.stat().st_mtime
    for pattern in ("ircd/*.c", "ircd/*.y", "include/*.h"):
        for src in REPO_ROOT.glob(pattern):
            if src.stat().st_mtime > built:
                return True
    return False


pytestmark = [
    pytest.mark.skipif(
        not IRCD_BIN.exists(), reason="local ircd binary not built"
    ),
    pytest.mark.skipif(
        _ircd_bin_is_stale(),
        reason="local ircd binary is older than the sources; rebuild with make",
    ),
]


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spath():
    for line in (REPO_ROOT / "config.h").read_text().splitlines():
        if line.startswith("#define SPATH "):
            return Path(line.split('"')[1])
    return None


@pytest.fixture
def ensure_spath():
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
        name = "iauthnick.example.net";
        vhost = "127.0.0.1";
        description = "iauth nick test server";
        numeric = 98;
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
Class {{
        name = "Server";
        pingfreq = 90 seconds;
        connectfreq = 5 minutes;
        sendq = 9 megabytes;
        maxlinks = 10;
}};
Client {{ ip = "127.*"; class = "Local"; }};
Connect {{
        name = "services.test.net";
        host = "127.0.0.1";
        password = "testpass";
        class = "Server";
        hub;
}};
UWorld {{
        oper = "services.test.net";
}};
Port {{ port = {client_port}; }};
Port {{ server = yes; port = {server_port}; }};
IAuth {{ program = "{python}" "{stub}" "{log}"; }};
Features {{
        "HUB" = "TRUE";
        "NODNS" = "TRUE";
}};
"""


async def _wait_listening(proc, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("ircd exited during startup")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("ircd did not start listening")


async def _warmup_iauth(port, attempts=5):
    last_exc = None
    for _ in range(attempts):
        try:
            await _register(port, "probeok", "testuser")
            return
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            last_exc = exc
            await asyncio.sleep(0.3)
    raise RuntimeError(f"iauth stub never became ready: {last_exc!r}")


@pytest.fixture
async def local_ircd(tmp_path, ensure_spath):
    """Local ircd + nick-forcing iauth stub (no SASL services)."""
    client_port = _free_port()
    server_port = _free_port()
    log = tmp_path / "iauth.log"
    log.touch()
    conf = tmp_path / "ircd.conf"
    conf.write_text(
        CONF_TEMPLATE.format(
            client_port=client_port,
            server_port=server_port,
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
        await _wait_listening(proc, client_port)
        await _warmup_iauth(client_port)
        log.write_text("")
        yield {"host": "127.0.0.1", "port": client_port, "log": log, "services": None}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
async def sasl_ircd(tmp_path, ensure_spath):
    """Local ircd + nick-forcing iauth stub + P10 services for SASL."""
    client_port = _free_port()
    server_port = _free_port()
    log = tmp_path / "iauth.log"
    log.touch()
    conf = tmp_path / "ircd.conf"
    conf.write_text(
        CONF_TEMPLATE.format(
            client_port=client_port,
            server_port=server_port,
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
    services = None
    try:
        await _wait_listening(proc, client_port)
        await _warmup_iauth(client_port)
        log.write_text("")

        services = P10Server(
            name="services.test.net",
            numeric=4,
            password="testpass",
        )
        await services.connect("127.0.0.1", server_port)
        await services.handshake()
        await services.send_config("sasl.server", "services.test.net")
        await services.send_config("sasl.mechanisms", "PLAIN")
        await asyncio.sleep(0.5)

        yield {
            "host": "127.0.0.1",
            "port": client_port,
            "log": log,
            "services": services,
        }
    finally:
        if services is not None:
            try:
                await services.disconnect()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _register(port, nick, username="testuser", timeout=15.0):
    client = IRCClient()
    await client.connect("127.0.0.1", port)
    try:
        await client.send(f"NICK {nick}")
        await client.send(f"USER {username} 0 * :Test User")
        msg = await client.wait_for("001", timeout=timeout)
        return msg
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def _start_sasl(client, services):
    await client.send("CAP LS 302")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert "sasl" in msg.params[-1], "server does not advertise sasl"

    await client.send("CAP REQ :sasl")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert msg.params[1] == "ACK", f"expected CAP ACK, got {msg.params}"

    await client.send("AUTHENTICATE PLAIN")
    line = await services.wait_for_token("XQ", timeout=5.0)
    parts = line.split()
    hub_num = parts[0]
    routing = parts[3]
    assert routing.startswith("sasl:")
    return hub_num, routing


async def _finish_registration(client, nick):
    await client.send(f"NICK {nick}")
    await client.send("USER testuser 0 * :Test User")
    await client.send("CAP END")
    return await client.wait_for("001", timeout=10.0)


def _iauth_errors(log_path):
    errors = []
    for line in log_path.read_text().splitlines():
        parts = line.split(" ")
        if len(parts) >= 3 and parts[1] == "E":
            errors.append(parts[2])
    return errors


def _assert_force_before_done(log_path, forced="Guest001", nick="testnick"):
    """Stub must emit f <forced> before D after seeing n <nick>."""
    text = log_path.read_text().splitlines()
    saw_n = False
    saw_f = False
    for line in text:
        if not saw_n and line.split(" ")[1:3] == ["n", nick]:
            saw_n = True
            continue
        if not saw_n:
            continue
        if line.startswith("> f ") and line.rstrip().endswith(forced):
            saw_f = True
            continue
        if line.startswith("> D "):
            if not saw_f:
                raise AssertionError(
                    f"iauth sent D before f {forced} for {nick}\nlog:\n"
                    + log_path.read_text()
                )
            return
    raise AssertionError(
        f"missing n/{nick} -> f/{forced} -> D sequence\nlog:\n{log_path.read_text()}"
    )


def _assert_no_force(log_path, nick):
    """After n <nick>, stub must Done without an f reply."""
    text = log_path.read_text().splitlines()
    saw_n = False
    for line in text:
        if not saw_n and line.split(" ")[1:3] == ["n", nick]:
            saw_n = True
            continue
        if not saw_n:
            continue
        if line.startswith("> f "):
            raise AssertionError(
                f"unexpected forced nick after n {nick}\nlog:\n{log_path.read_text()}"
            )
        if line.startswith("> D "):
            return
    raise AssertionError(f"missing n/{nick} -> D sequence\nlog:\n{log_path.read_text()}")


async def test_iauth_forced_nick_on_registration(local_ircd):
    """IAuth may replace the client's requested nick before registration."""
    msg = await _register(local_ircd["port"], "tmpuser")
    assert msg.params[0] == "finaluser"


async def test_iauth_forced_nick_explicit_prefix(local_ircd):
    """set_<nick> requests a specific assigned nickname."""
    msg = await _register(local_ircd["port"], "set_custnick")
    assert msg.params[0] == "custnick"


async def test_unregistered_client_cannot_change_nick(local_ircd):
    """After the first NICK, further NICK before 001 is ignored.

    The nick is handed to iauth; changing it mid-auth would defeat forced
    nick / pending checks.
    """
    client = IRCClient()
    await client.connect("127.0.0.1", local_ircd["port"])
    try:
        await client.send("NICK firstnick")
        await client.send("NICK secondnick")
        await client.send("USER testuser 0 * :Test User")
        welcome = await client.wait_for("001", timeout=15.0)
        assert welcome.params[0] == "firstnick"
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_iauth_invalid_forced_nick_retries(local_ircd):
    """Failed f reports E to iauth; a later valid f may finish registration."""
    msg = await _register(local_ircd["port"], "bad_-invalid")
    assert msg.params[0] == "recovered"
    await asyncio.sleep(0.3)
    assert "Invalid" in _iauth_errors(local_ircd["log"])


async def test_iauth_failed_forced_nick_blocks_without_retry(local_ircd):
    """If iauth never sends a valid f after failure, registration must not finish."""
    client = IRCClient()
    await client.connect("127.0.0.1", local_ircd["port"])
    try:
        await client.send("NICK stuckbad")
        await client.send("USER testuser 0 * :Test User")
        with pytest.raises((asyncio.TimeoutError, TimeoutError)):
            await client.wait_for("001", timeout=3.0)
        await asyncio.sleep(0.3)
        assert "Invalid" in _iauth_errors(local_ircd["log"])
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_iauth_forced_nick_collision(local_ircd):
    """In-use forced nick is rejected; iauth can assign another and continue."""
    holder = IRCClient()
    await holder.connect("127.0.0.1", local_ircd["port"])
    try:
        await holder.send("NICK set_taken")
        await holder.send("USER holder 0 * :Holder")
        msg = await holder.wait_for("001", timeout=15.0)
        assert msg.params[0] == "taken"

        msg2 = await _register(local_ircd["port"], "collide")
        assert msg2.params[0] == "freenick"
        await asyncio.sleep(0.3)
        assert "InUse" in _iauth_errors(local_ircd["log"])
    finally:
        try:
            await holder.send("QUIT :done")
        except Exception:
            pass
        await holder.disconnect()


# --- SASL × nick-force matrix + pre-registration NICK edges --------------------


async def test_sasl_ok_then_force_guest001(sasl_ircd):
    """SASL succeeds; before Done, iauth forces testnick -> Guest001."""
    env = sasl_ircd
    services = env["services"]
    env["log"].write_text("")

    client = IRCClient()
    await client.connect(env["host"], env["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        await services.send_xreply(hub_num, routing, "OK forcedacct:1:0")
        assert (await client.wait_for("903", timeout=5.0)) is not None

        await client.send("NICK testnick")
        await client.send("USER testuser 0 * :Test User")
        # Client may try alternate nicks while iauth is still deciding.
        await client.send("NICK sneakynick")
        await client.send("NICK Guest999")
        await client.send("CAP END")

        nick_msg = await client.wait_for("NICK", timeout=10.0)
        assert nick_msg.params[-1] == "Guest001"
        welcome = await client.wait_for("001", timeout=10.0)
        assert welcome.params[0] == "Guest001"

        await asyncio.sleep(0.2)
        log = env["log"].read_text()
        assert " A forcedacct:1:0" in log
        _assert_force_before_done(env["log"])
        # SASL account notice must precede Done for this flow.
        assert log.index(" A forcedacct:1:0") < log.index("> D ")
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_sasl_fail_then_force_guest001(sasl_ircd):
    """Failed SASL still allows registration; iauth may force Guest001."""
    env = sasl_ircd
    services = env["services"]
    env["log"].write_text("")

    client = IRCClient()
    await client.connect(env["host"], env["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        await services.send_xreply(hub_num, routing, "NO bad credentials")
        fail = await client.wait_for("904", timeout=5.0)
        assert fail is not None

        welcome = await _finish_registration(client, "testnick")
        assert welcome.params[0] == "Guest001"
        await asyncio.sleep(0.2)
        assert " A " not in env["log"].read_text()
        _assert_force_before_done(env["log"])
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_sasl_ok_without_nick_force(sasl_ircd):
    """Successful SASL with a normal nick leaves the chosen nick alone."""
    env = sasl_ircd
    services = env["services"]
    env["log"].write_text("")

    client = IRCClient()
    await client.connect(env["host"], env["port"])
    try:
        hub_num, routing = await _start_sasl(client, services)
        await services.send_xreply(hub_num, routing, "OK keepacct:2:0")
        assert (await client.wait_for("903", timeout=5.0)) is not None

        welcome = await _finish_registration(client, "keepnick")
        assert welcome.params[0] == "keepnick"
        await asyncio.sleep(0.2)
        assert " A keepacct:2:0" in env["log"].read_text()
        _assert_no_force(env["log"], "keepnick")
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


async def test_no_sasl_force_guest001(local_ircd):
    """Without SASL, testnick is still forced to Guest001 before Done."""
    local_ircd["log"].write_text("")
    msg = await _register(local_ircd["port"], "testnick")
    assert msg.params[0] == "Guest001"
    await asyncio.sleep(0.2)
    _assert_force_before_done(local_ircd["log"])


async def test_no_sasl_without_nick_force(local_ircd):
    """Without SASL and without a force trigger, the requested nick sticks."""
    local_ircd["log"].write_text("")
    msg = await _register(local_ircd["port"], "plainnick")
    assert msg.params[0] == "plainnick"
    await asyncio.sleep(0.2)
    _assert_no_force(local_ircd["log"], "plainnick")


async def test_nick_changes_ignored_during_sasl_and_force(sasl_ircd):
    """NICK attempts during CAP/SASL/iauth must not stick; force still wins."""
    env = sasl_ircd
    services = env["services"]
    env["log"].write_text("")

    client = IRCClient()
    await client.connect(env["host"], env["port"])
    try:
        # Set nick early, then try to change it throughout SASL negotiation.
        await client.send("NICK testnick")
        await client.send("NICK during_cap")

        hub_num, routing = await _start_sasl(client, services)
        await client.send("NICK during_sasl")
        await services.send_xreply(hub_num, routing, "OK edgeacct:3:0")
        assert (await client.wait_for("903", timeout=5.0)) is not None

        await client.send("NICK after_sasl")
        await client.send("USER testuser 0 * :Test User")
        await client.send("NICK before_cap_end")
        await client.send("CAP END")

        nick_msg = await client.wait_for("NICK", timeout=10.0)
        assert nick_msg.params[-1] == "Guest001"
        welcome = await client.wait_for("001", timeout=10.0)
        assert welcome.params[0] == "Guest001"

        await asyncio.sleep(0.2)
        # Only the first client nick is announced to iauth.
        n_lines = [
            line
            for line in env["log"].read_text().splitlines()
            if line.split(" ")[1:2] == ["n"]
        ]
        assert any(line.endswith(" testnick") or " n testnick" in f" {line}" for line in n_lines)
        assert not any(
            any(bad in line for bad in ("during_cap", "during_sasl", "after_sasl", "before_cap_end"))
            for line in n_lines
        )
        _assert_force_before_done(env["log"])
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()
