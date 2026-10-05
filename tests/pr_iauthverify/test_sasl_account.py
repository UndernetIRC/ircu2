"""SASL OK account parsing and the matching iauth "A" notification.

auth_set_account() parses the first word as account[:id[:flags[:...]]] and
an optional second umode-like word (+...). The full original payload is
forwarded to iauth as "A <payload>" while only account/id/flags/+x affect
local state.

These tests run a locally built ircd with the logging iauth stub, link a
fake P10 services server for SASL XREPLY, and assert both client-visible
effects and the exact "A" line iauth received.
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
HIDDEN_HOST_SUFFIX = "users.undernet.org"


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


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spath() -> Path | None:
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
        name = "iavsasl.example.net";
        vhost = "127.0.0.1";
        description = "iauth sasl account test server";
        numeric = 1;
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
        "HOST_HIDING" = "TRUE";
        "HIDDEN_HOST" = "users.undernet.org";
}};
"""


@pytest.fixture
async def sasl_iauth_env(tmp_path, ensure_spath):
    """Local ircd + logging iauth stub + P10 services with SASL enabled."""
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
        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("ircd exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", client_port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("ircd did not start listening")

        # Wait until iauth is up (required policy) via a throwaway register.
        last_exc = None
        for _ in range(5):
            probe = IRCClient()
            try:
                await probe.connect("127.0.0.1", client_port)
                await probe.register("iavwarm", "testuser", "Warmup")
                await probe.send("QUIT :warmup")
                await probe.disconnect()
                break
            except Exception as exc:
                last_exc = exc
                try:
                    await probe.disconnect()
                except Exception:
                    pass
                await asyncio.sleep(0.3)
        else:
            raise RuntimeError(f"iauth stub never became ready: {last_exc!r}")

        log.write_text("")  # drop warmup traffic

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
            "server_port": server_port,
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


async def _start_sasl(client, services):
    await client.send("CAP LS 302")
    msg = await client.wait_for("CAP", timeout=5.0)
    assert "sasl" in msg.params[-1], "hub does not advertise sasl"

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
    await client.wait_for("001", timeout=10.0)


async def _whois_account_and_host(client, nick):
    await client.send(f"WHOIS {nick}")
    found_account = None
    found_host = None
    deadline = time.time() + 5.0
    while time.time() < deadline:
        msg = await client.recv(timeout=5.0)
        if msg.command == "311":
            found_host = msg.params[3]
        if msg.command == "330":
            found_account = msg.params[2]
        if msg.command == "318":
            break
    return found_account, found_host


def _wait_iauth_a(log: Path, payload: str, timeout: float = 5.0) -> str:
    """Wait until iauth has logged ``<id> A <payload>`` exactly."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = log.read_text()
        for line in text.splitlines():
            # "<fd> A <payload>" — payload may contain spaces.
            if " A " not in line:
                continue
            fd, _, rest = line.partition(" A ")
            if fd.lstrip("-").isdigit() and rest == payload:
                return line
        time.sleep(0.05)
    raise AssertionError(
        f"iauth never saw exact A payload {payload!r}\n"
        f"log was:\n{log.read_text()}"
    )


def _iauth_a_payloads(log: Path) -> list[str]:
    out = []
    for line in log.read_text().splitlines():
        if " A " not in line:
            continue
        fd, _, rest = line.partition(" A ")
        if fd.lstrip("-").isdigit():
            out.append(rest)
    return out


OK_VARIANTS = [
    # account_info, nick, expect_account, expect_hidden
    ("onlyacct", "iava0", "onlyacct", False),
    ("acctid:42", "iava1", "acctid", False),
    ("acctflags:42:7", "iava2", "acctflags", False),
    ("fullacct:42:0 +x", "iava3", "fullacct", True),
    ("hideid:77 +x", "iava5", "hideid", True),
    ("plusxo:88:3:something +xo YRS", "iava6", "plusxo", True),
    ("noyrs:9:0 YRS", "iava7", "noyrs", False),
    ("pluso:9:0 +o", "iava8", "pluso", False),
    ("spaced:1:2:extra +x TRAILING", "iava9", "spaced", True),
]


async def test_sasl_ok_variants_notify_iauth(sasl_iauth_env):
    """Various OK payloads: parse effects on the client; iauth gets the full string."""
    env = sasl_iauth_env
    services = env["services"]
    log: Path = env["log"]

    for account_info, nick, expect_account, expect_hidden in OK_VARIANTS:
        log.write_text("")
        client = IRCClient()
        await client.connect(env["host"], env["port"])
        try:
            hub_num, routing = await _start_sasl(client, services)
            await services.send_xreply(hub_num, routing, f"OK {account_info}")

            msg = await client.wait_for("903", timeout=5.0)
            assert msg is not None, account_info

            _wait_iauth_a(log, account_info)

            await _finish_registration(client, nick)

            found_account, found_host = await _whois_account_and_host(client, nick)
            assert found_account == expect_account, account_info
            hidden = f"{expect_account}.{HIDDEN_HOST_SUFFIX}"
            if expect_hidden:
                assert found_host == hidden, (
                    f"{account_info}: expected hide, got {found_host!r}"
                )
            else:
                assert found_host != hidden, (
                    f"{account_info}: did not expect hide, got {found_host!r}"
                )
        finally:
            try:
                await client.send("QUIT :done")
            except Exception:
                pass
            await client.disconnect()


async def test_sasl_ok_without_account_must_not_crash_or_notify_iauth(
    sasl_iauth_env,
):
    """Malformed OK must not crash; iauth must not receive an "A" line."""
    env = sasl_iauth_env
    services = env["services"]
    log: Path = env["log"]

    for i, bad_reply in enumerate(("OK", "OK ", "OK ::::")):
        log.write_text("")
        client = IRCClient()
        await client.connect(env["host"], env["port"])
        try:
            hub_num, routing = await _start_sasl(client, services)
            await services.send_xreply(hub_num, routing, bad_reply)
            await _finish_registration(client, f"iavbad{i}")
        finally:
            try:
                await client.send("QUIT :done")
            except Exception:
                pass
            await client.disconnect()

        assert _iauth_a_payloads(log) == [], (
            f"malformed {bad_reply!r} must not send A to iauth; got "
            f"{_iauth_a_payloads(log)!r}"
        )

    probe = IRCClient()
    await probe.connect(env["host"], env["port"])
    try:
        await probe.register("iavprobe", "testuser", "Test User")
    finally:
        await probe.send("QUIT :done")
        await probe.disconnect()
