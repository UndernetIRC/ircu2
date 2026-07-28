"""
WebSocket Cloudflare proxy integration tests.

Verifies CF-Connecting-IP handling, IPcheck placement, and ident policy on
``cloudflare = yes`` websocket listeners vs plain websocket/TCP ports.

  pytest test_websocket_cloudflare.py -v --timeout=120
"""

from __future__ import annotations

import asyncio
import os
import random
import struct
import tempfile
import time
from pathlib import Path

import pytest

from irc_client import IRCClient, parse_message

pytestmark = pytest.mark.single_server

HOST = "127.0.0.1"
NORMAL_PORT = 6667
WS_PORT = 7000
CF_WS_PORT = 7001

# RFC 5737 documentation range — not routed on the public internet.
CF_CLIENT_IP = "203.0.113.50"
SPOOF_IP = "203.0.113.99"

_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="

REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_CONF_HOST = REPO_ROOT / "tests" / "docker" / "ircd-hub.conf"
HUB_CONTAINER = "ircu-hub"
HUB_CONF_CONTAINER = "/opt/ircu/lib/ircd.conf"

# Hub test harness: explicit username = "ident" Client line enables DoIdentLookups.
_IDENT_CLIENT_LINE = (
    'Client { ip = "*"; class = "Local"; username = "ident"; maxlinks = 50; };\n'
)
_IAUTH_TRUST_LINE = (
    'IAuth { program = "/opt/ircu/bin/iauth-trust-username.pl"; };\n'
)

def _raw_ws_handshake(*extra_header_lines: bytes) -> bytes:
    lines = [
        b"GET / HTTP/1.1\r\n",
        b"Host: 127.0.0.1\r\n",
        b"Upgrade: websocket\r\n",
        b"Connection: Upgrade\r\n",
        b"Sec-WebSocket-Key: " + _WS_KEY.encode() + b"\r\n",
        b"Sec-WebSocket-Version: 13\r\n",
        b"Sec-WebSocket-Protocol: text.ircv3.net\r\n",
    ]
    lines.extend(extra_header_lines)
    lines.append(b"\r\n")
    return b"".join(lines)


def _masked_client_frame(opcode: int, payload: bytes) -> bytes:
    pl = len(payload)
    b0 = (0x80 | (opcode & 0x0F)) & 0xFF
    if pl <= 125:
        hdr = struct.pack("!BB", b0, 0x80 | pl)
    elif pl < 65536:
        hdr = struct.pack("!BBH", b0, 0x80 | 126, pl)
    else:
        hdr = struct.pack("!BB", b0, 0x80 | 127) + b"\x00\x00\x00\x00" + struct.pack("!I", pl)
    key = os.urandom(4)
    masked = bytes(payload[i] ^ key[i % 4] for i in range(pl))
    return hdr + key + masked


def _masked_text_frame(line: str) -> bytes:
    return _masked_client_frame(0x1, (line + "\r\n").encode("utf-8"))


async def _read_http_response(r: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5.0)


async def _read_one_unmasked_server_ws_frame(
    r: asyncio.StreamReader, *, read_timeout: float
) -> tuple[int, bytes]:
    """Read next server→client WebSocket frame (unmasked). Returns (opcode, payload)."""
    b0, b1 = await asyncio.wait_for(r.readexactly(2), timeout=read_timeout)
    pl = b1 & 0x7F
    if pl == 126:
        pl = int.from_bytes(await asyncio.wait_for(r.readexactly(2), timeout=read_timeout), "big")
    elif pl == 127:
        ext = await asyncio.wait_for(r.readexactly(8), timeout=read_timeout)
        pl = int.from_bytes(ext[4:8], "big")
    payload = await asyncio.wait_for(r.readexactly(pl), timeout=read_timeout) if pl else b""
    return b0 & 0x0F, payload


async def _attempt_ws_handshake(
    port: int,
    *,
    extra_headers: tuple[bytes, ...] = (),
) -> tuple[bool, bytes]:
    """Return (upgraded, response_prefix). Rejected handshakes close with an ERROR line."""
    reader, writer = await asyncio.open_connection(HOST, port)
    try:
        writer.write(_raw_ws_handshake(*extra_headers))
        await writer.drain()
        try:
            http = await _read_http_response(reader)
        except asyncio.IncompleteReadError as exc:
            return False, exc.partial or b""
        return b"101" in http, http
    finally:
        writer.close()


async def _ws_register_collect_notices(
    port: int,
    nick: str,
    *,
    extra_headers: tuple[bytes, ...] = (),
    stop_after_notices: bool = False,
    keep_open: bool = False,
) -> tuple[list[str], list[str], asyncio.StreamWriter | None]:
    """Complete a WS handshake and registration; return (notice texts, raw lines, writer).

    When ``keep_open`` is true the WebSocket connection stays up until the caller
    closes ``writer`` (used when another client will WHOIS this session).
    """
    reader, writer = await asyncio.open_connection(HOST, port)
    try:
        writer.write(_raw_ws_handshake(*extra_headers))
        await writer.drain()
        http = await _read_http_response(reader)
        if b"101" not in http:
            raise AssertionError(f"expected HTTP 101 on port {port}, got {http[:300]!r}")

        writer.write(_masked_text_frame(f"NICK {nick}"))
        writer.write(_masked_text_frame("USER wsuser 0 * :Cloudflare WS test"))
        await writer.drain()

        notices: list[str] = []
        raw_lines: list[str] = []
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            slot = min(5.0, max(0.25, deadline - time.monotonic()))
            try:
                opcode, payload = await _read_one_unmasked_server_ws_frame(
                    reader, read_timeout=slot
                )
            except asyncio.TimeoutError:
                continue
            if opcode == 0x8:
                break
            if opcode == 0x9:
                writer.write(_masked_client_frame(0xA, payload))
                await writer.drain()
                continue
            if opcode != 0x1:
                continue
            line = payload.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            raw_lines.append(line)
            msg = parse_message(line)
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
                if stop_after_notices and "Checking Ident" in " ".join(msg.params):
                    if keep_open:
                        return notices, raw_lines, writer
                    return notices, raw_lines, None
            if msg.command.upper() == "PING":
                writer.write(_masked_text_frame(f"PONG :{msg.params[-1]}"))
                await writer.drain()
                continue
            if msg.command in ("376", "422"):
                if keep_open:
                    return notices, raw_lines, writer
                return notices, raw_lines, None
        raise AssertionError("registration ended without MOTD")
    finally:
        if not keep_open:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _whois_userhost(observer: IRCClient, nick: str) -> tuple[str, str]:
    """Return (username, host) from RPL_WHOISUSER."""
    await observer.send(f"WHOIS {nick}")
    while True:
        msg = await observer.recv(timeout=10.0)
        if msg.command == "311":
            return msg.params[2], msg.params[3]
        if msg.command in ("318", "401"):
            raise AssertionError(f"WHOIS for {nick} failed: {msg}")


async def _whois_host(observer: IRCClient, nick: str) -> str:
    _, host = await _whois_userhost(observer, nick)
    return host


@pytest.mark.asyncio
async def test_cloudflare_port_uses_cf_connecting_ip(ircd_hub, make_client):
    """CF-Connecting-IP becomes the client address on a cloudflare websocket port."""
    observer = await make_client("cfwho")
    nick = f"cfok{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
    _, _, ws_writer = await _ws_register_collect_notices(
        CF_WS_PORT, nick, extra_headers=headers, keep_open=True
    )
    assert ws_writer is not None
    try:
        host = await _whois_host(observer, nick)
        assert host == CF_CLIENT_IP, f"expected WHOIS host {CF_CLIENT_IP}, got {host!r}"
    finally:
        ws_writer.write(_masked_text_frame("QUIT :done"))
        await ws_writer.drain()
        ws_writer.close()
        await observer.send("QUIT :done")


@pytest.mark.asyncio
async def test_plain_websocket_ignores_cf_connecting_ip(ircd_hub, make_client):
    """CF-Connecting-IP is ignored on websocket ports without cloudflare = yes."""
    observer = await make_client("wswho")
    nick = f"wsno{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + SPOOF_IP.encode() + b"\r\n",)
    _, _, ws_writer = await _ws_register_collect_notices(
        WS_PORT, nick, extra_headers=headers, keep_open=True
    )
    assert ws_writer is not None
    try:
        host = await _whois_host(observer, nick)
        assert host != SPOOF_IP, (
            f"plain websocket port must not trust CF-Connecting-IP; WHOIS host was {host!r}"
        )
    finally:
        ws_writer.write(_masked_text_frame("QUIT :done"))
        await ws_writer.drain()
        ws_writer.close()
        await observer.send("QUIT :done")


@pytest.mark.asyncio
async def test_cloudflare_port_rejects_missing_cf_connecting_ip(ircd_hub):
    """cloudflare = yes requires a valid CF-Connecting-IP header at handshake."""
    upgraded, response = await _attempt_ws_handshake(CF_WS_PORT)
    assert not upgraded, f"handshake should fail without CF-Connecting-IP, got {response[:200]!r}"


@pytest.mark.asyncio
async def test_cloudflare_port_rejects_invalid_cf_connecting_ip(ircd_hub):
    upgraded, response = await _attempt_ws_handshake(
        CF_WS_PORT, extra_headers=(b"CF-Connecting-IP: not-an-ip\r\n",)
    )
    assert not upgraded, f"invalid CF-Connecting-IP must be rejected, got {response[:200]!r}"


def _notice_blob(notices: list[str]) -> str:
    return "\n".join(notices)


@pytest.mark.asyncio
async def test_cloudflare_websocket_keeps_tilde_without_ident(
    ircd_hub, make_client, request
):
    """CF ports skip ident but still get ~ from ircu when lookups are enabled."""
    baseline = HUB_CONF_HOST.read_text()
    assert _IDENT_CLIENT_LINE in baseline, "hub conf missing username=ident Client line"

    oper = await make_client("cftilop")
    await _oper_up(oper)
    try:
        observer = await make_client("cftilob")
        nick = f"cftu{random.randint(0, 999_999)}"
        headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
        notices, _, ws_writer = await _ws_register_collect_notices(
            CF_WS_PORT, nick, extra_headers=headers, keep_open=True
        )
        assert ws_writer is not None
        try:
            blob = _notice_blob(notices)
            assert "Checking Ident" not in blob, (
                f"cloudflare WS should skip ident, got notices: {blob!r}"
            )
            username, host = await _whois_userhost(observer, nick)
            assert host == CF_CLIENT_IP, f"expected CF IP host, got {host!r}"
            assert username == "~wsuser", (
                "with DoIdentLookups on, cloudflare WS must keep tilde, "
                f"got {username!r}"
            )
        finally:
            ws_writer.write(_masked_text_frame("QUIT :done"))
            await ws_writer.drain()
            ws_writer.close()
            await observer.send("QUIT :done")
            await observer.disconnect()
    finally:
        await oper.disconnect()


@pytest.mark.asyncio
async def test_cloudflare_iauth_trusted_username_no_tilde(
    ircd_hub, make_client, request
):
    """When iauth asserts a trusted username (U), CF WS must not get a tilde.

    Ident is skipped on cloudflare ports, so without iauth the client would
    get ~ from DoIdentLookups.  Enabling iauth-trust-username.pl temporarily
    proves the trust path: iauth sets the username, and ircu must not prepend ~.
    """
    baseline = HUB_CONF_HOST.read_text()
    assert _IDENT_CLIENT_LINE in baseline, "hub conf missing username=ident Client line"
    assert "IAuth {" not in baseline, "shared hub must not run a permanent IAuth"

    request.addfinalizer(lambda: _restore_hub_baseline(baseline))

    patched = baseline.rstrip() + "\n" + _IAUTH_TRUST_LINE
    assert _IAUTH_TRUST_LINE in patched

    oper = await make_client("cfiauthop")
    await _oper_up(oper)
    try:
        _write_hub_config(patched)
        await _rehash_hub(oper)

        observer = await make_client("cfiauthob")
        nick = f"cfiu{random.randint(0, 999_999)}"
        headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
        notices, _, ws_writer = await _ws_register_collect_notices(
            CF_WS_PORT, nick, extra_headers=headers, keep_open=True
        )
        assert ws_writer is not None
        try:
            blob = _notice_blob(notices)
            assert "Checking Ident" not in blob, (
                f"cloudflare WS should skip ident, got notices: {blob!r}"
            )
            username, host = await _whois_userhost(observer, nick)
            assert host == CF_CLIENT_IP, f"expected CF IP host, got {host!r}"
            assert username == "wsuser", (
                "iauth trusted username must register without tilde on CF WS, "
                f"got {username!r}"
            )
        finally:
            ws_writer.write(_masked_text_frame("QUIT :done"))
            await ws_writer.drain()
            ws_writer.close()
            await observer.send("QUIT :done")
            await observer.disconnect()
    finally:
        _restore_hub_baseline(baseline)
        conf = _hub_conf_text()
        assert _IDENT_CLIENT_LINE in conf, "hub conf restore missing username=ident"
        assert "IAuth {" not in conf, "hub conf restore left IAuth enabled"
        try:
            await _rehash_hub(oper)
        except Exception:
            pass
        await oper.disconnect()


@pytest.mark.asyncio
async def test_cloudflare_websocket_skips_ident_lookup(ircd_hub):
    """Ident is not queried for cloudflare websocket clients."""
    nick = f"cfid{random.randint(0, 999_999)}"
    headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
    notices, _, _ = await _ws_register_collect_notices(CF_WS_PORT, nick, extra_headers=headers)
    blob = _notice_blob(notices)
    assert "Checking Ident" not in blob, f"cloudflare WS should skip ident, got notices: {blob!r}"


@pytest.mark.asyncio
async def test_plain_websocket_runs_ident_lookup(ircd_hub):
    """Plain websocket ports still attempt ident when enabled in config."""
    nick = f"wsid{random.randint(0, 999_999)}"
    notices, _, _ = await _ws_register_collect_notices(
        WS_PORT, nick, stop_after_notices=True
    )
    blob = _notice_blob(notices)
    assert "Checking Ident" in blob, f"plain WS should attempt ident, got notices: {blob!r}"


@pytest.mark.asyncio
async def test_plain_tcp_runs_ident_lookup(ircd_hub):
    """Normal TCP user ports attempt ident when enabled in config."""
    nick = f"tcpid{random.randint(0, 999_999)}"
    client = IRCClient()
    await client.connect(HOST, NORMAL_PORT)
    notices: list[str] = []
    try:
        await client.send(f"NICK {nick}")
        await client.send("USER tcpuser 0 * :TCP ident test")
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            msg = await client.recv(timeout=5.0)
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
                if "Checking Ident" in " ".join(msg.params):
                    break
            if msg.command in ("376", "422"):
                break
    finally:
        await client.disconnect()

    blob = _notice_blob(notices)
    assert "Checking Ident" in blob, f"TCP port should attempt ident, got notices: {blob!r}"


@pytest.mark.asyncio
async def test_cloudflare_defers_ipcheck_until_handshake(ircd_hub):
    """Many TCP accepts from one socket IP do not throttle before CF IP is applied."""
    # Without deferred IPcheck, repeated connects from the same peer could hit
    # limits at accept time. Cloudflare ports defer until CF-Connecting-IP.
    for i in range(6):
        upgraded, http = await _attempt_ws_handshake(
            CF_WS_PORT,
            extra_headers=(b"CF-Connecting-IP: " + f"203.0.113.{10 + i}".encode() + b"\r\n",),
        )
        assert upgraded, f"connect {i}: expected 101, got {http[:120]!r}"


def _write_hub_config(text: str) -> None:
    """Push config into the running hub with docker cp (see class_limits helpers)."""
    import subprocess

    tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    try:
        tmp.write(text)
        tmp.close()
        os.chmod(tmp.name, 0o644)
        subprocess.run(
            ["docker", "cp", tmp.name, f"{HUB_CONTAINER}:{HUB_CONF_CONTAINER}"],
            check=True,
            capture_output=True,
        )
    finally:
        os.unlink(tmp.name)


def _sighup_hub_ircd() -> None:
    """Reload hub config without needing a live OPER connection."""
    import subprocess

    subprocess.run(
        [
            "docker",
            "exec",
            HUB_CONTAINER,
            "sh",
            "-c",
            # Prefer the real ircd binary; fall back to pgrep -f.
            "pid=$(pidof /opt/ircu/bin/ircd 2>/dev/null || pidof ircd 2>/dev/null || "
            "pgrep -n -f /opt/ircu/bin/ircd || true); "
            '[ -n "$pid" ] && kill -HUP "$pid"',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    time.sleep(0.5)


def _restore_hub_baseline(baseline: str) -> None:
    """Always rewrite the baked hub conf and SIGHUP so later tests see tildes again.

    The patched config removes ``username = "ident"`` or adds a temporary
    IAuth trust stub; if a run is interrupted before REHASH restore, subsequent
    trust_username tests register without ``~`` (or hang on required iauth)
    and fail in cascade.  File write + SIGHUP works even when the test's oper
    client is already dead.
    """
    _write_hub_config(baseline)
    _sighup_hub_ircd()


def _hub_conf_text() -> str:
    import subprocess

    result = subprocess.run(
        ["docker", "exec", HUB_CONTAINER, "cat", HUB_CONF_CONTAINER],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


async def _oper_up(oper: IRCClient) -> None:
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)


async def _rehash_hub(oper: IRCClient) -> None:
    await oper.send("REHASH")
    msg = await oper.wait_for("382", timeout=10.0)
    assert "Rehashing" in msg.params[-1], f"Unexpected REHASH reply: {msg}"
    await asyncio.sleep(0.5)


@pytest.mark.asyncio
async def test_cloudflare_no_tilde_when_ident_lookups_disabled(
    ircd_hub, make_client, request
):
    """CF ports must not force ~ when DoIdentLookups is off.

    DoIdentLookups is enabled when any Client block has a non-empty username
    component (dedicated username =, or host/ip = "user@host").  This test
    removes the hub's username = "ident" line to turn lookups off.  IAuth is
    disabled for this check; iauth U/o is a separate trust path.
    """
    baseline = HUB_CONF_HOST.read_text()
    assert _IDENT_CLIENT_LINE in baseline, "hub conf missing username=ident Client line"

    request.addfinalizer(lambda: _restore_hub_baseline(baseline))

    patched = baseline.replace(_IDENT_CLIENT_LINE, "", 1)
    assert _IDENT_CLIENT_LINE not in patched

    oper = await make_client("cfnoidop")
    await _oper_up(oper)
    try:
        _write_hub_config(patched)
        await _rehash_hub(oper)

        observer = await make_client("cfnoidob")
        nick = f"cfnt{random.randint(0, 999_999)}"
        headers = (b"CF-Connecting-IP: " + CF_CLIENT_IP.encode() + b"\r\n",)
        notices, _, ws_writer = await _ws_register_collect_notices(
            CF_WS_PORT, nick, extra_headers=headers, keep_open=True
        )
        assert ws_writer is not None
        try:
            blob = _notice_blob(notices)
            assert "Checking Ident" not in blob, (
                f"cloudflare WS must still skip ident with DoIdentLookups off, "
                f"got notices: {blob!r}"
            )
            username, host = await _whois_userhost(observer, nick)
            assert host == CF_CLIENT_IP, f"expected CF IP host, got {host!r}"
            assert username == "wsuser", (
                f"with DoIdentLookups off, CF port must not force tilde, "
                f"got {username!r}"
            )
        finally:
            ws_writer.write(_masked_text_frame("QUIT :done"))
            await ws_writer.drain()
            ws_writer.close()
            await observer.send("QUIT :done")
            await observer.disconnect()
    finally:
        # Explicit restore + verify before other tests in this session continue.
        _restore_hub_baseline(baseline)
        conf = _hub_conf_text()
        assert _IDENT_CLIENT_LINE in conf, "hub conf restore missing username=ident"
        try:
            await _rehash_hub(oper)
        except Exception:
            # SIGHUP already applied in _restore_hub_baseline.
            pass
        await oper.disconnect()
