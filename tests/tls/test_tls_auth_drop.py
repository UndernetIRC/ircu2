"""Stress TLS registration / AUTH notice pipeline (ZNC-like).

Production symptom under investigation: TLS client sees NOTICE AUTH, then the
link dies with no ERROR and without finishing registration.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field

import pytest

from irc_client import IRCClient
from tls_certs import client_ssl_context

pytestmark = [pytest.mark.tls, pytest.mark.tls_stress, pytest.mark.asyncio]


@dataclass
class AttemptResult:
    nick: str
    saw_auth: bool = False
    saw_welcome: bool = False
    saw_error: bool = False
    auth_lines: list[str] = field(default_factory=list)
    last_command: str | None = None
    outcome: str = "unknown"
    detail: str = ""


def _is_auth_notice(msg) -> bool:
    return (
        msg.command == "NOTICE"
        and len(msg.params) >= 1
        and msg.params[0].upper() == "AUTH"
    )


async def _pipeline_tls_register(
    host: str,
    port: int,
    nick: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = 20.0,
    delay_before_read: float = 0.0,
) -> AttemptResult:
    """TLS connect, immediately send NICK/USER (ZNC-like), watch for silent drop."""
    result = AttemptResult(nick=nick)
    client = IRCClient()
    try:
        await client.connect_tls(host, port, ssl_context=ssl_context)
        # Pipeline registration without waiting for AUTH — matches bouncer behaviour.
        await client.send(f"NICK {nick}")
        await client.send(f"USER {nick} 0 * :TLS AUTH drop probe")
        if delay_before_read > 0:
            await asyncio.sleep(delay_before_read)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                result.outcome = "timeout"
                result.detail = (
                    f"timed out after AUTH={result.saw_auth} "
                    f"welcome={result.saw_welcome} error={result.saw_error} "
                    f"last={result.last_command}"
                )
                return result
            try:
                msg = await client.recv(timeout=remaining)
            except ConnectionError as exc:
                result.detail = str(exc)
                if result.saw_auth and not result.saw_welcome and not result.saw_error:
                    result.outcome = "silent_drop"
                elif result.saw_welcome:
                    result.outcome = "ok_closed_after_welcome"
                elif result.saw_error:
                    result.outcome = "error_then_close"
                else:
                    result.outcome = "closed_before_auth"
                return result

            result.last_command = msg.command
            if _is_auth_notice(msg):
                result.saw_auth = True
                if len(msg.params) >= 2:
                    result.auth_lines.append(msg.params[-1])
            elif msg.command == "001":
                result.saw_welcome = True
            elif msg.command == "ERROR":
                result.saw_error = True
                result.outcome = "error"
                result.detail = " ".join(msg.params)
                return result
            elif msg.command in ("432", "433", "436", "437", "464", "465"):
                result.outcome = "numeric_reject"
                result.detail = f"{msg.command} {' '.join(msg.params)}"
                return result
            elif msg.command in ("376", "422"):
                result.outcome = "ok"
                return result
    finally:
        await client.disconnect()


async def _run_batch(
    host: str,
    port: int,
    *,
    count: int,
    nick_prefix: str,
    ssl_context: ssl.SSLContext | None = None,
    delay_before_read: float = 0.0,
) -> list[AttemptResult]:
    tasks = [
        _pipeline_tls_register(
            host,
            port,
            f"{nick_prefix}{i}",
            ssl_context=ssl_context,
            delay_before_read=delay_before_read,
        )
        for i in range(count)
    ]
    return list(await asyncio.gather(*tasks))


def _assert_no_silent_drops(results: list[AttemptResult]) -> None:
    drops = [r for r in results if r.outcome == "silent_drop"]
    failures = [r for r in results if r.outcome not in ("ok", "ok_closed_after_welcome")]
    if drops:
        samples = "; ".join(
            f"{r.nick}: auth={r.auth_lines!r} detail={r.detail!r}" for r in drops[:5]
        )
        pytest.fail(
            f"{len(drops)}/{len(results)} TLS clients saw NOTICE AUTH then "
            f"silent close (no ERROR / 001). samples: {samples}"
        )
    bad = [r for r in failures if r.outcome not in ("numeric_reject",)]
    if bad:
        samples = "; ".join(f"{r.nick}:{r.outcome}:{r.detail!r}" for r in bad[:5])
        pytest.fail(
            f"{len(bad)}/{len(results)} TLS registrations failed unexpectedly: {samples}"
        )


async def test_tls_auth_pipeline_single(ircd_tls_network):
    """One pipelined TLS registration must complete or ERROR — never silent drop."""
    hub = ircd_tls_network["hub"]
    result = await _pipeline_tls_register(hub["host"], hub["tls_port"], "auths1")
    assert result.outcome != "silent_drop", f"silent drop after AUTH: {result}"
    assert result.outcome == "ok", f"unexpected outcome: {result}"
    assert result.saw_welcome


async def test_tls_auth_pipeline_with_client_cert(ircd_tls_network):
    """Same with a presented client cert (soft CertificateRequest path)."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context(cert="selfsigned")
    result = await _pipeline_tls_register(
        hub["host"], hub["tls_port"], "authcert1", ssl_context=ctx
    )
    assert result.outcome != "silent_drop", f"silent drop after AUTH: {result}"
    assert result.outcome == "ok", f"unexpected outcome: {result}"
    assert result.saw_welcome


async def test_tls_auth_pipeline_concurrent(ircd_tls_network):
    """Concurrent pipelined TLS connects — stress AUTH flush / sendq."""
    hub = ircd_tls_network["hub"]
    results = await _run_batch(
        hub["host"], hub["tls_port"], count=24, nick_prefix="authc"
    )
    _assert_no_silent_drops(results)


async def test_tls_auth_pipeline_concurrent_client_cert(ircd_tls_network):
    """Concurrent TLS connects presenting client certificates."""
    hub = ircd_tls_network["hub"]
    ctx = client_ssl_context(cert="selfsigned")
    results = await _run_batch(
        hub["host"],
        hub["tls_port"],
        count=16,
        nick_prefix="authcc",
        ssl_context=ctx,
    )
    _assert_no_silent_drops(results)


async def test_tls_auth_pipeline_burst_rounds(ircd_tls_network):
    """Several waves of concurrent connects to amplify timing races."""
    hub = ircd_tls_network["hub"]
    all_results: list[AttemptResult] = []
    for wave in range(4):
        all_results.extend(
            await _run_batch(
                hub["host"],
                hub["tls_port"],
                count=12,
                nick_prefix=f"authw{wave}",
            )
        )
    _assert_no_silent_drops(all_results)
