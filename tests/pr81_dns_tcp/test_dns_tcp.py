"""DNS resolver integration tests for UDP truncation and TCP fallback."""

from __future__ import annotations

import asyncio
import random
import time

import pytest

from irc_client import IRCClient
from pr81_dns_tcp.helpers import (
    AUTH_FAIL,
    AUTH_FOUND,
    AUTH_MISMATCH,
    get_stats,
    notice_blob,
    notice_text,
    register_collect_auth_notices,
    reset_stats,
    set_scenario,
    trigger_oper_connect,
)

pytestmark = pytest.mark.dns


@pytest.mark.asyncio
async def test_normal_udp_ptr_and_a_success(ircd_dns_hub, dns_control):
  """PTR and A over UDP succeed without TCP fallback."""
  dns_control("ok_udp")
  nick = f"dnsok{random.randint(0, 999_999)}"
  notices = await register_collect_auth_notices(
      ircd_dns_hub["host"],
      ircd_dns_hub["port"],
      nick,
  )
  blob = notice_blob(notices)
  assert AUTH_FOUND in blob, f"expected hostname success, got: {blob!r}"
  stats = get_stats()
  assert stats["tcp_queries"] == 0, f"normal UDP path should not use TCP: {stats}"


@pytest.mark.asyncio
async def test_udp_tc_tcp_fallback_success(ircd_dns_hub, dns_control):
  """UDP TC=1 on A lookup retries over TCP and succeeds."""
  dns_control("tc_tcp")
  reset_stats()
  nick = f"dnstc{random.randint(0, 999_999)}"
  notices = await register_collect_auth_notices(
      ircd_dns_hub["host"],
      ircd_dns_hub["port"],
      nick,
  )
  blob = notice_blob(notices)
  assert AUTH_FOUND in blob, f"expected TCP fallback success, got: {blob!r}"
  stats = get_stats()
  assert stats["tcp_queries"] >= 1, f"expected TCP retry, stats={stats}"


@pytest.mark.asyncio
async def test_udp_tc_tcp_fallback_fails(ircd_dns_hub, dns_control):
  """When TCP fallback cannot complete, hostname lookup fails."""
  dns_control("tc_tcp_fail")
  nick = f"dnstf{random.randint(0, 999_999)}"
  notices = await register_collect_auth_notices(
      ircd_dns_hub["host"],
      ircd_dns_hub["port"],
      nick,
  )
  blob = notice_blob(notices)
  assert AUTH_FAIL in blob, f"expected DNS failure, got: {blob!r}"


@pytest.mark.asyncio
async def test_forward_reverse_dns_mismatch(ircd_dns_hub, dns_control):
  """Mismatched forward A record is rejected after PTR succeeds."""
  dns_control("mismatch")
  nick = f"dnsmm{random.randint(0, 999_999)}"
  notices = await register_collect_auth_notices(
      ircd_dns_hub["host"],
      ircd_dns_hub["port"],
      nick,
  )
  blob = notice_blob(notices)
  assert AUTH_MISMATCH in blob, f"expected mismatch notice, got: {blob!r}"


@pytest.mark.asyncio
async def test_aaaa_tcp_fallback_on_connect(ircd_dns_hub, dns_control):
    """Server CONNECT AAAA lookup retries over TCP when UDP response is truncated."""
    dns_control("tc_aaaa")
    reset_stats()
    await trigger_oper_connect(
        ircd_dns_hub["host"],
        ircd_dns_hub["port"],
        "aaaa.tc.test",
    )
    stats = get_stats()
    assert stats["tcp_aaaa_queries"] >= 1, (
        f"expected AAAA TCP fallback on CONNECT, stats={stats}"
    )


@pytest.mark.asyncio
async def test_aaaa_empty_over_tcp_falls_back_to_a(ircd_dns_hub, dns_control):
    """A complete-but-empty AAAA answer over TCP must fall back to an A query.

    The truncated UDP reply must not be treated as "no AAAA" (that is what
    the TCP retry is for), but once the TCP response authoritatively says
    there are no AAAA records, the resolver should query A like the plain
    UDP path does -- not fail the lookup.
    """
    dns_control("tc_aaaa_empty")
    reset_stats()
    await trigger_oper_connect(
        ircd_dns_hub["host"],
        ircd_dns_hub["port"],
        "aaaa.empty.test",
    )
    deadline = time.monotonic() + 10.0
    stats = get_stats()
    while time.monotonic() < deadline and stats["a_fallback_queries"] < 1:
        await asyncio.sleep(0.5)
        stats = get_stats()
    assert stats["tcp_aaaa_queries"] >= 1, (
        f"expected AAAA retry over TCP first, stats={stats}"
    )
    assert stats["a_fallback_queries"] >= 1, (
        f"expected A fallback after empty AAAA over TCP, stats={stats}"
    )


@pytest.mark.asyncio
async def test_tc_hold_keeps_tcp_session_pending(ircd_dns_hub, dns_control):
  """Truncated UDP with tc_hold keeps the DNS-over-TCP session open."""
  dns_control("tc_hold")
  reset_stats()
  host = ircd_dns_hub["host"]
  port = ircd_dns_hub["port"]
  nick = f"hold{random.randint(0, 999_999)}"

  client = IRCClient()
  await client.connect(host, port)
  notices: list[str] = []
  try:
    await client.send(f"NICK {nick}")
    await client.send("USER hold 0 * :DNS hold test")
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
      try:
        msg = await client.recv(timeout=1.0)
      except TimeoutError:
        if get_stats()["tcp_queries"] >= 1:
          break
        continue
      if msg.command == "NOTICE":
        notices.append(notice_text(msg))
      if get_stats()["tcp_queries"] >= 1:
        break
    await asyncio.sleep(2.0)
    stats = get_stats()
    blob = notice_blob(notices)
    assert stats["tcp_queries"] >= 1, f"expected pending TCP DNS query, stats={stats}"
    assert AUTH_FOUND not in blob, f"hold should delay DNS completion, got: {blob!r}"
    assert AUTH_FAIL not in blob, f"hold should not fail DNS immediately, got: {blob!r}"
  finally:
    try:
      await client.send("QUIT :hold test cleanup")
    except Exception:
      pass
    await client.disconnect()
