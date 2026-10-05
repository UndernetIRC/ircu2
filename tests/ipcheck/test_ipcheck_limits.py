"""IPcheck connection-rate limiting on the dedicated limits server.

IPcheck (ircd/IPcheck.c) keeps a per-address registry of connected clients
and recent connection attempts.  A local connection is refused with

    ERROR :Your host is trying to (re)connect too fast -- throttled

when the address has made IPCHECK_CLONE_LIMIT attempts each less than
IPCHECK_CLONE_PERIOD seconds apart -- unless the server booted less than
IPCHECK_CLONE_DELAY seconds ago, or the address is listed in an IPCheck
except block.  Every registered local client is told the registry state for
its address ("on N ca M(L) ft F(S)"), which these tests use to observe the
counters.  The Client-block maxlinks limit is enforced from the same
registry via IPcheck_nr().

All test connections come from one address (the docker bridge gateway), so
every connection made by a test -- including the opers -- is an attempt
against that address.  Each test therefore sleeps out the period before its
measured burst.  Features changed with SET are reverted with RESET, and
REHASH (which resets SET features to the config values) always precedes
the SET calls.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from class_limits.helpers import rehash_config, restore_config
from ipcheck.helpers import (
    disconnect_all,
    raw_connect_first_line,
    register_expect_no_notice,
    register_expect_throttled,
    register_with_notice,
    userip,
    THROTTLE_ERROR,
)
from irc_client import IRCClient
from tls.helpers import oper_up

pytestmark = pytest.mark.limits

CLONE_LIMIT = 3     # attempts within the period; the LIMIT-th is refused
CLONE_PERIOD = 4    # seconds between attempts that keep the counter alive
STARTTARGETS = 10   # ircd_defs.h


def _grant_set(snapshot: str) -> str:
    """Config with PRIV_SET granted to the test oper (denied by default)."""
    return snapshot.replace(
        'name = "testoper";',
        'name = "testoper";\n        set = yes;',
    )


async def _apply(setoper: IRCClient, **features: int | str) -> None:
    for name, value in features.items():
        await setoper.send(f"SET {name} {value}")
    await asyncio.sleep(0.3)


async def _reset(setoper: IRCClient, *names: str) -> None:
    for name in names:
        try:
            await setoper.send(f"RESET {name}")
        except Exception:
            pass
    await asyncio.sleep(0.3)


async def _idle_out_period() -> None:
    """Let the address go idle for longer than the clone period."""
    await asyncio.sleep(CLONE_PERIOD + 1.5)


@pytest_asyncio.fixture
async def ipcheck_env(ircd_limits, limits_oper, limits_config_snapshot, make_limits_client):
    """PRIV_SET-capable oper with the clone limit/period/delay applied.

    Yields (server, setoper).  Restores features and config afterwards.
    """
    restore_config(_grant_set(limits_config_snapshot))
    await rehash_config(limits_oper)
    setoper = await make_limits_client("ipcsetop")
    await oper_up(setoper)
    await _apply(
        setoper,
        IPCHECK_CLONE_DELAY=0,
        IPCHECK_CLONE_LIMIT=CLONE_LIMIT,
        IPCHECK_CLONE_PERIOD=CLONE_PERIOD,
    )
    try:
        yield ircd_limits, setoper
    finally:
        await _reset(
            setoper,
            "IPCHECK_CLONE_DELAY", "IPCHECK_CLONE_LIMIT", "IPCHECK_CLONE_PERIOD",
        )
        restore_config(limits_config_snapshot)
        await rehash_config(limits_oper)


async def test_registration_notice_reports_registry_state(ipcheck_env):
    """Each local client is told connected/attempt counts and the limit."""
    srv, _ = ipcheck_env
    await _idle_out_period()
    c1 = c2 = None
    try:
        c1, n1 = await register_with_notice(srv["host"], srv["port"], "ipcnot1")
        assert n1.limit == CLONE_LIMIT
        assert n1.attempts == 1, n1            # idle period reset the counter
        assert n1.start_targets == STARTTARGETS
        assert 0 <= n1.free_targets <= STARTTARGETS
        base = n1.connected                    # opers + c1

        c2, n2 = await register_with_notice(srv["host"], srv["port"], "ipcnot2")
        assert n2.connected == base + 1, (n1, n2)
        assert n2.attempts == 2, n2
    finally:
        await disconnect_all(c1, c2)


async def test_clone_limit_throttles_and_recovers(ipcheck_env):
    """LIMIT-1 quick connects succeed; the LIMIT-th is refused before it
    can send anything; a refused attempt does not count as connected; after
    the period the address is accepted again."""
    srv, _ = ipcheck_env
    await _idle_out_period()
    clients = []
    try:
        for i in range(CLONE_LIMIT - 1):
            c, n = await register_with_notice(srv["host"], srv["port"], f"ipclim{i}")
            clients.append(c)
            assert n.attempts == i + 1, n
        connected_before = n.connected

        await register_expect_throttled(srv["host"], srv["port"])
        # Still refused while the counter is alive.
        await register_expect_throttled(srv["host"], srv["port"])

        await _idle_out_period()
        c, n = await register_with_notice(srv["host"], srv["port"], "ipclimok")
        clients.append(c)
        assert n.attempts == 1, n                        # counter reset
        assert n.connected == connected_before + 1, n    # refusals not counted
    finally:
        await disconnect_all(*clients)


async def test_refused_attempt_restarts_period(ipcheck_env):
    """A throttled attempt is itself an attempt: it restarts the period, so
    an address that keeps retrying stays refused even once the last
    *accepted* connect is more than a period in the past."""
    srv, _ = ipcheck_env
    half = CLONE_PERIOD / 2 + 0.5
    await _idle_out_period()
    clients = []
    try:
        for i in range(CLONE_LIMIT - 1):
            c, _ = await register_with_notice(srv["host"], srv["port"], f"ipcref{i}")
            clients.append(c)
        await register_expect_throttled(srv["host"], srv["port"])
        await asyncio.sleep(half)
        await register_expect_throttled(srv["host"], srv["port"])
        await asyncio.sleep(half)
        # More than CLONE_PERIOD since the last accepted connect, but only
        # half a period since the last refusal: still refused.
        await register_expect_throttled(srv["host"], srv["port"])
        await _idle_out_period()
        c, _ = await register_with_notice(srv["host"], srv["port"], "ipcrefok")
        clients.append(c)
    finally:
        await disconnect_all(*clients)


async def test_disconnected_clients_release_connected_slots(ipcheck_env):
    """The connected count drops when clients leave (attempts do not)."""
    srv, _ = ipcheck_env
    await _idle_out_period()
    keep = None
    try:
        a, na = await register_with_notice(srv["host"], srv["port"], "ipcrel1")
        await disconnect_all(a)
        await asyncio.sleep(0.3)
        keep, nb = await register_with_notice(srv["host"], srv["port"], "ipcrel2")
        assert nb.connected == na.connected, (na, nb)   # a's slot released
        assert nb.attempts == na.attempts + 1, (na, nb)  # but still an attempt
    finally:
        await disconnect_all(keep)


async def test_boot_grace_disables_throttling(ipcheck_env):
    """With IPCHECK_CLONE_DELAY larger than the uptime nothing is refused,
    although attempts keep being counted past the limit."""
    srv, setoper = ipcheck_env
    await _apply(setoper, IPCHECK_CLONE_DELAY=10_000_000)
    await _idle_out_period()
    clients = []
    try:
        for i in range(2 * CLONE_LIMIT):
            c, n = await register_with_notice(srv["host"], srv["port"], f"ipcgrc{i}")
            clients.append(c)
            assert n.attempts == i + 1, n
        assert n.attempts > n.limit
    finally:
        await disconnect_all(*clients)


async def test_except_block_exempts_address(ipcheck_env, limits_oper, limits_config_snapshot):
    """An address in IPCheck { except ...; } is never counted or refused,
    and gets no registry notice; removing the block restores the limit."""
    srv, setoper = ipcheck_env
    ip = await userip(setoper, "ipcsetop")

    text = _grant_set(limits_config_snapshot) + f'\nIPCheck {{ except "{ip}"; }};\n'
    restore_config(text)
    await rehash_config(limits_oper)
    # REHASH reverts SET features to the config values; reapply.
    await _apply(
        setoper,
        IPCHECK_CLONE_DELAY=0,
        IPCHECK_CLONE_LIMIT=CLONE_LIMIT,
        IPCHECK_CLONE_PERIOD=CLONE_PERIOD,
    )
    clients = []
    try:
        for i in range(2 * CLONE_LIMIT):
            clients.append(
                await register_expect_no_notice(srv["host"], srv["port"], f"ipcexm{i}")
            )
    finally:
        await disconnect_all(*clients)
        clients = []

    # Drop the exemption again.
    restore_config(_grant_set(limits_config_snapshot))
    await rehash_config(limits_oper)
    await _apply(
        setoper,
        IPCHECK_CLONE_DELAY=0,
        IPCHECK_CLONE_LIMIT=CLONE_LIMIT,
        IPCHECK_CLONE_PERIOD=CLONE_PERIOD,
    )
    await _idle_out_period()
    try:
        for i in range(CLONE_LIMIT - 1):
            c, n = await register_with_notice(srv["host"], srv["port"], f"ipcexn{i}")
            clients.append(c)
        await register_expect_throttled(srv["host"], srv["port"])
    finally:
        await disconnect_all(*clients)


async def test_except_blocks_accumulate(ipcheck_env, limits_oper, limits_config_snapshot):
    """Several IPCheck blocks add up: a later block must not discard the
    exemptions of an earlier one."""
    srv, setoper = ipcheck_env
    ip = await userip(setoper, "ipcsetop")

    text = (
        _grant_set(limits_config_snapshot)
        + f'\nIPCheck {{ except "{ip}"; }};\n'
        + '\nIPCheck { except "192.0.2.0/24"; };\n'
    )
    restore_config(text)
    await rehash_config(limits_oper)
    await _apply(
        setoper,
        IPCHECK_CLONE_DELAY=0,
        IPCHECK_CLONE_LIMIT=CLONE_LIMIT,
        IPCHECK_CLONE_PERIOD=CLONE_PERIOD,
    )
    clients = []
    try:
        for i in range(2 * CLONE_LIMIT):
            clients.append(
                await register_expect_no_notice(srv["host"], srv["port"], f"ipcacc{i}")
            )
    finally:
        await disconnect_all(*clients)


async def test_client_block_maxlinks_uses_ip_registry(ipcheck_env, limits_oper, limits_config_snapshot):
    """Client { maxlinks = N } refuses the N+1th client from one address,
    counted from the IPcheck registry (IPcheck_nr), and admits again once a
    client leaves."""
    srv, setoper = ipcheck_env
    probe = extra = None
    # No rate limiting in this test: it is about the per-IP maximum.
    await _apply(setoper, IPCHECK_CLONE_LIMIT=1000)
    try:
        # Measure how many clients from our address are connected right now.
        probe, n = await register_with_notice(srv["host"], srv["port"], "ipcmaxp")
        limit = n.connected

        text = _grant_set(limits_config_snapshot).replace(
            'Client { ip = "*"; class = "Local"; };',
            f'Client {{ ip = "*"; class = "Local"; maxlinks = {limit}; }};',
        )
        assert text != limits_config_snapshot
        restore_config(text)
        await rehash_config(limits_oper)
        await _apply(setoper, IPCHECK_CLONE_LIMIT=1000)   # REHASH reset it

        # limit + 1 > maxlinks: refused at registration.
        line = await _register_first_error(srv, "ipcmaxx")
        assert "Too many connections from your host" in line, line

        # Once a slot frees up the next client is admitted.
        await disconnect_all(probe)
        probe = None
        await asyncio.sleep(0.3)
        extra, n2 = await register_with_notice(srv["host"], srv["port"], "ipcmaxy")
        assert n2.connected == limit, (limit, n2)
    finally:
        await disconnect_all(probe, extra)


async def _register_first_error(srv, nick: str) -> str:
    """Register and return the ERROR line the server closes with."""
    client = IRCClient()
    await client.connect(srv["host"], srv["port"])
    await client.send(f"NICK {nick}")
    await client.send(f"USER {nick} 0 * :IPcheck test")
    try:
        while True:
            msg = await client.recv(timeout=5.0)
            if msg.command == "ERROR":
                return msg.raw
            if msg.command == "001":
                raise AssertionError(f"{nick}: registered but should have been refused")
    finally:
        await client.disconnect()


async def test_throttle_error_is_sent_before_any_input(ipcheck_env):
    """The throttle decision is made at accept time: the ERROR arrives
    without the client sending a byte, then the connection is closed."""
    srv, _ = ipcheck_env
    await _idle_out_period()
    clients = []
    try:
        for i in range(CLONE_LIMIT - 1):
            c, _ = await register_with_notice(srv["host"], srv["port"], f"ipcerr{i}")
            clients.append(c)
        line = await raw_connect_first_line(srv["host"], srv["port"])
        assert line == THROTTLE_ERROR, line
    finally:
        await disconnect_all(*clients)
