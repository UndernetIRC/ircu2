"""NETWORK_FEATURES rolling-upgrade compat tests.

Topology (see docker-compose ircd-nf-{a,b,c}):

    A (prod release, u2.10.12.19) — B (tree, NETWORK_FEATURES=FALSE) — C (tree, NETWORK_FEATURES=TRUE)
                                                                              ^
                                                                       services (P10)

Prod ircu rejects a second ACCOUNT for an already-authed user with
protocol_violation (WALLOPS to +g opers).  Remote OPMODE +x and +z TLS
fingerprint tokens on NICK/umode bursts are newer extensions.  With
NETWORK_FEATURES=FALSE on the middle hop B, those must not reach A.

TLS clients on B still get umode +z locally, but B omits the fingerprint
parameter when introducing them toward peers.  C (NF=TRUE) must accept that
+z-without-fingerprint NICK without crashing or protocol-violating.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server

pytestmark = pytest.mark.nf_compat

# SHA-256-sized hex token used as a synthetic TLS client fingerprint.
FAKE_TLS_FINGERPRINT = (
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
)


@pytest.fixture
async def services(ircd_nf_compat):
    """U:lined P10 services attached to C (NETWORK_FEATURES=TRUE)."""
    c = ircd_nf_compat["c"]
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(c["host"], c["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


@pytest.fixture
async def spy_on_b(ircd_nf_compat):
    """P10 peer on B to observe what B relays toward other servers (incl. A)."""
    b = ircd_nf_compat["b"]
    spy = P10Server(
        name="spy.test.net",
        numeric=5,
        password="testpass",
        description="NF compat wire spy",
    )
    await spy.connect(b["host"], b["server_port"])
    await spy.handshake()
    yield spy
    await spy.disconnect()


async def _make_oper(server: dict, nick: str = "nfoper") -> IRCClient:
    """Register and oper-up with +g so protocol_violation WALLOPS are visible."""
    oper = IRCClient()
    await oper.connect(server["host"], server["port"])
    await oper.register(nick, "oper", "NF Compat Oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=5.0)  # RPL_YOUREOPER
    # Ensure +g (debug / desynch) in case HIS_DEBUG_OPER_ONLY flipped it.
    await oper.send(f"MODE {nick} +g")
    await asyncio.sleep(0.2)
    # Drain greeting noise so later WALLOPS checks are clean.
    await _drain(oper, 0.3)
    return oper


async def _drain(client: IRCClient, seconds: float) -> list:
    """Read and discard messages for a short window."""
    collected = []
    deadline = asyncio.get_running_loop().time() + seconds
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            collected.append(await client.recv(timeout=remaining))
        except (asyncio.TimeoutError, TimeoutError):
            break
    return collected


async def _collect_wallops(client: IRCClient, seconds: float = 2.0) -> list[str]:
    """Collect WALLOPS texts for a window (protocol_violation uses WALLOPS)."""
    msgs = await _drain(client, seconds)
    return [
        m.params[-1]
        for m in msgs
        if m.command.upper() == "WALLOPS" and m.params
    ]


async def _wait_for_nick_lines(spy: P10Server, nick: str, timeout: float = 8.0) -> list[str]:
    """Collect P10 lines from spy until we see a NICK introducing ``nick``."""
    collected: list[str] = []
    deadline = asyncio.get_running_loop().time() + timeout
    needle = f" N {nick} "
    while asyncio.get_running_loop().time() < deadline:
        remaining = deadline - asyncio.get_running_loop().time()
        try:
            batch = await spy.recv_until("N", timeout=max(0.1, remaining))
        except (asyncio.TimeoutError, TimeoutError):
            break
        collected.extend(batch)
        hits = [line for line in collected if needle in f" {line} "]
        if hits:
            return hits
    return [line for line in collected if needle in f" {line} "]


async def test_account_flag_update_not_relayed_to_prod(
    ircd_nf_compat, services
):
    """Second ACCOUNT (flag update) must not reach prod A.

    Prod u2.10.12.19 calls protocol_violation() on any ACCOUNT for an
    already-authed nick.  B with NETWORK_FEATURES=FALSE must drop the
    relay so A's oper never sees a Protocol Violation WALLOPS.
    """
    a = ircd_nf_compat["a"]

    user = IRCClient()
    await user.connect(a["host"], a["port"])
    await user.register("nfuser1", "testuser", "NF User")

    oper = await _make_oper(a, "nfoper1")

    try:
        numnick = await services.wait_for_user("nfuser1", timeout=10.0)

        # First-time ACCOUNT must still propagate A←B←C (registration).
        await services.send_account(numnick, "NfAcct1")
        await asyncio.sleep(0.5)

        await user.send("WHOIS nfuser1")
        whois = await user.collect_until("318", timeout=5.0)
        accounts = [m for m in whois if m.command == "330"]
        assert accounts, (
            "First-time ACCOUNT should reach prod A "
            f"(WHOIS messages: {[m.command for m in whois]})"
        )
        assert "NfAcct1" in accounts[0].params

        await _drain(oper, 0.3)

        # Flag-only update: new servers accept this; prod would protocol_violate.
        await services.send_account(numnick, "NfAcct1", acc_id=1, acc_flags=42)
        wallops = await _collect_wallops(oper, seconds=2.5)

        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "ACCOUNT flag update was relayed to prod A: " + "; ".join(violations)
        )

        # Link must stay healthy.
        await user.send("PING :after-ac")
        pong = await user.wait_for("PONG", timeout=5.0)
        assert "after-ac" in (pong.params[-1] if pong.params else "")
    finally:
        for client in (user, oper):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_opmode_plus_x_not_relayed_to_prod(ircd_nf_compat, services):
    """Remote OPMODE +x from C must not be applied on prod A.

    B with NETWORK_FEATURES=FALSE drops OM +x toward non-local targets,
    so the user on A stays without +x and A raises no protocol noise.
    """
    a = ircd_nf_compat["a"]

    user = IRCClient()
    await user.connect(a["host"], a["port"])
    await user.register("nfuser2", "testuser", "NF User")

    oper = await _make_oper(a, "nfoper2")

    try:
        numnick = await services.wait_for_user("nfuser2", timeout=10.0)

        await services.send_account(numnick, "NfAcct2")
        await asyncio.sleep(0.4)
        await _drain(user, 0.3)
        await _drain(oper, 0.3)

        await services.send_opmode(numnick, "+x")

        # User on prod must not receive MODE +x from the remote OPMODE.
        try:
            mode_msg = await user.wait_for("MODE", timeout=2.5)
            modes = mode_msg.params[-1] if mode_msg.params else ""
            assert "x" not in modes, (
                f"OPMODE +x was applied on prod A: {mode_msg.params}"
            )
        except (asyncio.TimeoutError, TimeoutError):
            pass  # expected: no MODE at all

        wallops = await _collect_wallops(oper, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Unexpected protocol violation on prod after OM +x: "
            + "; ".join(violations)
        )

        await user.send("PING :after-om")
        await user.wait_for("PONG", timeout=5.0)
    finally:
        for client in (user, oper):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_plus_z_fingerprint_not_relayed_to_prod(
    ircd_nf_compat, services, spy_on_b
):
    """TLS +z fingerprint on NICK/umode must not be regenerated toward A.

    C (NETWORK_FEATURES=TRUE) accepts and stores the fingerprint.  B
    (NETWORK_FEATURES=FALSE) must omit it from umode_str() when
    re-bursting, so the wire toward A (and other peers of B) never
    carries the fingerprint token.
    """
    a = ircd_nf_compat["a"]
    oper = await _make_oper(a, "nfoper4")

    # modes="+iz <fp>" becomes two IRC params after host: +iz and the fp,
    # matching umode_str()'s "+iwz <fingerprint>" S2S layout.
    nick = "fpuser1"
    await services.introduce_user(
        nick,
        modes=f"+iz {FAKE_TLS_FINGERPRINT}",
        realname="TLS FP User",
    )

    try:
        user_nicks = await _wait_for_nick_lines(spy_on_b, nick, timeout=8.0)
        assert user_nicks, f"Spy on B never saw NICK for {nick!r}"

        for line in user_nicks:
            assert FAKE_TLS_FINGERPRINT not in line, (
                "B relayed +z TLS fingerprint toward peers (incl. prod A): "
                f"{line}"
            )

        wallops = await _collect_wallops(oper, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Unexpected protocol violation on prod after +z fingerprint "
            "introduction: " + "; ".join(violations)
        )
    finally:
        try:
            await oper.send("QUIT :cleanup")
        except Exception:
            pass
        await oper.disconnect()


async def test_first_account_still_reaches_prod(ircd_nf_compat, services):
    """NETWORK_FEATURES=FALSE must not block first-time ACCOUNT registration."""
    a = ircd_nf_compat["a"]

    user = IRCClient()
    await user.connect(a["host"], a["port"])
    await user.register("nfuser3", "testuser", "NF User")

    try:
        numnick = await services.wait_for_user("nfuser3", timeout=10.0)
        await services.send_account(numnick, "FirstAcct")
        await asyncio.sleep(0.5)

        await user.send("WHOIS nfuser3")
        whois = await user.collect_until("318", timeout=5.0)
        accounts = [m for m in whois if m.command == "330"]
        assert accounts, "First-time ACCOUNT should propagate through B to A"
        assert "FirstAcct" in accounts[0].params
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_tls_plus_z_without_fingerprint_accepted_on_nf_true(
    ircd_nf_compat, services
):
    """TLS client on B (NF=FALSE) reaches C (NF=TRUE) as +z with no fingerprint.

    B omits the fingerprint parameter from S2S NICK while NETWORK_FEATURES is
    off.  C must still SetTLS from bare +z (the ``*(p + 1)`` guard skips
    consuming a missing param) — no crash, no protocol violation, and WHOIS
    on C still reports a secure connection (671).
    """
    b = ircd_nf_compat["b"]
    c = ircd_nf_compat["c"]
    nick = "nftls1"

    oper_c = await _make_oper(c, "nftlsop")

    tls_user = IRCClient()
    await tls_user.connect_tls(b["host"], b["tls_port"])
    await tls_user.register(nick, "testuser", "TLS on NF=FALSE")

    observer = IRCClient()
    await observer.connect(c["host"], c["port"])
    await observer.register("nftlsobs", "testuser", "Observer on C")

    try:
        # C (and services attached to it) must learn the nick from B.
        numnick = await services.wait_for_user(nick, timeout=10.0)
        assert numnick, f"{nick} never appeared on C/services"

        await observer.send(f"WHOIS {nick}")
        whois = await observer.collect_until("318", timeout=5.0)
        secure = [m for m in whois if m.command == "671"]
        assert secure, (
            f"C should keep IsTLS for {nick} introduced without fingerprint; "
            f"WHOIS replies: {[m.command for m in whois]}"
        )

        wallops = await _collect_wallops(oper_c, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "C protocol-violated on +z without fingerprint: "
            + "; ".join(violations)
        )

        # C must still be healthy after accepting the NICK.
        await observer.send("PING :after-tls-z")
        pong = await observer.wait_for("PONG", timeout=5.0)
        assert "after-tls-z" in (pong.params[-1] if pong.params else "")
    finally:
        for client in (tls_user, observer, oper_c):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_p10_plus_z_without_fingerprint_no_crash(
    ircd_nf_compat, services
):
    """Direct P10 NICK with +z and no fingerprint param is accepted on C.

    Mimics the wire format B emits under NETWORK_FEATURES=FALSE, injected
    from services (also attached to C) so the receive path is exercised
    without requiring a TLS client.
    """
    c = ircd_nf_compat["c"]
    nick = "nftls2"

    oper_c = await _make_oper(c, "nftlsop2")
    observer = IRCClient()
    await observer.connect(c["host"], c["port"])
    await observer.register("nftlsobs2", "testuser", "Observer on C")

    try:
        # Bare +iz — no fingerprint after the mode string (unlike "+iz <fp>").
        await services.introduce_user(nick, modes="+iz", realname="No FP User")
        await asyncio.sleep(0.4)

        await observer.send(f"WHOIS {nick}")
        whois = await observer.collect_until("318", timeout=5.0)
        assert any(m.command == "311" for m in whois), (
            f"{nick} missing after +z-without-fp introduce: "
            f"{[m.command for m in whois]}"
        )
        secure = [m for m in whois if m.command == "671"]
        assert secure, (
            f"IsTLS not set on C for +z without fingerprint: "
            f"{[m.command for m in whois]}"
        )

        wallops = await _collect_wallops(oper_c, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Unexpected protocol violation on +z-without-fp NICK: "
            + "; ".join(violations)
        )

        await observer.send("PING :after-p10-z")
        await observer.wait_for("PONG", timeout=5.0)
    finally:
        for client in (observer, oper_c):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_p10_plus_rz_account_without_fingerprint(
    ircd_nf_compat, services
):
    """+r account param then bare +z (no fingerprint) is parsed correctly on C.

    umode_str() emits modes in userModeList order (r before z) and appends
    the account before any fingerprint.  With NETWORK_FEATURES=FALSE the
    fingerprint is omitted, so the wire is ``+irz AcctName`` with one mode
    param.  C must consume AcctName for +r and leave +z without a param —
    not treat the account as a TLS fingerprint.
    """
    c = ircd_nf_compat["c"]
    nick = "nfrztls"
    account = "RzAcct"

    oper_c = await _make_oper(c, "nfrzop")
    observer = IRCClient()
    await observer.connect(c["host"], c["port"])
    await observer.register("nfrzobs", "testuser", "Observer on C")

    try:
        # Single mode-param after +irz is the account; no fingerprint follows.
        await services.introduce_user(
            nick, modes=f"+irz {account}", realname="Account+TLS No FP"
        )
        await asyncio.sleep(0.4)

        await observer.send(f"WHOIS {nick}")
        whois = await observer.collect_until("318", timeout=5.0)
        assert any(m.command == "311" for m in whois), (
            f"{nick} missing after +irz introduce: {[m.command for m in whois]}"
        )

        accounts = [m for m in whois if m.command == "330"]
        assert accounts, (
            f"Account param was lost/misparsed as fingerprint; "
            f"WHOIS: {[m.command for m in whois]}"
        )
        assert account in accounts[0].params, accounts[0].params

        secure = [m for m in whois if m.command == "671"]
        assert secure, (
            f"IsTLS not set when +z followed +r without fingerprint; "
            f"WHOIS: {[m.command for m in whois]}"
        )

        wallops = await _collect_wallops(oper_c, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Unexpected protocol violation on +irz without fingerprint: "
            + "; ".join(violations)
        )

        await observer.send("PING :after-rz")
        await observer.wait_for("PONG", timeout=5.0)
    finally:
        for client in (observer, oper_c):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
