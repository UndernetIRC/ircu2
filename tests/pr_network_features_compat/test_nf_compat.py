"""NETWORK_FEATURES rolling-upgrade compat tests.

Topology (see docker-compose ircd-nf-{a,b,c}):

    A (prod release, u2.10.12.19) — B (tree, NETWORK_FEATURES=FALSE) — C (tree, NETWORK_FEATURES=TRUE)
                                                                              ^
                                                                       services (P10)

Flag-only / same-name ACCOUNT updates for already-authed users confuse
peers on u2.10.12.19 and earlier: a second ACCOUNT for an already-authed
nick is a hard protocol_violation (WALLOPS to +g opers).  u2.10.13.0
tolerates same-name updates locally (for flag changes); with
NETWORK_FEATURES=FALSE, B must not relay a second AC toward peers —
assert that on the wire via spy_on_b, not only via A's non-violation.
On C (NF=TRUE), a flag update after bare-name registration must still
relay id+flags (spy_on_c); otherwise flags die after one hop even on a
fully upgraded path.

Remote OPMODE +x and +z TLS fingerprint tokens on NICK/umode bursts are
newer extensions.  With NETWORK_FEATURES=FALSE on the middle hop B, those
must not reach A.

TOPIC lines from current servers include a topic-who field that older
``ms_topic`` never stored; topic text remains ``parv[parc-1]``, so prod
must accept TOPIC-with-who without desync.  First-time ACCOUNT with
acc_id/acc_flags likewise reaches A (id is treated as the old timestamp).

TLS clients on B still get umode +z locally, but B omits the fingerprint
parameter when introducing them toward peers.  C (NF=TRUE) must accept that
+z-without-fingerprint NICK without crashing or protocol-violating.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server, strip_msg_tags

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


@pytest.fixture
async def spy_on_c(ircd_nf_compat):
    """P10 peer on C to observe what C relays (NF=TRUE hop before B)."""
    c = ircd_nf_compat["c"]
    spy = P10Server(
        name="spyc.test.net",
        numeric=6,
        password="testpass",
        description="NF compat wire spy on C",
    )
    await spy.connect(c["host"], c["server_port"])
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


def _ac_lines_for_numnick(lines: list[str], numnick: str) -> list[str]:
    """P10 ACCOUNT (AC) lines whose target numnick matches."""
    out = []
    for line in lines:
        parts = strip_msg_tags(line).split()
        # <source> AC <target_numnick> <account> ...
        if len(parts) >= 3 and parts[1] == "AC" and parts[2] == numnick:
            out.append(line)
    return out


async def _collect_ac_from_spy(
    spy: P10Server, numnick: str, seconds: float = 2.0
) -> list[str]:
    """Drain spy traffic for a window and return AC lines for ``numnick``."""
    before = len(spy.received)
    deadline = asyncio.get_running_loop().time() + seconds
    while asyncio.get_running_loop().time() < deadline:
        remaining = deadline - asyncio.get_running_loop().time()
        try:
            await spy.drain_messages(timeout=min(0.4, max(0.05, remaining)))
        except (asyncio.TimeoutError, TimeoutError):
            pass
        await asyncio.sleep(0.05)
    return _ac_lines_for_numnick(spy.received[before:], numnick)


def _topic_lines_for_chan(lines: list[str], chan: str) -> list[str]:
    """P10 TOPIC (T) lines mentioning ``chan``."""
    out = []
    chan_l = chan.lower()
    for line in lines:
        parts = strip_msg_tags(line).split()
        if len(parts) >= 3 and parts[1] == "T" and parts[2].lower() == chan_l:
            out.append(line)
    return out


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
    ircd_nf_compat, services, spy_on_b
):
    """Second ACCOUNT (flag update) must not leave B toward peers (incl. A).

    u2.10.12.19 and earlier protocol_violate on any ACCOUNT for an
    already-authed nick.  u2.10.13.0 tolerates same-name updates locally;
    assert the NETWORK_FEATURES=FALSE gate on the wire via spy_on_b:
    after the first AC, B must relay no further AC for that numnick.
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
        first_acs = await _collect_ac_from_spy(spy_on_b, numnick, seconds=2.5)
        assert first_acs, (
            f"Spy on B never saw first-time AC for {numnick}; "
            f"recent={spy_on_b.received[-20:]!r}"
        )

        await user.send("WHOIS nfuser1")
        whois = await user.collect_until("318", timeout=5.0)
        accounts = [m for m in whois if m.command == "330"]
        assert accounts, (
            "First-time ACCOUNT should reach prod A "
            f"(WHOIS messages: {[m.command for m in whois]})"
        )
        assert "NfAcct1" in accounts[0].params

        await _drain(oper, 0.3)
        await spy_on_b.drain_messages(0.3)
        ac_count_before = len(_ac_lines_for_numnick(spy_on_b.received, numnick))

        # Flag-only / same-name update: u2.10.13.0 accepts it locally.
        # B must not relay it (gate).  Prod ≤.12.19 would protocol_violate if it arrived.
        await services.send_account(numnick, "NfAcct1", acc_id=1, acc_flags=42)
        late_acs = await _collect_ac_from_spy(spy_on_b, numnick, seconds=2.5)
        ac_count_after = len(_ac_lines_for_numnick(spy_on_b.received, numnick))

        assert not late_acs and ac_count_after == ac_count_before, (
            "B relayed a second AC for an already-authed user toward peers "
            f"(incl. prod A): before={ac_count_before} after={ac_count_after} "
            f"late={late_acs!r}"
        )

        # Prod A must not see a Protocol Violation WALLOPS either.
        wallops = await _collect_wallops(oper, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "ACCOUNT flag update reached prod A: " + "; ".join(violations)
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


async def test_flag_update_after_bare_account_relays_id_and_flags(
    ircd_nf_compat, services, spy_on_b, spy_on_c
):
    """Flag update after bare ACCOUNT must keep id+flags across the NF=TRUE hop.

    Topology: A(prod) — B(NF=FALSE) — C(NF=TRUE) ← services / spy_on_c;
    spy_on_b watches B's outbound toward A.

    Registration without acc_id left stored id at 0; a later same-name
    update that supplies id+flags used to be re-emitted as bare ``%C %s``
    because the relay format keyed on stored acc_id and the already-
    account path never adopted a first-seen id.  On C (NF=TRUE) the full
    line must leave toward peers (spy_on_c).  B still gates it (spy_on_b
    sees no second AC), so prod A stays quiet.
    """
    a = ircd_nf_compat["a"]

    user = IRCClient()
    await user.connect(a["host"], a["port"])
    await user.register("flghop1", "testuser", "Flag Hop User")

    oper = await _make_oper(a, "flghoper")

    try:
        numnick = await services.wait_for_user("flghop1", timeout=10.0)

        # Bare registration must traverse C → B → A.
        await services.send_account(numnick, "BareAcct")
        deadline = asyncio.get_running_loop().time() + 3.0
        first_on_c: list[str] = []
        first_on_b: list[str] = []
        while asyncio.get_running_loop().time() < deadline:
            await spy_on_c.drain_messages(0.3)
            await spy_on_b.drain_messages(0.3)
            first_on_c = _ac_lines_for_numnick(spy_on_c.received, numnick)
            first_on_b = _ac_lines_for_numnick(spy_on_b.received, numnick)
            if first_on_c and first_on_b:
                break
            await asyncio.sleep(0.1)

        assert first_on_c, (
            f"Spy on C never saw first-time AC for {numnick}; "
            f"recent={spy_on_c.received[-20:]!r}"
        )
        first_parts = strip_msg_tags(first_on_c[-1]).split()
        assert first_parts[3] == "BareAcct"
        assert len(first_parts) == 4, (
            f"First AC should be bare name on C's wire: {first_on_c[-1]!r}"
        )
        assert first_on_b, (
            f"Spy on B never saw first-time AC for {numnick} "
            f"(C→B→A hop); recent={spy_on_b.received[-20:]!r}"
        )

        await user.send("WHOIS flghop1")
        whois = await user.collect_until("318", timeout=5.0)
        accounts = [m for m in whois if m.command == "330"]
        assert accounts and "BareAcct" in accounts[0].params, (
            f"Bare ACCOUNT should reach prod A: {[m.raw for m in whois]}"
        )

        await spy_on_c.drain_messages(0.3)
        await spy_on_b.drain_messages(0.3)
        c_before = len(spy_on_c.received)
        b_count_before = len(_ac_lines_for_numnick(spy_on_b.received, numnick))

        # Same-name update with first-seen id+flags: C must relay the full
        # line; B must not forward it toward prod.
        await services.send_account(numnick, "BareAcct", acc_id=42, acc_flags=7)
        late_on_c = await _collect_ac_from_spy(spy_on_c, numnick, seconds=2.5)
        # _collect starts from current len; use slice from c_before if empty race
        if not late_on_c:
            late_on_c = _ac_lines_for_numnick(spy_on_c.received[c_before:], numnick)
        assert late_on_c, (
            f"Spy on C never saw flag-update AC for {numnick}: "
            f"{spy_on_c.received[c_before:]!r}"
        )
        parts = strip_msg_tags(late_on_c[-1]).split()
        assert parts[3:] == ["BareAcct", "42", "7"], (
            f"C must relay account id and flags after bare registration, "
            f"got {late_on_c[-1]!r}"
        )

        late_on_b = await _collect_ac_from_spy(spy_on_b, numnick, seconds=2.0)
        b_count_after = len(_ac_lines_for_numnick(spy_on_b.received, numnick))
        assert not late_on_b and b_count_after == b_count_before, (
            "B must not relay the flag update toward prod A: "
            f"before={b_count_before} after={b_count_after} late={late_on_b!r}"
        )

        wallops = await _collect_wallops(oper, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Flag update reached prod A: " + "; ".join(violations)
        )

        await user.send("PING :after-flag-hop")
        await user.wait_for("PONG", timeout=5.0)
    finally:
        for client in (user, oper):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_first_account_with_flags_reaches_prod(
    ircd_nf_compat, services, spy_on_b
):
    """First-time ACCOUNT with id+flags may pass flags through NF=FALSE to prod.

    Design: do not strip acc_id on first-time relays — .19 stores parv[3] as
    acc_create (legacy "logged in since").  The open question was whether the
    4th param (acc_flags) is safe.  .19's ms_account only reads parc>3 for
    acc_create and ignores further params, so flags should be harmless.

    Assert on spy_on_b that B (NF=FALSE) still relays the full
    ``account id flags`` line toward peers, and that prod A accepts it
    (account name visible, no protocol_violation, link healthy).
    """
    a = ircd_nf_compat["a"]

    user = IRCClient()
    await user.connect(a["host"], a["port"])
    await user.register("flguser1", "testuser", "Flag User")

    oper = await _make_oper(a, "flgoper1")

    try:
        numnick = await services.wait_for_user("flguser1", timeout=10.0)
        await services.send_account(numnick, "FlagAcct", acc_id=99, acc_flags=5)
        acs = await _collect_ac_from_spy(spy_on_b, numnick, seconds=2.5)
        assert acs, f"Spy on B never saw first AC with flags for {numnick}"

        # B must forward id+flags (not strip flags for ≤.19).
        matched = [
            line for line in acs
            if strip_msg_tags(line).split()[3:] == ["FlagAcct", "99", "5"]
        ]
        assert matched, (
            "Expected full account/id/flags on B's wire toward prod, got: "
            f"{[strip_msg_tags(l) for l in acs]!r}"
        )

        await user.send("WHOIS flguser1")
        whois = await user.collect_until("318", timeout=5.0)
        accounts = [m for m in whois if m.command == "330"]
        assert accounts and "FlagAcct" in accounts[0].params, (
            f"First ACCOUNT+flags should reach prod A: {[m.raw for m in whois]}"
        )

        wallops = await _collect_wallops(oper, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Prod protocol-violated on first ACCOUNT with flags: "
            + "; ".join(violations)
        )

        await user.send("PING :after-flags")
        await user.wait_for("PONG", timeout=5.0)
    finally:
        for client in (user, oper):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_topic_with_who_accepted_by_prod(ircd_nf_compat, spy_on_b):
    """TOPIC carrying topic-who must reach prod without protocol_violation.

    Current servers send ``TOPIC chan chanTS topicTS who :text``.  Older
    ``ms_topic`` takes the topic from ``parv[parc-1]`` and ignores the
    who field; prod must keep the topic text and stay linked.
    """
    a = ircd_nf_compat["a"]
    c = ircd_nf_compat["c"]
    chan = "#nf_topic_who"

    setter = IRCClient()
    await setter.connect(c["host"], c["port"])
    await setter.register("twhoset", "testuser", "Topic Setter")

    prod_user = IRCClient()
    await prod_user.connect(a["host"], a["port"])
    await prod_user.register("twhousr", "testuser", "Topic Prod User")

    oper = await _make_oper(a, "twhooper")

    try:
        await setter.send(f"JOIN {chan}")
        await setter.wait_for("JOIN")
        await asyncio.sleep(0.4)

        await spy_on_b.drain_messages(0.3)
        before = len(spy_on_b.received)

        await setter.send(f"TOPIC {chan} :who-compat topic")
        await asyncio.sleep(0.8)
        await spy_on_b.drain_messages(1.0)

        topic_lines = _topic_lines_for_chan(spy_on_b.received[before:], chan)
        assert topic_lines, (
            f"Spy on B never saw TOPIC for {chan}: {spy_on_b.received[before:]!r}"
        )
        matched = [l for l in topic_lines if "who-compat topic" in l]
        assert matched, f"TOPIC text missing on wire: {topic_lines!r}"
        # Format: <src> T <chan> <chanTS> <topicTS> <who> :<topic>
        parts = strip_msg_tags(matched[0]).split()
        assert len(parts) >= 6, f"TOPIC-with-who too short: {matched[0]!r}"
        assert parts[5] == "twhoset", (
            f"Expected who=twhoset on wire, got {parts[5]!r} in {matched[0]!r}"
        )

        await prod_user.send(f"JOIN {chan}")
        msgs = await prod_user.collect_until("366", timeout=8.0)
        topic_msgs = [m for m in msgs if m.command == "332"]
        assert topic_msgs, (
            f"Prod client should receive RPL_TOPIC, got {[m.command for m in msgs]}"
        )
        assert topic_msgs[0].params[-1] == "who-compat topic"

        wallops = await _collect_wallops(oper, seconds=1.5)
        violations = [w for w in wallops if "Protocol Violation" in w]
        assert not violations, (
            "Prod protocol-violated on TOPIC-with-who: " + "; ".join(violations)
        )

        await prod_user.send("PING :after-topic")
        await prod_user.wait_for("PONG", timeout=5.0)
    finally:
        for client in (setter, prod_user, oper):
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
