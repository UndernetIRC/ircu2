"""Labeled-response S2S propagation across a partially-upgraded network.

Topology (see docker-compose ircd-nf-{a,b,c}):

    A (prod release, u2.10.12.19 -- no labeled-response/BATCH S2S at all)
      -- B (tree, NETWORK_FEATURES=FALSE)
      -- C (tree, NETWORK_FEATURES=TRUE)

sendcmdto_one_hunted() (send.c) and parse_server()'s labeled-response
wrapper (parse.c) gate S2S @label= propagation on feature_bool(
FEAT_NETWORK_FEATURES) -- a purely local, per-server flag with no per-
link negotiation (same convention this codebase already uses for @time=
and other federated tags, see msg_tag_key_federated()). Each hop decides
independently whether to attach/relay the tag onward, so as long as
every hop on the path gates correctly, a foreign server that has never
heard of "label"/"batch" (A here) should never actually see one.

Two directions worth checking, since the shape of the fallback differs:

  1. A client on B (NF=FALSE) doing a labeled WHOIS-trick: B's own gate
     is off, so sendcmdto_one_hunted() never touches the local capture at
     all -- parse.c closes it as an immediate bare ACK, then the real
     (unlabeled) reply follows. That's today's ordinary, already-
     documented local-only-capture behavior for anything hunt_server_
     cmd() forwards, unrelated to A being present at all.

  2. A client on C (NF=TRUE) doing the same, routed toward a target on A
     through B: C's gate is *on*, so sendcmdto_one_hunted() hands the
     local capture off and attaches @label= to the forward, betting the
     label survives the whole path. It doesn't -- B (NF=FALSE) is a
     deliberate firewall for exactly this tag -- so the reply that
     eventually arrives carries no label and no batch, and the client
     never receives an ACK for it either.

     This is *not* a bug to fix: it's precisely the escape hatch the
     labeled-response spec itself sanctions for a response a server
     cannot honestly label ("servers might not produce a labeled
     response... clients should handle these cases as they would
     normally for a server without support for labeled responses") --
     the same allowance label_capture_abort() already relies on for the
     local overflow/interrupted-LIST cases. No ACK, no BATCH, just the
     plain reply is a legal outcome, not a broken one; there is nothing
     left dangling either (the capture is unlinked and freed at handoff,
     not orphaned). What actually matters here, and what these tests
     exist to confirm, is that this degrades cleanly: the real reply
     still arrives complete, nothing hangs, and nothing crashes or
     desyncs anywhere on the path (including the truly foreign prod
     binary on A, which must never even see an @label=/@batch= tag it
     wouldn't understand -- confirmed directly on the wire via spy_on_b,
     not just inferred from the client's own view).
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import make_cap_client
from irc_client import IRCClient
from p10_server import P10Server

pytestmark = pytest.mark.nf_compat

LABELED_CAPS = ["batch", "labeled-response"]


def _tag_value(tags: str, key: str) -> str | None:
    if not tags:
        return None
    for part in tags.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        if k == key:
            return v
    return None


def _tag_has(tags: str, key: str) -> bool:
    return _tag_value(tags, key) is not None


@pytest.fixture
async def spy_on_b(ircd_nf_compat):
    """P10 peer on B to observe what B relays toward other servers (incl. A)."""
    b = ircd_nf_compat["b"]
    spy = P10Server(
        name="spy.test.net",
        numeric=7,
        password="testpass",
        description="NF compat labeled-response wire spy",
    )
    await spy.connect(b["host"], b["server_port"])
    await spy.handshake()
    yield spy
    await spy.disconnect()


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _assert_still_alive(server: dict, nick: str):
    """Sanity check: the server in question is still responsive."""
    probe = IRCClient()
    await probe.connect(server["host"], server["port"])
    await probe.register(nick, "testuser", "Liveness Probe")
    await probe.send("PING :alive")
    pong = await probe.wait_for("PONG", timeout=5.0)
    assert pong.params[-1] == "alive", pong.raw
    await probe.send("QUIT :done")
    await probe.disconnect()


async def test_whois_trick_via_nf_false_hop_falls_back_to_immediate_ack(
    ircd_nf_compat,
):
    """Client connects directly to B (NF=FALSE) and does a labeled WHOIS
    trick for a user on A. B's own sendcmdto_one_hunted() gate is off, so
    it never touches the local capture -- the client must get an
    immediate bare ACK (today's known, safe S2S gap), never a hang.
    """
    a = ircd_nf_compat["a"]
    b = ircd_nf_compat["b"]

    target = IRCClient()
    await target.connect(a["host"], a["port"])
    await target.register("nfwhoistgt1", "testuser", "NF WHOIS Target on A")

    client = await make_cap_client(b["host"], b["port"], "nflblb1", caps=LABELED_CAPS)
    try:
        await client.send(f"@label=viaB WHOIS {target.nick} {target.nick}")

        ack = await client.wait_for("ACK", timeout=5.0)
        assert _tag_value(ack.tags, "label") == "viaB", ack.raw

        # The real reply still arrives afterward, unlabeled -- same shape
        # as any other hunt_server_cmd()-routed command when NF is off.
        lines = await client.collect_until("318", timeout=10.0)
        assert any(m.command == "311" for m in lines), [m.command for m in lines]
        for m in lines:
            assert not _tag_has(m.tags, "label"), m.raw
            assert not _tag_has(m.tags, "batch"), m.raw
    finally:
        await _cleanup(client, target)

    await _assert_still_alive(a, "nfaliveA1")
    await _assert_still_alive(b, "nfaliveB1")


async def test_whois_trick_from_nf_true_through_nf_false_to_prod_target(
    ircd_nf_compat, spy_on_b,
):
    """Client connects to C (NF=TRUE) and does a labeled WHOIS trick for a
    user on A, routed C -> B -> A. C's gate is on, so it hands its local
    capture off and attaches @label= to the forward -- but B (NF=FALSE)
    is a deliberate firewall for that tag, so it never reaches A. The
    real WHOIS reply still arrives complete, just with no ACK and no
    BATCH: the spec-sanctioned "can't honestly label this" fallback
    (label_capture_abort()'s own rationale, see send.c), not a bug.
    Confirms it degrades cleanly rather than hanging or corrupting
    anything: the reply is complete and unlabeled, and nothing crashes
    or desyncs anywhere on the path.
    """
    a = ircd_nf_compat["a"]
    b = ircd_nf_compat["b"]
    c = ircd_nf_compat["c"]

    target = IRCClient()
    await target.connect(a["host"], a["port"])
    await target.register("nfwhoistgt2", "testuser", "NF WHOIS Target on A 2")

    client = await make_cap_client(c["host"], c["port"], "nflblc1", caps=LABELED_CAPS)
    try:
        await client.send(f"@label=viaC WHOIS {target.nick} {target.nick}")

        # The real reply does arrive (routing itself is unaffected) --
        # collect up to RPL_ENDOFWHOIS.
        lines = await client.collect_until("318", timeout=10.0)
        assert any(m.command == "311" for m in lines), [m.command for m in lines]

        # No ACK and no BATCH ever showed up for this label: the
        # speculative handoff on C was never fulfilled, because B (NF=
        # FALSE) never relayed @label=/@batch= toward A in the first
        # place -- confirmed directly on the wire via spy_on_b, not just
        # inferred from the client's own view.
        for m in lines:
            assert not _tag_has(m.tags, "label"), m.raw
            assert not _tag_has(m.tags, "batch"), m.raw
        assert not any(m.command == "ACK" for m in lines), lines
        assert not any(m.command == "BATCH" for m in lines), lines

        await spy_on_b.drain_messages(0.5)
        tagged_toward_a = [
            line for line in spy_on_b.received
            if line.startswith("@") and ("label=" in line or "batch=" in line)
        ]
        assert not tagged_toward_a, (
            f"B must never relay @label=/@batch= toward a non-NETWORK_FEATURES "
            f"peer: {tagged_toward_a!r}"
        )
    finally:
        await _cleanup(client, target)

    # Nothing crashed or desynced anywhere on the path.
    await _assert_still_alive(a, "nfaliveA2")
    await _assert_still_alive(b, "nfaliveB2")
    await _assert_still_alive(c, "nfaliveC2")
