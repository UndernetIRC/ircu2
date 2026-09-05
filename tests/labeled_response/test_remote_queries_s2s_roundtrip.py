"""Labeled-response across a genuine S2S round trip (real hub + leaf).

Two commands force hunt_server_cmd() to route to a *different* server and
return immediately with zero local output on the origin: `WHOIS nick nick`
(the classic "whois trick" -- a repeated second parameter forces routing
to the target's own home server, rather than answering from this
server's already-synced cache the way plain `WHOIS nick` does) and
`STATS <letter> <server>`.

The real reply is generated later, asynchronously, by the remote server.
Labeled-response makes this work end to end:

  - hunt_server_cmd() (s_user.c) forwards the command via
    sendcmdto_one_hunted() (send.c), which propagates @label= on the
    forwarded line (gated on FEAT_NETWORK_FEATURES -- msg_tag_key_
    federated(), msg_tag.c) and silently hands the *local* capture off
    (no premature ACK) instead of letting parse.c finish it empty.
  - parse_server()'s own labeled-response wrapper (parse.c) recognizes
    the inbound @label= on the far side, and runs the *same* capture
    machinery as a local command -- keyed to the original remote
    requester (label_capture_start()/finish() key off cli_from(), which
    aliases the shared S2S link Connection either way).
  - The answering server's own BATCH open/close and batch=<ref> tags are
    addressed by target numnick over S2S (ms_batch()/ms_ack(),
    m_batch.c) and relayed hop by hop -- exactly like do_numeric()
    already relays ordinary numerics -- until they reach the original
    requester's actual connection, where they land in plain client-
    facing form.

Each scenario is covered at both one hop (client on the hub, target on a
directly-linked leaf) and two hops (client on leaf1, target on leaf2 --
leaf1 -> hub -> leaf2, so the request and reply both genuinely cross two
real S2S links). Also covered: the flip side, that unrelated traffic on
the same connection isn't disturbed while a remote reply is in flight.
"""

from __future__ import annotations

import pytest

from cap_helpers import make_cap_client, oper_up
from irc_client import IRCClient

from .helpers import LABELED_CAPS, tag_has, tag_value

pytestmark = pytest.mark.multi_server


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _assert_batched_reply(client, label, expect_command):
    """Collect a labeled BATCH and assert its shape: label on the open
    line only, batch=ref on every body line, `expect_command` present
    somewhere in the body.

    Selects body lines by their batch=ref tag rather than positionally
    (everything between the open and close lines) -- unrelated traffic
    (e.g. a global oper-announce NOTICE from this same connection's own
    OPER, or anything else server-injected) can legitimately interleave
    on the wire without being part of this batch, same rationale as
    test_labeled_response.py's test_multiline_reply_wrapped_in_batch.
    """
    opening = await client.wait_for("BATCH", timeout=10.0)
    assert tag_value(opening.tags, "label") == label, opening.raw
    assert opening.params[1] == "labeled-response", opening.raw
    ref = opening.params[0][1:]

    lines = await client.collect_until("BATCH", timeout=10.0)
    closing = lines[-1]
    assert closing.params[0] == f"-{ref}", closing.raw
    assert not tag_has(closing.tags, "label"), closing.raw

    rest = lines[:-1]
    body = [m for m in rest if tag_value(m.tags, "batch") == ref]
    assert body, "expected at least one line inside the batch"
    for m in body:
        assert not tag_has(m.tags, "label"), m.raw
    assert any(m.command == expect_command for m in body), [m.command for m in body]

    stray = [m for m in rest if m not in body]
    for m in stray:
        assert tag_value(m.tags, "batch") != ref, m.raw
        assert not tag_has(m.tags, "label"), m.raw

    await client.assert_no_message("ACK", timeout=1.0)
    return ref, body


async def test_remote_whois_trick_reply_is_properly_labeled(ircd_network):
    """`WHOIS nick nick` against a user on a real, directly-linked leaf:
    the leaf answers on the original requester's behalf and its BATCH-
    wrapped reply is relayed straight through the hub to the client,
    correctly labeled -- no premature ACK, no stray unlabeled traffic.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    target = IRCClient()
    await target.connect(leaf1["host"], leaf1["port"])
    await target.register("rwhoistgt", "testuser", "Remote WHOIS Target")

    client = await make_cap_client(hub["host"], hub["port"], "lblrwho3", caps=LABELED_CAPS)
    try:
        await oper_up(client)

        await client.send(f"@label=rwho3 WHOIS {target.nick} {target.nick}")

        ref, body = await _assert_batched_reply(client, "rwho3", "311")
        whoisuser = next(m for m in body if m.command == "311")
        assert whoisuser.params[1] == target.nick, whoisuser.raw
        assert any(m.command == "318" for m in body), [m.command for m in body]
    finally:
        await _cleanup(client, target)


async def test_remote_stats_reply_is_properly_labeled(ircd_network):
    """`STATS <letter> <server>` aimed at a real, directly-linked leaf:
    same correct end-to-end labeling as the WHOIS trick above, for a
    different hunt_server_cmd() consumer.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    client = await make_cap_client(hub["host"], hub["port"], "lblrstat1", caps=LABELED_CAPS)
    try:
        await oper_up(client)

        await client.send(f"@label=rstats1 STATS u {leaf1['name']}")

        await _assert_batched_reply(client, "rstats1", "219")  # RPL_ENDOFSTATS
    finally:
        await _cleanup(client)


async def test_interim_traffic_not_mislabeled_while_remote_reply_in_flight(ircd_network):
    """Edge case: while a remote-routed labeled command's real reply is
    still in flight from the leaf, *other* traffic on the same connection
    must not be swept into it, and a fresh labeled command must resolve
    entirely on its own -- both must eventually get their own, correctly
    separated labeled replies.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    target = IRCClient()
    await target.connect(leaf1["host"], leaf1["port"])
    await target.register("rwhoistgt2", "testuser", "Remote WHOIS Target 2")

    client = await make_cap_client(hub["host"], hub["port"], "lblinterim1", caps=LABELED_CAPS)
    try:
        await oper_up(client)

        await client.send(f"@label=pending WHOIS {target.nick} {target.nick}")

        # Fire a second, unrelated labeled command immediately afterward,
        # before the first's real S2S reply has necessarily arrived.
        await client.send("@label=fresh PING :hello")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.params[-1] == "hello", pong.raw
        assert tag_value(pong.tags, "label") == "fresh", pong.raw
        assert not tag_has(pong.tags, "batch"), pong.raw

        # The WHOIS trick's own reply still shows up, correctly labeled
        # "pending" -- not merged into "fresh", not silently dropped.
        _, body = await _assert_batched_reply(client, "pending", "311")
        for m in body:
            assert tag_value(m.tags, "label") != "fresh", m.raw
    finally:
        await _cleanup(client, target)


# --- Same three scenarios, genuinely two hops: client on leaf1, target on
# leaf2 (leaf1 -> hub -> leaf2). ------------------------------------------


async def test_remote_whois_trick_reply_is_properly_labeled_two_hops(ircd_network):
    """Same as test_remote_whois_trick_reply_is_properly_labeled, but the
    querying client is on leaf1 and the target is on leaf2: the request
    and its BATCH-wrapped reply both cross two real S2S links (leaf1 ->
    hub, hub -> leaf2) rather than one.
    """
    leaf1 = ircd_network["leaf1"]
    leaf2 = ircd_network["leaf2"]

    target = IRCClient()
    await target.connect(leaf2["host"], leaf2["port"])
    await target.register("rwhoistgt3", "testuser", "Remote WHOIS Target (2 hops)")

    client = await make_cap_client(leaf1["host"], leaf1["port"], "lblrwho4", caps=LABELED_CAPS)
    try:
        await oper_up(client)

        await client.send(f"@label=rwho4 WHOIS {target.nick} {target.nick}")

        ref, body = await _assert_batched_reply(client, "rwho4", "311")
        whoisuser = next(m for m in body if m.command == "311")
        assert whoisuser.params[1] == target.nick, whoisuser.raw
        assert any(m.command == "318" for m in body), [m.command for m in body]
    finally:
        await _cleanup(client, target)


async def test_remote_stats_reply_is_properly_labeled_two_hops(ircd_network):
    """Same as test_remote_stats_reply_is_properly_labeled, but the
    querying client is on leaf1 and STATS targets leaf2 by name (leaf1 ->
    hub -> leaf2).
    """
    leaf1 = ircd_network["leaf1"]
    leaf2 = ircd_network["leaf2"]

    client = await make_cap_client(leaf1["host"], leaf1["port"], "lblrstat2", caps=LABELED_CAPS)
    try:
        await oper_up(client)

        await client.send(f"@label=rstats2 STATS u {leaf2['name']}")

        await _assert_batched_reply(client, "rstats2", "219")
    finally:
        await _cleanup(client)


async def test_interim_traffic_not_mislabeled_while_remote_reply_in_flight_two_hops(
    ircd_network,
):
    """Same edge case as test_interim_traffic_not_mislabeled_while_remote_
    reply_in_flight, but genuinely two hops (leaf1 -> hub -> leaf2)."""
    leaf1 = ircd_network["leaf1"]
    leaf2 = ircd_network["leaf2"]

    target = IRCClient()
    await target.connect(leaf2["host"], leaf2["port"])
    await target.register("rwhoistgt4", "testuser", "Remote WHOIS Target 2 (2 hops)")

    client = await make_cap_client(leaf1["host"], leaf1["port"], "lblinterim2", caps=LABELED_CAPS)
    try:
        await oper_up(client)

        await client.send(f"@label=pending2 WHOIS {target.nick} {target.nick}")

        # Fire a second, unrelated labeled command immediately afterward,
        # before the first's real (two-hop) S2S reply has necessarily
        # arrived.
        await client.send("@label=fresh2 PING :hello")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.params[-1] == "hello", pong.raw
        assert tag_value(pong.tags, "label") == "fresh2", pong.raw
        assert not tag_has(pong.tags, "batch"), pong.raw

        _, body = await _assert_batched_reply(client, "pending2", "311")
        for m in body:
            assert tag_value(m.tags, "label") != "fresh2", m.raw
    finally:
        await _cleanup(client, target)
