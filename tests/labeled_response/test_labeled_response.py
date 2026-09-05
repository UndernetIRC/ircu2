"""IRCv3 labeled-response / batch integration tests.

Exercises the client-facing behavior introduced across parse.c (the
labeled-response dispatch wrapper around a single command's handler
call), send.c (the label_capture_* deferred-output state machine),
m_cap.c (the batch <- labeled-response capability dependency), and
msg_tag.c (label=/batch= tag formatting).
"""

from __future__ import annotations

import pytest

from cap_helpers import make_cap_client
from irc_client import IRCClient

from .helpers import LABELED_CAPS, escape_tag_value, tag_has, tag_value

pytestmark = pytest.mark.single_server


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _labeled_client(hub: dict, nick: str, extra_caps: list[str] | None = None) -> IRCClient:
    caps = LABELED_CAPS + (extra_caps or [])
    return await make_cap_client(hub["host"], hub["port"], nick, caps=caps)


async def _plain_client(hub: dict, nick: str) -> IRCClient:
    return await make_cap_client(hub["host"], hub["port"], nick, caps=None)


# --- Core response shapes ----------------------------------------------------


async def test_ack_for_command_with_no_reply(ircd_hub):
    """A labeled command that normally produces no reply gets a bare ACK.

    NOTICE is used (rather than PRIVMSG) because it is specified to never
    generate an automatic reply, so this is unambiguous: any bare ACK the
    sender receives can only be the label acknowledgment.
    """
    sender = await _labeled_client(ircd_hub, "lblack1")
    target = await _plain_client(ircd_hub, "lblack2")
    try:
        await sender.send(f"@label=ack1 NOTICE {target.nick} :hi there")

        ack = await sender.wait_for("ACK", timeout=5.0)
        assert tag_value(ack.tags, "label") == "ack1", ack.raw

        await sender.assert_no_message("NOTICE", timeout=1.0)

        delivered = await target.wait_for_user_msg("NOTICE", timeout=5.0)
        assert delivered.params[-1] == "hi there", delivered.raw
    finally:
        await _cleanup(sender, target)


async def test_single_line_reply_carries_label_directly(ircd_hub):
    """A one-line reply (PONG) gets label= on that line -- no BATCH wrapper."""
    client = await _labeled_client(ircd_hub, "lblping1")
    try:
        await client.send("@label=ping1 PING :hello")

        pong = await client.wait_for("PONG", timeout=5.0)
        assert tag_value(pong.tags, "label") == "ping1", pong.raw

        await client.assert_no_message("BATCH", timeout=1.0)
    finally:
        await _cleanup(client)


async def test_multiline_reply_wrapped_in_batch(ircd_hub):
    """A multi-line reply (WHOIS) is wrapped in a labeled-response BATCH.

    Per spec: the BATCH open line alone carries label=; every line inside
    carries batch=<ref>; the close line carries neither the sender's data
    nor the label.
    """
    target = await _plain_client(ircd_hub, "lblwhoT")
    client = await _labeled_client(ircd_hub, "lblwho1")
    try:
        await client.send(f"@label=who1 WHOIS {target.nick}")

        opening = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening.tags, "label") == "who1", opening.raw
        assert len(opening.params) >= 2, opening.raw
        ref_param, batch_type = opening.params[0], opening.params[1]
        assert ref_param.startswith("+"), opening.raw
        ref = ref_param[1:]
        assert batch_type == "labeled-response", opening.raw

        lines = await client.collect_until("BATCH", timeout=5.0)
        closing = lines[-1]
        assert closing.params[0] == f"-{ref}", closing.raw
        assert not tag_has(closing.tags, "label"), closing.raw

        # Select by batch= tag, not by wire position: unrelated traffic
        # (e.g. a registration-time IPcheck notice arriving late) can
        # legitimately interleave on the wire between the open and close
        # lines without being part of this batch.
        rest = lines[:-1]
        body = [m for m in rest if tag_value(m.tags, "batch") == ref]
        assert body, "expected at least one WHOIS numeric inside the batch"
        for msg in body:
            # Only the opening BATCH line carries the label (spec: "exactly
            # one logical message").
            assert not tag_has(msg.tags, "label"), msg.raw
        assert any(m.command == "318" for m in body), [m.command for m in body]

        stray = [m for m in rest if m not in body]
        for msg in stray:
            assert tag_value(msg.tags, "batch") != ref, msg.raw
            assert not tag_has(msg.tags, "label"), msg.raw
    finally:
        await _cleanup(client, target)


# --- Label tag mechanics ------------------------------------------------------


async def test_label_value_roundtrips_with_escaped_chars(ircd_hub):
    """A label value needing tag-escaping survives the round trip intact."""
    client = await _labeled_client(ircd_hub, "lblesc1")
    try:
        raw_value = "a b;c\\d"
        wire_value = escape_tag_value(raw_value)
        await client.send(f"@label={wire_value} PING :x")

        pong = await client.wait_for("PONG", timeout=5.0)
        assert tag_value(pong.tags, "label", unescape=True) == raw_value, pong.raw
    finally:
        await _cleanup(client)


async def test_label_value_at_max_length_is_honored(ircd_hub):
    """Exactly 64 bytes (the spec maximum) is accepted and echoed back."""
    client = await _labeled_client(ircd_hub, "lbllen1")
    try:
        label = "x" * 64
        await client.send(f"@label={label} PING :x")

        pong = await client.wait_for("PONG", timeout=5.0)
        assert tag_value(pong.tags, "label") == label, pong.raw
    finally:
        await _cleanup(client)


async def test_label_value_over_max_length_is_ignored(ircd_hub):
    """65 bytes exceeds the spec maximum: the command still runs, unlabeled."""
    client = await _labeled_client(ircd_hub, "lbllen2")
    try:
        label = "x" * 65
        await client.send(f"@label={label} PING :x")

        pong = await client.wait_for("PONG", timeout=5.0)
        assert not tag_has(pong.tags, "label"), pong.raw
    finally:
        await _cleanup(client)


async def test_empty_label_value_is_ignored(ircd_hub):
    """A `label` tag with no value does not arm labeling."""
    client = await _labeled_client(ircd_hub, "lblempty1")
    try:
        await client.send("@label PING :x")

        pong = await client.wait_for("PONG", timeout=5.0)
        assert not tag_has(pong.tags, "label"), pong.raw
    finally:
        await _cleanup(client)


async def test_unlabeled_command_gets_no_stray_tags(ircd_hub):
    """With both caps active but no label= sent, replies stay plain."""
    client = await _labeled_client(ircd_hub, "lblplain1")
    try:
        await client.send("PING :x")

        pong = await client.wait_for("PONG", timeout=5.0)
        assert not tag_has(pong.tags, "label"), pong.raw
        assert not tag_has(pong.tags, "batch"), pong.raw

        await client.assert_no_message("ACK", timeout=1.0)
        await client.assert_no_message("BATCH", timeout=1.0)
    finally:
        await _cleanup(client)


# --- CAP dependency: labeled-response requires batch --------------------------


async def test_cap_req_labeled_response_without_batch_is_naked(ircd_hub):
    client = await _plain_client(ircd_hub, "lblcap1")
    try:
        await client.send("CAP REQ :labeled-response")
        reply = await client.wait_for("CAP", timeout=5.0)
        assert reply.params[1] == "NAK", reply.raw
    finally:
        await _cleanup(client)


async def test_cap_req_batch_and_labeled_response_together_acks(ircd_hub):
    client = await _plain_client(ircd_hub, "lblcap2")
    try:
        await client.send("CAP REQ :batch labeled-response")
        reply = await client.wait_for("CAP", timeout=5.0)
        assert reply.params[1] == "ACK", reply.raw
        assert set(reply.params[-1].split()) == {"batch", "labeled-response"}, reply.raw
    finally:
        await _cleanup(client)


async def test_cap_req_remove_batch_while_labeled_response_active_is_naked(ircd_hub):
    """Dropping `batch` while `labeled-response` is still active must NAK
    (dependency), and the rejection must be atomic: labeled-response keeps
    working afterward."""
    client = await _plain_client(ircd_hub, "lblcap3")
    try:
        await client.send("CAP REQ :batch labeled-response")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK", ack.raw

        await client.send("CAP REQ :-batch")
        reply = await client.wait_for("CAP", timeout=5.0)
        assert reply.params[1] == "NAK", reply.raw

        await client.send("@label=stillon PING :x")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert tag_value(pong.tags, "label") == "stillon", pong.raw
    finally:
        await _cleanup(client)


# --- Regression: parse.c must not touch a Client freed by its own handler ----


async def test_labeled_quit_does_not_crash_or_wedge_server(ircd_hub):
    """A labeled QUIT frees its own Client synchronously (handler returns
    CPTR_KILLED, and exit_client -> ... -> free_client() runs before
    parse_client()'s caller regains control).

    parse_client() used to call label_capture_finish(cptr) unconditionally
    after the handler returned, including on this path: a use-after-free
    on the Client struct that was just freed, and a stale
    label_capture_target left pointing at freed memory that could
    silently swallow a *later, unrelated* connection's entire output if
    its Client struct happened to reuse the same memory slot. Neither
    symptom is guaranteed to be a hard crash, so liveness is probed from
    several fresh connections afterward rather than just checking that
    this connection's socket closes.
    """
    victim = await _labeled_client(ircd_hub, "lblquit1")
    await victim.send("@label=diediedie QUIT :goodbye")
    try:
        await victim.disconnect()
    except Exception:
        pass

    # Hammer fresh connections right after the free, to maximize the odds
    # of a reused Client slot if label_capture_target were left dangling.
    for i in range(8):
        probe = IRCClient()
        await probe.connect(ircd_hub["host"], ircd_hub["port"])
        try:
            await probe.send(f"PING :liveness{i}")
            # Unregistered PING is rejected with 451, not PONG -- proves the
            # connection is alive and being processed, and (critically)
            # that this reply wasn't silently captured into someone else's
            # abandoned label buffer.
            reply = await probe.wait_for("451", timeout=5.0)
            assert reply.command == "451"
        finally:
            await probe.disconnect()

    # And a full registration + PING/PONG round trip, for good measure.
    survivor = await _plain_client(ircd_hub, "lblquitsurvivor")
    try:
        await survivor.send("PING :after-quit")
        pong = await survivor.wait_for("PONG", timeout=5.0)
        assert pong.params[-1] == "after-quit", pong.raw
    finally:
        await _cleanup(survivor)


# --- LIST: happy path for the async-continuation guard ------------------------


async def test_small_list_is_fully_batched(ircd_hub):
    """A LIST that finishes synchronously still gets a complete, closed batch.

    list_next_channels() can yield across event-loop ticks for a large
    reply, resuming later from outside parse_client()'s call stack; when
    that happens parse.c detects it via cli_listing() and releases the
    partial capture unlabeled rather than closing a batch that understates
    the real reply. With only a couple of channels the whole reply is
    produced in the single synchronous dispatch, so this must still take
    the normal, fully-labeled path -- this guards against that check
    misfiring on the common case.
    """
    ch1 = await _plain_client(ircd_hub, "lbllist1")
    ch2 = await _plain_client(ircd_hub, "lbllist2")
    await ch1.send("JOIN #lbltest1")
    await ch1.wait_for("JOIN", timeout=5.0)
    await ch2.send("JOIN #lbltest2")
    await ch2.wait_for("JOIN", timeout=5.0)

    client = await _labeled_client(ircd_hub, "lbllist3")
    try:
        await client.send("@label=list1 LIST")

        opening = await client.wait_for("BATCH", timeout=10.0)
        assert tag_value(opening.tags, "label") == "list1", opening.raw
        assert opening.params[1] == "labeled-response", opening.raw
        ref = opening.params[0][1:]

        lines = await client.collect_until("BATCH", timeout=10.0)
        closing = lines[-1]
        assert closing.params[0] == f"-{ref}", closing.raw

        # Select by batch= tag, not by wire position: unrelated traffic
        # (e.g. a registration-time IPcheck notice arriving late) can
        # legitimately interleave on the wire without being part of this
        # batch.
        body = [m for m in lines[:-1] if tag_value(m.tags, "batch") == ref]
        commands = [m.command for m in body]
        assert "323" in commands, commands  # RPL_LISTEND

        # Nothing about this LIST leaks out after the batch closes.
        await client.assert_no_message("322", timeout=1.0)  # RPL_LIST
        await client.assert_no_message("323", timeout=1.0)  # RPL_LISTEND
    finally:
        await _cleanup(client, ch1, ch2)
