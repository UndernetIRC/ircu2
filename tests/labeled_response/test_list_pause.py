"""Labeled LIST at scale.

Unlike every other labeled command (which defers its output in memory
and decides ACK vs. single-line vs. BATCH only once it's known to be
complete -- see label_capture_finish() in send.c), a labeled LIST commits
to BATCH immediately: m_list.c calls label_capture_stream_active() the
moment it starts a genuine paginated listing, which emits "BATCH +ref
labeled-response" right away and marks the capture "streaming". From
then on, every line list_next_channels() (hash.c) sends is re-tagged
batch=ref and put on the wire as it's produced -- nothing is buffered,
so there is nothing to decide later and nothing that can overflow. LIST
is unconditionally multi-line (at minimum RPL_LISTEND) and may span many
event-loop ticks, so there was never a real decision to defer in the
first place.

This has a real consequence for pacing: streamed output goes through the
*real* send_buffer()/cli_sendQ() path (see label_capture_append()'s
streaming branch), not an in-memory buffer that bypasses it. So a
labeled LIST now genuinely pauses and resumes across ticks exactly the
way an unlabeled one always could -- list_next_channels()'s own sendQ-
based pause check sees real, growing output either way. label_capture_
reopen() re-activates the streaming window for each continuation tick,
same as it already did for the (now removed) buffered case.

So there are three scales worth testing here:
  - A LIST comfortably under one connection's sendq (some pause/resume
    ticks are plausible but not guaranteed): confirms the ordinary case
    produces one complete, correctly-closed batch regardless.
  - A LIST at real scale (thousands of channels, forcing many pause/
    resume ticks): confirms streaming never degrades no matter how large
    the response gets -- there's no buffer to overflow anymore.
  - A labeled LIST genuinely superseded by a second LIST while still
    parked mid-pagination: confirms m_list.c's interruption handling
    (label_capture_reopen() + RPL_LISTEND + label_capture_finish(), not
    abort()) does what it's meant to against a *live* streaming capture
    -- the old batch closes cleanly with whatever it had, and the new
    command gets its own fresh batch.

Also covered: an *unlabeled* LIST interrupted by an unrelated labeled
command (a parse.c regression, unrelated to streaming).

Channels are created via a fake P10 server link (see
_make_channels_via_burst()) rather than real clients repeatedly JOINing:
a real client trips ircu's pre-existing ERR_TARGETTOOFAST target-change
flood limit (TARGET_DELAY=128s, ircd/s_user.c) after only a handful of
JOINs to distinct channels, unrelated to labeled-response but making a
client-based helper unusable at the channel counts these tests need.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess

import pytest

from cap_helpers import make_cap_client
from irc_client import IRCClient
from p10_server import P10Server

from .helpers import LABELED_CAPS, tag_has, tag_value

pytestmark = [pytest.mark.single_server, pytest.mark.timeout(180)]


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _make_channels_via_burst(server: P10Server, prefix: str, count: int) -> None:
    """Create `count` channels almost instantly via a fake P10 server link.

    A real client repeatedly JOINing distinct channels trips ircu's
    pre-existing ERR_TARGETTOOFAST target-change flood limit
    (TARGET_DELAY=128s, ircd/s_user.c) after only its first handful of
    JOINs -- unrelated to labeled-response, but it makes a client-based
    channel-creation helper unusable at hundreds of channels (each
    subsequent JOIN needing minutes of wait, and eventually destabilizing
    the connection). A trusted S2S link has no such restriction --
    ms_join() in m_join.c never calls the client-only target-change
    check, and skips MAXCHANNELSPERUSER too -- so this creates hundreds
    of channels in well under a second, all owned by one fake remote
    user.
    """
    numnick = await server.introduce_user(f"{prefix}fake")
    for i in range(count):
        await server.send_join(numnick, f"#{prefix}{i}")
    # Give the hub a moment to finish processing the burst before the
    # test's own client issues LIST against it.
    await asyncio.sleep(1.0)


async def test_large_list_is_one_complete_batch(ircd_hub, ulined_server):
    """A LIST at a modest scale still produces one complete, correctly-
    closed batch -- whether or not it happens to pause and resume across
    ticks along the way (streamed output now goes through real sendQ, so
    it can), the client only ever sees one clean, well-formed batch.
    """
    await _make_channels_via_burst(ulined_server, "biglist", 60)
    client = await make_cap_client(
        ircd_hub["host"], ircd_hub["tiny_sendq_port"], "lblbig1", caps=LABELED_CAPS
    )
    try:
        await client.send("@label=biglist1 LIST")

        opening = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening.tags, "label") == "biglist1", opening.raw
        assert opening.params[1] == "labeled-response", opening.raw
        ref = opening.params[0][1:]

        lines = await client.collect_until("BATCH", timeout=15.0)
        closing = lines[-1]
        assert closing.params[0] == f"-{ref}", closing.raw

        body = [m for m in lines[:-1] if tag_value(m.tags, "batch") == ref]
        list_lines = [m for m in body if m.command == "322"]
        assert len(list_lines) >= 60, (
            f"expected at least 60 RPL_LIST lines in the batch, got {len(list_lines)}"
        )
        assert any(m.command == "323" for m in body), [m.command for m in body]

        # Nothing about this LIST leaks out after the batch closes.
        await client.assert_no_message("322", timeout=1.0)
        await client.assert_no_message("323", timeout=1.0)
    finally:
        await _cleanup(client)


async def test_large_list_streams_without_degrading(ircd_hub, ulined_server):
    """A LIST at real scale (thousands of channels, well past the old
    buffered design's capture-overflow threshold) still comes back as one
    complete, correctly-labeled batch -- streaming has no buffer to
    overflow, so there's nothing left to degrade. This channel count
    reliably forces many pause/resume ticks (label_capture_reopen() on
    each), which is the point: it's a real, not synchronous-in-one-shot,
    multi-tick run.
    """
    await _make_channels_via_burst(ulined_server, "biglist2", 5020)
    client = await make_cap_client(
        ircd_hub["host"], ircd_hub["tiny_sendq_port"], "lblbig2", caps=LABELED_CAPS
    )
    try:
        await client.send("@label=biglist2 LIST")

        opening = await client.wait_for("BATCH", timeout=10.0)
        assert tag_value(opening.tags, "label") == "biglist2", opening.raw
        ref = opening.params[0][1:]

        list_lines = 0
        saw_listend = False
        while True:
            msg = await client.recv(timeout=15.0)
            if msg.command == "BATCH" and msg.params[0] == f"-{ref}":
                break
            if tag_value(msg.tags, "batch") != ref:
                # Unrelated traffic (e.g. a connection-class NOTICE) can
                # legitimately interleave on the wire without being part
                # of this batch -- select by tag, not by wire position.
                continue
            assert not tag_has(msg.tags, "label"), msg.raw
            if msg.command == "322":
                list_lines += 1
            if msg.command == "323":
                saw_listend = True

        assert list_lines >= 5000, f"expected many RPL_LIST lines, got {list_lines}"
        assert saw_listend, "expected RPL_LISTEND inside the batch"

        # The server must still be fully responsive afterward.
        await client.send("PING :after-large")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.params[-1] == "after-large", pong.raw
    finally:
        await _cleanup(client)


async def test_labeled_list_interrupted_by_new_list_closes_and_reopens_batch(
    ircd_hub, ulined_server,
):
    """A labeled LIST genuinely parked mid-pagination, superseded by a
    second labeled LIST: the old batch must close cleanly with whatever
    it had streamed so far (RPL_LISTEND folded in, then BATCH -ref --
    m_list.c's label_capture_reopen()+finish(), not abort()), and the new
    command gets its own fresh BATCH +ref.

    Unlike under the old buffered design, this now exercises a
    genuinely-*live* capture at interruption time: streamed output goes
    through real sendQ, so list_next_channels()'s own pause check can
    (and at this channel count, reliably does) leave cli_listing() set
    across ticks for a labeled LIST too.
    """
    await _make_channels_via_burst(ulined_server, "intlist", 60)
    client = await make_cap_client(
        ircd_hub["host"], ircd_hub["tiny_sendq_port"], "lblint1", caps=LABELED_CAPS
    )
    try:
        await client.send("@label=firstlist LIST")

        opening1 = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening1.tags, "label") == "firstlist", opening1.raw
        ref1 = opening1.params[0][1:]

        # Confirm it's genuinely still going (parked, not yet closed)
        # before interrupting it: collect a few batch=ref1 lines without
        # requiring the close.
        first_batch_lines = []
        while len(first_batch_lines) < 5:
            msg = await client.recv(timeout=10.0)
            if tag_value(msg.tags, "batch") != ref1:
                # Unrelated traffic (e.g. a connection-class NOTICE) can
                # legitimately interleave without being part of this batch.
                continue
            first_batch_lines.append(msg)

        # A second, also-labeled LIST supersedes the first while it's
        # still parked.
        await client.send("@label=secondlist LIST")

        # The old batch must close cleanly: any remaining batch=ref1
        # lines (more RPL_LIST, then RPL_LISTEND), then BATCH -ref1 --
        # never an unlabeled dump.
        old_tail = await client.collect_until("BATCH", timeout=15.0)
        old_closing = old_tail[-1]
        assert old_closing.params[0] == f"-{ref1}", old_closing.raw
        # Select by batch= tag, not by wire position: unrelated traffic
        # (e.g. a connection-class NOTICE) can legitimately interleave
        # without being part of this batch.
        old_body = [m for m in old_tail[:-1] if tag_value(m.tags, "batch") == ref1]
        for m in old_body:
            assert not tag_has(m.tags, "label"), m.raw
        assert any(m.command == "323" for m in old_body), (
            "expected the superseded listing's own RPL_LISTEND inside its batch"
        )

        # The new command gets its own fresh batch.
        opening2 = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening2.tags, "label") == "secondlist", opening2.raw
        ref2 = opening2.params[0][1:]
        assert ref2 != ref1, "expected a distinct ref for the new listing"

        new_lines = await client.collect_until("BATCH", timeout=15.0)
        new_closing = new_lines[-1]
        assert new_closing.params[0] == f"-{ref2}", new_closing.raw
        new_body = [m for m in new_lines[:-1] if tag_value(m.tags, "batch") == ref2]
        assert any(m.command == "322" for m in new_body), [m.command for m in new_body]
        assert any(m.command == "323" for m in new_body), [m.command for m in new_body]
        for m in new_body:
            assert not tag_has(m.tags, "label"), m.raw

        await client.send("PING :after-interrupt")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.params[-1] == "after-interrupt", pong.raw
    finally:
        await _cleanup(client)


async def test_unrelated_labeled_command_while_unlabeled_list_parked_gets_own_response(
    ircd_hub, ulined_server,
):
    """A labeled command unrelated to LIST, sent while an *unlabeled* LIST
    is genuinely parked mid-pagination on the same connection, must
    resolve on its own -- promptly, and without disturbing the parked
    LIST at all.

    Regression test for a parse.c bug: its async-continuation detection
    used to treat *any* already-in-progress cli_listing() as "this
    command just started/continued the listing" (`else if
    (cli_listing(cptr))`, with no check of what was there before the
    handler ran). A labeled PING sent while an unrelated LIST was already
    parked had its own capture ref clobber the parked LIST's
    ListingArgs.label_ref (empty, since that LIST isn't labeled) --
    the PING's PONG was never delivered promptly, and once the LIST
    resumed, list_next_channels() found a non-empty label_ref and wrongly
    reopened *the PING's* capture, sweeping the LIST's own RPL_LIST /
    RPL_LISTEND lines into a bogus BATCH labeled "pingme".

    An *unlabeled* LIST is used here so the pause is unambiguous and
    unrelated to streaming timing -- a labeled LIST now paces itself
    through real sendQ too (see this module's docstring), so it would
    also work, but would make the "genuinely parked" moment less
    deterministic to land the interrupting command on.
    """
    await _make_channels_via_burst(ulined_server, "unrel", 60)
    client = await make_cap_client(
        ircd_hub["host"], ircd_hub["tiny_sendq_port"], "lblunrel1", caps=LABELED_CAPS
    )
    try:
        # Single write(): guarantees the PING is dispatched while
        # cli_listing() is still set from the (unlabeled, genuinely
        # paused) LIST above it, with no event-loop turn in between to
        # blur the timing.
        client._writer.write(b"LIST\r\n@label=pingme PING :hello\r\n")
        await client._writer.drain()

        # The unrelated, labeled PING must resolve on its own, promptly --
        # not be parked, not wrapped in a BATCH (it's a single line).
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.params[-1] == "hello", pong.raw
        assert tag_value(pong.tags, "label") == "pingme", pong.raw
        assert not tag_has(pong.tags, "batch"), pong.raw

        # The LIST itself still completes normally as plain RPL_LIST /
        # RPL_LISTEND -- never bundled into a BATCH under the PING's
        # label, and never carrying that label directly either.
        lines = await client.collect_until("323", timeout=15.0)
        assert not any(m.command == "BATCH" for m in lines), lines
        assert not any(tag_value(m.tags, "label") == "pingme" for m in lines), lines
        list_lines = [m for m in lines if m.command == "322"]
        assert len(list_lines) >= 60, (
            f"expected at least 60 RPL_LIST lines, got {len(list_lines)}"
        )

        # The server must still be fully responsive afterward.
        await client.send("PING :after")
        pong2 = await client.wait_for("PONG", timeout=5.0)
        assert pong2.params[-1] == "after", pong2.raw
    finally:
        await _cleanup(client)


def _hub_container_ip() -> str:
    """The hub's own address on the docker bridge. Connecting there (rather
    than to the 127.0.0.1 port mapping) keeps docker-proxy -- a userspace
    relay with buffering of its own -- out of the path, so the hub's kernel
    write really does block when the client stops reading."""
    out = subprocess.run(
        ["docker", "inspect", "ircu-hub", "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
        check=True, capture_output=True, text=True,
    )
    ip = out.stdout.strip()
    assert ip, "could not determine hub container IP"
    return ip


async def _make_throttled_cap_client(host: str, port: int, nick: str) -> IRCClient:
    """Like make_cap_client(), but on a socket whose receive side is kept
    tiny (SO_RCVBUF plus a small asyncio StreamReader limit), so that once
    the test stops calling recv() the hub's kernel send buffer fills within
    a few KB and its write blocks -- the only way list_next_channels()
    genuinely parks: send_buffer() flushes to the kernel every 1KB, so the
    TinySendQ class's sendq/2 pause threshold is never reached while the
    kernel keeps accepting data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    sock.connect((host, port))
    sock.setblocking(False)
    client = IRCClient()
    client._reader, client._writer = await asyncio.open_connection(sock=sock, limit=4096)
    acked = await client.negotiate_cap(LABELED_CAPS)
    if any(c not in acked for c in LABELED_CAPS):
        await client.disconnect()
        pytest.skip(f"CAP(s) not available (acked={acked})")
    await client.register(nick, "testuser", "Test User")
    return client


async def test_new_labeled_list_replacing_parked_labeled_list(
    ircd_hub, ulined_server,
):
    """A second labeled LIST -- one with a parameter, so it starts a *new*
    paginated listing rather than acting as LIST STOP -- parsed while the
    first is genuinely parked mid-pagination (hub write blocked: the
    client isn't reading and its receive side is throttled, see
    _make_throttled_cap_client()).

    Regression: parse.c decided "this handler started a new listing" by
    comparing the cli_listing() *pointer* before and after the handler.
    m_list.c's superseding path frees the old ListingArgs and immediately
    mallocs a new one of the same size, so the allocator hands back the
    same address, the comparison says "unchanged", and parse.c finished
    the brand-new streaming capture on the spot -- BATCH -ref2 went out
    after the first tick, and every later tick's RPL_LIST plus the final
    RPL_LISTEND left unlabeled, outside any batch.
    """
    count = 1500
    await _make_channels_via_burst(ulined_server, "supl", count)
    client = await _make_throttled_cap_client(
        _hub_container_ip(), ircd_hub["tiny_sendq_port"], "lblsup1"
    )
    try:
        await client.send("@label=firstlist LIST")
        # Let the hub run the first LIST until its write blocks and the
        # listing parks, then supersede it while parked.
        await asyncio.sleep(2.0)
        await client.send("@label=secondlist LIST >0")
        await asyncio.sleep(1.0)

        opening1 = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening1.tags, "label") == "firstlist", opening1.raw
        ref1 = opening1.params[0][1:]

        old_tail = await client.collect_until("BATCH", timeout=30.0)
        assert old_tail[-1].params[0] == f"-{ref1}", old_tail[-1].raw
        old_body = [m for m in old_tail[:-1] if tag_value(m.tags, "batch") == ref1]
        assert any(m.command == "323" for m in old_body)
        # Count only this test's channels, and distinct names: other tests
        # in the same hub session leave their channels behind (both LISTs
        # match them too), and list_next_channels() re-sends the hash
        # bucket it paused on when it resumes (pre-existing ircu
        # behaviour: the bucket loop breaks before its increment), so a
        # paused listing repeats a few entries.
        old_322 = len({
            m.params[1] for m in old_body
            if m.command == "322" and m.params[1].startswith("#supl")
        })
        # Precondition for the scenario: the first LIST must have been
        # superseded while still parked, i.e. cut short.
        assert old_322 < count, (
            "first LIST completed before the second was parsed; "
            "the superseding path was not exercised"
        )

        opening2 = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening2.tags, "label") == "secondlist", opening2.raw
        ref2 = opening2.params[0][1:]
        assert ref2 != ref1

        new_lines = await client.collect_until("BATCH", timeout=30.0)
        assert new_lines[-1].params[0] == f"-{ref2}", new_lines[-1].raw
        new_body = [m for m in new_lines[:-1] if tag_value(m.tags, "batch") == ref2]
        new_322 = len({
            m.params[1] for m in new_body
            if m.command == "322" and m.params[1].startswith("#supl")
        })
        assert any(m.command == "323" for m in new_body), (
            f"RPL_LISTEND missing from batch {ref2}: only {new_322} RPL_LIST "
            f"lines were inside it before BATCH -{ref2}"
        )
        assert new_322 == count, new_322

        # Nothing from the second listing may trail out unlabeled.
        await client.send("PING :after-supersede")
        trailing = await client.collect_until("PONG", timeout=10.0)
        leaked = [m.raw for m in trailing if m.command in ("322", "323")]
        assert not leaked, leaked
    finally:
        await _cleanup(client)
