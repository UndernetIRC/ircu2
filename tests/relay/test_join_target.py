"""Joining many channels at once (commits 5ffe0a1, 54cfd56).

With FEAT_JOIN_TARGET=FALSE (default) a JOIN never fails because of the
target-change limit: the membership is flagged "delayed target" instead,
and -- since the join is allowed -- no ERR_TARGETTOOFAST is sent and no
penalty is applied.  With FEAT_JOIN_TARGET=TRUE the historical behaviour
applies and joins beyond the free-target budget are refused with
ERR_TARGETTOOFAST.
"""

from __future__ import annotations

import asyncio

import pytest

from common import collect, set_feature

pytestmark = pytest.mark.single_server

# Well above STARTTARGETS (10) and MAXTARGETS (20); below MAXCHANNELSPERUSER (40).
CHANNELS = 25


async def _burst_join(client, prefix):
    chans = [f"#{prefix}{i}" for i in range(CHANNELS)]
    # One JOIN command so the per-command flood penalty does not slow us down.
    await client.send("JOIN " + ",".join(chans))
    joined = set()
    tfast = 0
    for msg in await collect(client, 3.0):
        if msg.command == "JOIN" and msg.prefix and msg.prefix.split("!")[0] == client.nick:
            joined.add(msg.params[0].lower())
        elif msg.command == "439":
            tfast += 1
    return chans, joined, tfast


async def test_join_burst_not_limited_by_default(make_client):
    client = await make_client("jtburst1")
    chans, joined, tfast = await _burst_join(client, "jt_free")
    assert joined == {c.lower() for c in chans}, (
        f"only {len(joined)}/{CHANNELS} channels joined: missing "
        f"{sorted(set(c.lower() for c in chans) - joined)}"
    )
    # An allowed join must not be reported as "too fast".
    assert tfast == 0, f"got {tfast} ERR_TARGETTOOFAST for joins that succeeded"


async def test_join_burst_limited_with_JOIN_TARGET(make_client, oper):
    """With JOIN_TARGET=TRUE the same burst is cut short by the target limit.

    Recent targets are remembered as a byte hash of the channel pointer and
    inherited by the next connection from the same IP, so channels that were
    freed just before would be "known" targets once their memory is reused.
    The unrestricted client therefore stays connected (keeping its channels
    alive) while the restricted client joins a fresh set.
    """
    free_client = await make_client("jtfree2")
    chans, joined, _ = await _burst_join(free_client, "jt_free2_")
    assert len(joined) == CHANNELS

    await set_feature(oper, "JOIN_TARGET", "TRUE")
    try:
        client = await make_client("jtburst2")
        chans, joined, tfast = await _burst_join(client, "jt_strict")
        assert len(joined) < CHANNELS, "JOIN_TARGET=TRUE should refuse some joins"
        assert tfast >= 1, "expected ERR_TARGETTOOFAST for refused joins"
    finally:
        await set_feature(oper, "JOIN_TARGET", "FALSE")

    # And the default is restored.
    client = await make_client("jtburst3")
    chans, joined, _ = await _burst_join(client, "jt_after")
    assert len(joined) == CHANNELS


async def test_messaging_after_join_burst(make_client):
    """Channels joined past the target budget are still usable."""
    speaker = await make_client("jtspk4")
    listener = await make_client("jtlst4")
    chans, joined, _ = await _burst_join(speaker, "jt_msg")
    assert len(joined) == CHANNELS
    last = chans[-1]
    await listener.send(f"JOIN {last}")
    await listener.wait_for("JOIN")
    await asyncio.sleep(0.3)
    await speaker.send(f"PRIVMSG {last} :still works")
    msg = await listener.wait_for_user_msg("PRIVMSG", timeout=5.0)
    assert msg.params[-1] == "still works"


async def test_invited_user_gets_free_target(make_client):
    """check_target_limit() still grants a free target for invited channels."""
    op = await make_client("jtop5")
    invitee = await make_client("jtinv5")
    await op.send("JOIN #jt_invite")
    await op.wait_for("JOIN")
    await op.send("INVITE jtinv5 #jt_invite")
    await invitee.wait_for_user_msg("INVITE", timeout=5.0)
    await invitee.send("JOIN #jt_invite")
    msg = await invitee.wait_for("JOIN", timeout=5.0)
    assert msg.params[0].lower() == "#jt_invite"
