"""Backwards-compat prep for S2S message-tags.

Before full msgtags support lands, server-server parsing must:
1. Ignore a leading @tag-section (through the separating space).
2. Keep the 512-byte limit on the message body only (tags are extra).

These tests send tagged P10 lines from a fake server and verify the hub
still processes the underlying command.
"""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.multi_server


@pytest.fixture
async def services(ircd_network):
    """Connect a fake P10 services server to the hub."""
    hub = ircd_network["hub"]
    srv = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    yield srv
    await srv.disconnect()


async def test_tagged_account_applied(ircd_network, services):
    """ACCOUNT with a leading @tag section must still be applied."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtagacct", "testuser", "Tag Compat User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("mtagobs", "testuser", "Tag Compat Obs")

    try:
        numnick = await services.wait_for_user("mtagacct")
        await services._send(
            f"@msgid=compat1;account-notify {services._num} AC {numnick} TagAcct"
        )
        await asyncio.sleep(0.3)

        await observer.send("WHOIS mtagacct")
        whois = await observer.collect_until("318", timeout=5.0)
        account_lines = [m for m in whois if m.command == "330"]
        assert account_lines, f"expected 330 account line, got: {whois}"
        assert "TagAcct" in account_lines[0].params
    finally:
        for c in (user, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_tagged_privmsg_delivered(ircd_network, services):
    """A PRIVMSG prefixed with ignored @tags must still reach the client."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtagpm", "testuser", "Tag Compat PM")

    try:
        numnick = await services.wait_for_user("mtagpm")
        await services._send(
            f"@msgid=pm1;foo=bar {services._num} P {numnick} :hello tagged world"
        )
        msg = await user.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "hello tagged world", msg
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_tags_push_total_over_512_body_ok(ircd_network, services):
    """Tags + body may exceed 512; a body that fits in 512 must still work.

    This is the backwards-compat case: without skipping tags / enlarging
    the receive buffer, a line over 512 octets would be truncated and the
    command would be lost even though the body itself is short.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtagover", "testuser", "Tag Compat Over512")

    try:
        numnick = await services.wait_for_user("mtagover")

        body = f"{services._num} P {numnick} :tags made this line long"
        assert len(body) < 512

        # Tag section large enough that tags + body > 512 on the wire.
        tag_payload = "x" * 500
        tags = f"@big={tag_payload}"
        wire = f"{tags} {body}"
        assert len(wire) > 512
        assert len(tags) + 1 < 8191  # within TAGSLEN (incl. '@' and space)

        await services._send(wire)
        msg = await user.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "tags made this line long", msg
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_large_tags_short_body_delivered(ircd_network, services):
    """A multi-kilobyte tag section with a short body must still parse."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtagbig", "testuser", "Tag Compat BigTags")

    try:
        numnick = await services.wait_for_user("mtagbig")

        body = f"{services._num} P {numnick} :still here"
        # ~4k of tag data (well under TAGSLEN=8191, well over 512 total).
        tags = "@pad=" + ("y" * 4000)
        wire = f"{tags} {body}"
        assert len(wire) > 512
        assert len(tags) + 1 <= 8191

        await services._send(wire)
        msg = await user.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "still here", msg
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_tagged_body_still_capped_at_512(ircd_network, services):
    """Tags do not expand the body limit: a body over 512 is truncated.

    Untagged S2S input silently truncates at BUFSIZE. With tags, the same
    truncate applies to the body after the tag section, so a long body
    must not arrive intact at the client.
    """
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtaglong", "testuser", "Tag Compat Long")

    try:
        numnick = await services.wait_for_user("mtaglong")

        # Body is the P10 message after tags: "<num> P <target> :<text>"
        prefix = f"{services._num} P {numnick} :"
        text = "X" * 600
        body = prefix + text
        assert len(body) > 512

        await services._send(f"@tag1=value1;tag2=value2 {body}")

        msg = await user.wait_for("PRIVMSG", timeout=5.0)
        assert len(msg.params[-1]) < len(text), (
            f"expected truncated body, got len={len(msg.params[-1])}"
        )
        assert msg.params[-1].startswith("X")
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_untagged_privmsg_unchanged(ircd_network, services):
    """Sanity: untagged S2S PRIVMSG still works after the compat change."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtagnorm", "testuser", "Tag Compat Normal")

    try:
        numnick = await services.wait_for_user("mtagnorm")
        await services._send(f"{services._num} P {numnick} :plain hello")
        msg = await user.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "plain hello", msg
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()
