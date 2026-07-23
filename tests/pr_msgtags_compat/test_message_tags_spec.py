"""IRCv3 message-tags: delivery rules, CLIENTTAGDENY, TAGMSG."""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.multi_server


@pytest.fixture
async def services(ircd_network):
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


async def test_message_tags_alone_gets_time_and_account(ircd_network, services):
    """message-tags without server-time/account-tag still receives time+account."""
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("mtagonly", "testuser", "Tag Only Sender")
    numnick = await services.wait_for_user("mtagonly")
    await services.send_account(numnick, "OnlyAcct")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags"])
    await observer.register("mtagobs", "testuser", "Tag Only Obs")

    try:
        await sender.send("JOIN #mtagonly")
        await observer.send("JOIN #mtagonly")
        await asyncio.sleep(0.3)

        await sender.send("PRIVMSG #mtagonly :catchall caps")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert "time=" in msg.tags, msg.raw
        assert "account=OnlyAcct" in msg.tags, msg.raw
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_client_tag_relay_when_allowed(ircd_network):
    """Allowed +tags relay to clients with message-tags."""
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("mtagcli", "testuser", "Tag Client Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags"])
    await observer.register("mtagclobs", "testuser", "Tag Client Obs")

    try:
        await sender.send("JOIN #mtagcli")
        await observer.send("JOIN #mtagcli")
        await asyncio.sleep(0.3)

        await sender.send("PRIVMSG #mtagcli :plain")
        await observer.wait_for("PRIVMSG", timeout=5.0)

        await sender.send("@+example.com/foo=bar PRIVMSG #mtagcli :tagged")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "tagged", msg.raw
        assert "+example.com/foo=bar" in msg.tags, msg.raw
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_client_tag_denied_by_default(ircd_network):
    """CLIENTTAGDENY=* blocks client-only tags (message still delivered)."""
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("mtagdeny", "testuser", "Tag Deny Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags", "server-time"])
    await observer.register("mtagdenyobs", "testuser", "Tag Deny Obs")

    try:
        await sender.send("JOIN #mtagdeny")
        await observer.send("JOIN #mtagdeny")
        await asyncio.sleep(0.3)

        await sender.send("@+secret=1 PRIVMSG #mtagdeny :denied tag")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "denied tag", msg.raw
        assert "secret" not in msg.tags, msg.raw
        assert msg.tags.startswith("time="), msg.raw
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_unprefixed_client_tag_stripped(ircd_network):
    """Unprefixed tags from clients must not be relayed."""
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("mtagstrip", "testuser", "Tag Strip Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags"])
    await observer.register("mtagstripobs", "testuser", "Tag Strip Obs")

    try:
        await sender.send("JOIN #mtagstrip")
        await observer.send("JOIN #mtagstrip")
        await asyncio.sleep(0.3)

        await sender.send("@msgid=abc PRIVMSG #mtagstrip :no relay")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "no relay", msg.raw
        assert "msgid" not in msg.tags, msg.raw
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_tagmsg_requires_message_tags(ircd_network):
    """TAGMSG without message-tags cap is rejected."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("mtagmsg1", "testuser", "Tagmsg User")

    try:
        await user.send("JOIN #mtagmsgtest")
        await asyncio.sleep(0.2)
        await user.send("TAGMSG #mtagmsgtest")
        err = await user.wait_for("421", timeout=5.0)
        assert any(p == "TAGMSG" for p in err.params), err.raw
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_tagmsg_delivered_with_tags(ircd_network):
    """TAGMSG with message-tags delivers tag-only line to channel."""
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.negotiate_cap(["message-tags"])
    await sender.register("mtagmsg2", "testuser", "Tagmsg Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["message-tags"])
    await observer.register("mtagmsgobs", "testuser", "Tagmsg Obs")

    try:
        await sender.send("JOIN #mtagmsgchan")
        await observer.send("JOIN #mtagmsgchan")
        await asyncio.sleep(0.3)

        await sender.send("@+example.com/foo=tagonly TAGMSG #mtagmsgchan")
        msg = await observer.wait_for("TAGMSG", timeout=5.0)
        assert msg.params[0] == "#mtagmsgchan", msg.raw
        assert "+example.com/foo=tagonly" in msg.tags, msg.raw
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
