"""IRCv3 message-tags over WebSocket clients (hub port 7000).

Covers the client-facing delivery path: CAP matrix, CLIENTTAGDENY, TAGMSG,
server-time, forged tags, and 417 — using IRCWebSocketClient instead of TCP.
"""

import asyncio
import re

import pytest

from irc_ws_client import IRCWebSocketClient
from p10_server import P10Server

from .helpers import tag_has, tag_value

pytestmark = pytest.mark.multi_server

WS_PORT = 7000
CHANNEL = "#mtagws"
STAMP = "2020-06-15T08:30:00.123Z"


def _ws_url(host: str) -> str:
    return f"ws://{host}:{WS_PORT}/"


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


async def _cleanup(*clients: IRCWebSocketClient):
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _ws_client(
    host: str,
    nick: str,
    caps: list[str] | None = None,
    *,
    binary: bool = False,
) -> IRCWebSocketClient:
    c = IRCWebSocketClient(binary=binary)
    await c.connect(_ws_url(host))
    if caps:
        await c.negotiate_cap(caps)
    await c.register(nick, "testuser", f"User {nick}")
    return c


async def _join(clients: list[IRCWebSocketClient], channel: str = CHANNEL):
    for c in clients:
        await c.send(f"JOIN {channel}")
        await c.wait_for("JOIN", timeout=5.0)
    await asyncio.sleep(0.3)


@pytest.mark.parametrize(
    "caps,expect_time,expect_account,expect_client",
    [
        ([], False, False, False),
        (["server-time"], True, False, False),
        (["account-tag"], False, True, False),
        (["message-tags"], True, True, True),
        (["server-time", "account-tag"], True, True, False),
        (["server-time", "message-tags"], True, True, True),
    ],
)
async def test_ws_cap_matrix_delivery(
    ircd_network,
    services,
    caps,
    expect_time,
    expect_account,
    expect_client,
):
    """WebSocket observers receive the same tag subset as TCP for each CAP combo."""
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wscapsnd")
    numnick = await services.wait_for_user("wscapsnd")
    await services.send_account(numnick, "WsCapAcct")

    observer = await _ws_client(
        hub["host"], f"wscap{len(caps)}", caps=caps or None
    )

    try:
        await _join([sender, observer], "#wscapmtx")
        await sender.send("@+example.com/foo=bar PRIVMSG #wscapmtx :ws matrix")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "ws matrix", msg.raw
        assert tag_has(msg.tags, "time") == expect_time, msg.raw
        assert tag_has(msg.tags, "account") == expect_account, msg.raw
        assert tag_has(msg.tags, "+example.com/foo") == expect_client, msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_local_privmsg_gets_server_time(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wslocalsnd")
    observer = await _ws_client(hub["host"], "wslocalobs", ["server-time"])

    try:
        await _join([sender, observer], "#wslocal")
        await sender.send("PRIVMSG #wslocal :ws local hello")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "ws local hello", msg.raw
        assert msg.tags.startswith("time="), msg.raw
        assert re.match(r"time=\d{4}-\d{2}-\d{2}T", msg.tags), msg.tags
    finally:
        await _cleanup(sender, observer)


async def test_ws_client_tag_relay_when_allowed(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsclisnd", ["message-tags"])
    observer = await _ws_client(hub["host"], "wscliobs", ["message-tags"])

    try:
        await _join([sender, observer], "#wsclitag")
        await sender.send("PRIVMSG #wsclitag :plain")
        await observer.wait_for("PRIVMSG", timeout=5.0)

        await sender.send("@+example.com/foo=bar PRIVMSG #wsclitag :tagged")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "tagged", msg.raw
        assert "+example.com/foo=bar" in msg.tags, msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_client_tag_denied_by_default(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsdenysnd", ["message-tags"])
    observer = await _ws_client(
        hub["host"], "wsdenyobs", ["message-tags", "server-time"]
    )

    try:
        await _join([sender, observer], "#wsdeny")
        await sender.send("@+secret=1 PRIVMSG #wsdeny :denied tag")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "denied tag", msg.raw
        assert "secret" not in msg.tags, msg.raw
        assert msg.tags.startswith("time="), msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_unprefixed_client_tag_stripped(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsstripsnd", ["message-tags"])
    observer = await _ws_client(hub["host"], "wsstripobs", ["message-tags"])

    try:
        await _join([sender, observer], "#wsstrip")
        await sender.send("@msgid=abc PRIVMSG #wsstrip :no relay")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "no relay", msg.raw
        assert "msgid" not in msg.tags, msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_cannot_forge_server_tags(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsforgesnd", ["message-tags"])
    observer = await _ws_client(
        hub["host"],
        "wsforgeobs",
        ["message-tags", "server-time", "account-tag"],
    )

    try:
        await _join([sender, observer], "#wsforge")
        fake_time = "1999-01-01T00:00:00.000Z"
        await sender.send(
            f"@time={fake_time};account=FakeAcct;+example.com/foo=x "
            f"PRIVMSG #wsforge :forged"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "forged", msg.raw
        assert tag_value(msg.tags, "time") != fake_time, msg.raw
        assert not tag_has(msg.tags, "account"), msg.raw
        assert tag_value(msg.tags, "+example.com/foo") == "x", msg.raw
        assert tag_has(msg.tags, "time"), msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_oversize_tags_rejected_with_417(ircd_network):
    hub = ircd_network["hub"]

    user = await _ws_client(hub["host"], "wsbigtags", ["message-tags"])

    try:
        await user.send("JOIN #wsbigtag")
        await user.wait_for("JOIN", timeout=5.0)
        payload = "a" * 4095
        await user.send(f"@+big={payload} PRIVMSG #wsbigtag :overflow")
        err = await user.wait_for("417", timeout=5.0)
        assert err.command == "417", err.raw
    finally:
        await _cleanup(user)


async def test_ws_tagmsg_requires_message_tags(ircd_network):
    hub = ircd_network["hub"]

    user = await _ws_client(hub["host"], "wstagmsg1")

    try:
        await user.send("JOIN #wstagmsg")
        await user.wait_for("JOIN", timeout=5.0)
        await user.send("TAGMSG #wstagmsg")
        err = await user.wait_for("421", timeout=5.0)
        assert any(p == "TAGMSG" for p in err.params), err.raw
    finally:
        await _cleanup(user)


async def test_ws_tagmsg_delivered_with_tags(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wstagmsgsnd", ["message-tags"])
    observer = await _ws_client(hub["host"], "wstagmsgobs", ["message-tags"])

    try:
        await _join([sender, observer], "#wstagmsgchan")
        await sender.send("@+example.com/foo=tagonly TAGMSG #wstagmsgchan")
        msg = await observer.wait_for("TAGMSG", timeout=5.0)
        assert msg.params[0] == "#wstagmsgchan", msg.raw
        assert "+example.com/foo=tagonly" in msg.tags, msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_notice_relays_client_tags(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsnotsnd", ["message-tags"])
    observer = await _ws_client(hub["host"], "wsnotobs", ["message-tags"])

    try:
        await _join([sender, observer], "#wsnotice")
        await sender.send("@+example.com/foo=notice PRIVMSG #wsnotice :warmup")
        await observer.wait_for("PRIVMSG", timeout=5.0)

        await sender.send(
            "@+example.com/foo=notice NOTICE #wsnotice :notice tagged"
        )
        deadline = asyncio.get_event_loop().time() + 5.0
        msg = None
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            candidate = await observer.wait_for(
                "NOTICE", timeout=max(remaining, 0.1)
            )
            if candidate.params and candidate.params[-1] == "notice tagged":
                msg = candidate
                break
        assert msg is not None, "channel NOTICE not received"
        assert tag_value(msg.tags, "+example.com/foo") == "notice", msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_no_caps_gets_untagged_privmsg(ircd_network):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsplain_snd")
    observer = await _ws_client(hub["host"], "wsplain_obs")

    try:
        await _join([sender, observer], "#wsplain")
        await sender.send("PRIVMSG #wsplain :no tags")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "no tags", msg.raw
        assert not msg.tags, msg.raw
        assert not msg.raw.startswith("@"), msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_s2s_time_tag_relayed(ircd_network, services):
    """Remote tagged PRIVMSG reaches a WebSocket observer with server-time."""
    hub = ircd_network["hub"]

    observer = await _ws_client(
        hub["host"], "wss2stobs", ["server-time", "message-tags"]
    )

    try:
        numnick = await services.wait_for_user("wss2stobs")
        await services._send(
            f"@time={STAMP} {services._num} P {numnick} :hello timed ws"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.tags.startswith(f"time={STAMP}"), msg.raw
        assert msg.params[-1] == "hello timed ws"
    finally:
        await _cleanup(observer)


async def test_ws_binary_subprotocol_server_time(ircd_network):
    """binary.ircv3.net path also delivers server-time tags."""
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsbinsnd", binary=True)
    observer = await _ws_client(
        hub["host"], "wsbinobs", ["server-time"], binary=True
    )

    try:
        await _join([sender, observer], "#wsbin")
        await sender.send("PRIVMSG #wsbin :binary hello")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "binary hello", msg.raw
        assert tag_has(msg.tags, "time"), msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_ws_message_tags_alone_gets_time_and_account(ircd_network, services):
    hub = ircd_network["hub"]

    sender = await _ws_client(hub["host"], "wsmtagsnd")
    numnick = await services.wait_for_user("wsmtagsnd")
    await services.send_account(numnick, "WsOnlyAcct")

    observer = await _ws_client(hub["host"], "wsmtagobs", ["message-tags"])

    try:
        await _join([sender, observer], "#wsmtagonly")
        await sender.send("PRIVMSG #wsmtagonly :catchall caps")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert "time=" in msg.tags, msg.raw
        assert "account=WsOnlyAcct" in msg.tags, msg.raw
    finally:
        await _cleanup(sender, observer)
