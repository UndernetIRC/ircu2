"""Comprehensive IRCv3 message-tags tests (S2S, caps, CLIENTTAGDENY, limits)."""

import asyncio
import re

import pytest

from irc_client import IRCClient
from p10_server import P10Server

from .helpers import parse_tag_list, tag_has, tag_value

pytestmark = pytest.mark.multi_server

CHANNEL = "#mtagcomp"
STAMP = "2020-06-15T08:30:00.123Z"


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


async def _join_channel(clients: list[IRCClient], channel: str = CHANNEL):
    for c in clients:
        await c.send(f"JOIN {channel}")
        await c.wait_for("JOIN", timeout=5.0)
    await asyncio.sleep(0.3)


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _client(
    host: str,
    port: int,
    nick: str,
    caps: list[str] | None = None,
) -> IRCClient:
    c = IRCClient()
    await c.connect(host, port)
    if caps:
        await c.negotiate_cap(caps)
    await c.register(nick, "testuser", f"User {nick}")
    return c


# Docker hub default; restore after runtime SET so later tests keep the
# deny-all-with-exemption policy.
_DEFAULT_CLIENTTAGDENY = "*,-example.com/foo"


async def _oper_set_clienttagdeny(hub: dict, nick: str, value: str | None) -> IRCClient:
    """OPER up and SET CLIENTTAGDENY. value=None clears it (allow all)."""
    oper = await _client(hub["host"], hub["port"], nick)
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)
    if value is None:
        await oper.send("SET CLIENTTAGDENY :")
    else:
        await oper.send(f"SET CLIENTTAGDENY {value}")
    reply = await oper.wait_for("284", timeout=8.0)
    if value is None:
        assert "not set" in reply.params[-1].lower(), reply.raw
    else:
        assert value in reply.params[-1], reply.raw
    return oper


async def _restore_clienttagdeny(oper: IRCClient) -> None:
    await oper.send(f"SET CLIENTTAGDENY {_DEFAULT_CLIENTTAGDENY}")
    await oper.wait_for("284", timeout=8.0)


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
async def test_cap_matrix_delivery(
    ircd_network,
    services,
    caps,
    expect_time,
    expect_account,
    expect_client,
):
    """Each cap combination receives the correct tag subset."""
    hub = ircd_network["hub"]

    sender = await _client(hub["host"], hub["port"], "capmtxsend")
    numnick = await services.wait_for_user("capmtxsend")
    await services.send_account(numnick, "CapAcct")

    observer = await _client(
        hub["host"], hub["port"], f"capmtx{len(caps)}", caps=caps or None
    )

    try:
        await _join_channel([sender, observer])
        await sender.send(
            f"@+example.com/foo=bar PRIVMSG {CHANNEL} :cap matrix"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "cap matrix", msg.raw

        assert tag_has(msg.tags, "time") == expect_time, msg.raw
        assert tag_has(msg.tags, "account") == expect_account, msg.raw
        assert tag_has(msg.tags, "+example.com/foo") == expect_client, msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_s2s_upstream_time_same_on_hub_and_leaf(ircd_network, services):
    """Fixed @time= from S2S must reach clients on hub and leaf unchanged."""
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    hub_obs = await _client(hub["host"], hub["port"], "s2sthub", ["server-time"])
    leaf_obs = await _client(leaf1["host"], leaf1["port"], "s2stleaf", ["server-time"])

    try:
        await _join_channel([hub_obs, leaf_obs], "#s2stfix")

        down_num = await services.send_downstream_server("down.time.test", 91)
        await services.send_downstream_nick(
            down_num, "TimeBot", server_numeric=91, client_num=1,
        )
        await services.send_downstream_join("TimeBot", "#s2stfix")
        await asyncio.sleep(0.3)

        bot = services.get_user_numnick("TimeBot")
        assert bot, "TimeBot numnick missing"
        await services._send(f"@time={STAMP} {bot} P #s2stfix :timed s2s")

        hub_msg = await hub_obs.wait_for("PRIVMSG", timeout=5.0)
        leaf_msg = await leaf_obs.wait_for("PRIVMSG", timeout=5.0)

        assert tag_value(hub_msg.tags, "time") == STAMP, hub_msg.raw
        assert tag_value(leaf_msg.tags, "time") == STAMP, leaf_msg.raw
        assert hub_msg.params[-1] == leaf_msg.params[-1] == "timed s2s"
    finally:
        await _cleanup(hub_obs, leaf_obs)


async def test_local_time_consistent_hub_and_leaf(ircd_network):
    """Locally stamped time should match for observers on linked servers."""
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    sender = await _client(hub["host"], hub["port"], "loctimesnd")
    hub_obs = await _client(hub["host"], hub["port"], "loctimehub", ["server-time"])
    leaf_obs = await _client(leaf1["host"], leaf1["port"], "loctimeleaf", ["server-time"])

    try:
        await _join_channel([sender, hub_obs, leaf_obs], "#loctime")
        await sender.send("PRIVMSG #loctime :same stamp")
        hub_msg = await hub_obs.wait_for("PRIVMSG", timeout=5.0)
        leaf_msg = await leaf_obs.wait_for("PRIVMSG", timeout=5.0)

        hub_t = tag_value(hub_msg.tags, "time")
        leaf_t = tag_value(leaf_msg.tags, "time")
        assert hub_t, hub_msg.raw
        assert leaf_t, leaf_msg.raw
        assert hub_t == leaf_t, (hub_msg.raw, leaf_msg.raw)
        assert re.match(r"\d{4}-\d{2}-\d{2}T", hub_t)
    finally:
        await _cleanup(sender, hub_obs, leaf_obs)


async def test_s2s_without_time_gets_local_stamp(ircd_network, services):
    """Untagged S2S PRIVMSG still gets a server-time tag at delivery edge."""
    hub = ircd_network["hub"]

    observer = await _client(hub["host"], hub["port"], "s2snostmp", ["server-time"])

    try:
        await _join_channel([observer], "#s2snostamp")
        down_num = await services.send_downstream_server("down.notime.test", 92)
        await services.send_downstream_nick(
            down_num, "NoTimeBot", server_numeric=92, client_num=1,
        )
        await services.send_downstream_join("NoTimeBot", "#s2snostamp")
        await asyncio.sleep(0.3)

        bot = services.get_user_numnick("NoTimeBot")
        assert bot, "NoTimeBot numnick missing"
        await services._send(f"{bot} P #s2snostamp :no upstream time")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert tag_has(msg.tags, "time"), msg.raw
        assert re.match(r"time=\d{4}-\d{2}-\d{2}T", msg.tags), msg.tags
    finally:
        await _cleanup(observer)


async def test_clienttagdeny_blocks_non_exempt_tag(ircd_network):
    """CLIENTTAGDENY=* blocks +secret; exempt +example.com/foo is allowed."""
    hub = ircd_network["hub"]

    sender = await _client(hub["host"], hub["port"], "denysnd", ["message-tags"])
    observer = await _client(hub["host"], hub["port"], "denyobs", ["message-tags"])

    try:
        await _join_channel([sender, observer])

        await sender.send(f"@+blockedtag=1 PRIVMSG {CHANNEL} :blocked")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "blocked", msg.raw
        assert not tag_has(msg.tags, "+blockedtag"), msg.raw

        await sender.send(f"@+example.com/foo=ok PRIVMSG {CHANNEL} :allowed")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert tag_value(msg.tags, "+example.com/foo") == "ok", msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_clienttagdeny_empty_allows_all(ircd_network):
    """CLIENTTAGDENY unset/empty allows arbitrary client-only tags."""
    hub = ircd_network["hub"]
    oper = await _oper_set_clienttagdeny(hub, "denyemptyop", None)

    sender = await _client(hub["host"], hub["port"], "denyemptys", ["message-tags"])
    observer = await _client(hub["host"], hub["port"], "denyemptyo", ["message-tags"])

    try:
        await _join_channel([sender, observer], "#denyempty")

        await sender.send("@+blockedtag=1 PRIVMSG #denyempty :was blocked")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "was blocked", msg.raw
        assert tag_value(msg.tags, "+blockedtag") == "1", msg.raw

        await sender.send("@+example.com/foo=ok PRIVMSG #denyempty :still ok")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert tag_value(msg.tags, "+example.com/foo") == "ok", msg.raw

        await sender.send("@+other=xyz TAGMSG #denyempty")
        msg = await observer.wait_for("TAGMSG", timeout=5.0)
        assert tag_value(msg.tags, "+other") == "xyz", msg.raw
    finally:
        try:
            await _restore_clienttagdeny(oper)
        finally:
            await _cleanup(sender, observer, oper)


async def test_clienttagdeny_named_denies_only_that_tag(ircd_network):
    """CLIENTTAGDENY=example.com/foo denies that tag; others remain allowed."""
    hub = ircd_network["hub"]
    oper = await _oper_set_clienttagdeny(hub, "denynamedop", "example.com/foo")

    sender = await _client(hub["host"], hub["port"], "denynameds", ["message-tags"])
    observer = await _client(hub["host"], hub["port"], "denynamedo", ["message-tags"])

    try:
        await _join_channel([sender, observer], "#denynamed")

        await sender.send(
            "@+example.com/foo=nope;+othertag=yes PRIVMSG #denynamed :partial"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "partial", msg.raw
        assert not tag_has(msg.tags, "+example.com/foo"), msg.raw
        assert tag_value(msg.tags, "+othertag") == "yes", msg.raw

        await sender.send("@+example.com/foo=nope TAGMSG #denynamed")
        # Denied-only TAGMSG: no client tags left to relay — message may be
        # dropped or arrive without the denied tag. Accept either no TAGMSG
        # or TAGMSG without +example.com/foo.
        try:
            msg = await observer.wait_for("TAGMSG", timeout=2.0)
            assert not tag_has(msg.tags, "+example.com/foo"), msg.raw
        except asyncio.TimeoutError:
            pass

        await sender.send("@+allowed=1 TAGMSG #denynamed")
        msg = await observer.wait_for("TAGMSG", timeout=5.0)
        assert tag_value(msg.tags, "+allowed") == "1", msg.raw
    finally:
        try:
            await _restore_clienttagdeny(oper)
        finally:
            await _cleanup(sender, observer, oper)


async def test_client_cannot_forge_server_tags(ircd_network, services):
    """Clients sending @time= / @account= must not relay those tags."""
    hub = ircd_network["hub"]

    sender = await _client(hub["host"], hub["port"], "forgesnd", ["message-tags"])
    observer = await _client(
        hub["host"], hub["port"], "forgeobs",
        ["message-tags", "server-time", "account-tag"],
    )

    try:
        await _join_channel([sender, observer])

        fake_time = "1999-01-01T00:00:00.000Z"
        await sender.send(
            f"@time={fake_time};account=FakeAcct;+example.com/foo=x "
            f"PRIVMSG {CHANNEL} :forged"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "forged", msg.raw
        assert tag_value(msg.tags, "time") != fake_time, msg.raw
        assert not tag_has(msg.tags, "account"), msg.raw
        assert tag_value(msg.tags, "+example.com/foo") == "x", msg.raw
        # Server should still stamp real time
        assert tag_has(msg.tags, "time"), msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_s2s_account_tag_never_relayed_from_wire(ircd_network, services):
    """Upstream @account= on S2S must not be forwarded to clients."""
    hub = ircd_network["hub"]

    observer = await _client(
        hub["host"], hub["port"], "s2saccobs", ["account-tag", "message-tags"]
    )

    try:
        numnick = await services.wait_for_user("s2saccobs")
        await services._send(
            f"@account=WireAcct {services._num} P {numnick} :wire account"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "wire account", msg.raw
        assert not tag_has(msg.tags, "account"), msg.raw
    finally:
        await _cleanup(observer)


async def test_client_oversize_tags_rejected_with_417(ircd_network):
    """Client tag data over 4094 bytes must yield ERR_INPUTTOOLONG (417)."""
    hub = ircd_network["hub"]

    user = await _client(hub["host"], hub["port"], "bigtags", ["message-tags"])

    try:
        await user.send("JOIN #bigtagtest")
        # tag data = 4095 'a' chars → over limit (excludes @ and space)
        payload = "a" * 4095
        await user.send(f"@+big={payload} PRIVMSG #bigtagtest :overflow")
        err = await user.wait_for("417", timeout=5.0)
        assert "too long" in err.params[-1].lower() or err.params[-1]
    finally:
        await _cleanup(user)


async def test_client_oversize_body_rejected_with_417(ircd_network):
    """Message body over BUFSIZE-2 (510) must yield 417 even with short tags."""
    hub = ircd_network["hub"]

    user = await _client(hub["host"], hub["port"], "bigbody", ["message-tags"])
    observer = await _client(hub["host"], hub["port"], "bigbodyo", ["message-tags"])

    try:
        await _join_channel([user, observer], "#bigbody")

        # Body = command + params; tags do not count toward BUFSIZE-2.
        # Keep the OK body well under 510 so the *outbound* formatted line
        # (with nick!user@host prefix) still fits BUFSIZE and is not truncated.
        prefix = "PRIVMSG #bigbody :"
        ok_text = "o" * 200
        assert len(prefix) + len(ok_text) < 510
        await user.send(f"@+example.com/foo=x {prefix}{ok_text}")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == ok_text, msg.raw

        # Exactly 510 body octets: accepted (no 417); may truncate on send.
        edge = "e" * (510 - len(prefix))
        assert len(prefix) + len(edge) == 510
        await user.send(f"@+example.com/foo=x {prefix}{edge}")
        edge_msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert edge_msg.params[-1].startswith("e"), edge_msg.raw

        # 511 body octets → ERR_INPUTTOOLONG; must not reach the channel.
        bad_text = "x" * (511 - len(prefix))
        assert len(prefix) + len(bad_text) == 511
        await user.send(f"@+example.com/foo=x {prefix}{bad_text}")
        err = await user.wait_for("417", timeout=5.0)
        assert err.command == "417", err.raw
        try:
            leaked = await observer.wait_for("PRIVMSG", timeout=1.0)
            raise AssertionError(f"oversize body was delivered: {leaked.raw}")
        except asyncio.TimeoutError:
            pass
    finally:
        await _cleanup(user, observer)


async def test_many_client_tags_parsed_without_crash(ircd_network):
    """Many semicolon-separated client tags should not crash the server."""
    hub = ircd_network["hub"]

    sender = await _client(hub["host"], hub["port"], "manytag", ["message-tags"])
    observer = await _client(hub["host"], hub["port"], "manyobs", ["message-tags"])

    try:
        await _join_channel([sender, observer], "#manytags")
        parts = [f"+t{i}=v{i}" for i in range(50)]
        tag_section = ";".join(parts)
        await sender.send(f"@{tag_section} PRIVMSG #manytags :many")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "many", msg.raw
        parsed = parse_tag_list(msg.tags)
        # All are + prefixed and denied except none match exempt - all denied by *
        assert "+t0" not in parsed
        assert tag_has(msg.tags, "time")
    finally:
        await _cleanup(sender, observer)


async def test_notice_relays_client_tags(ircd_network):
    """NOTICE must relay allowed client tags like PRIVMSG."""
    hub = ircd_network["hub"]

    sender = await _client(hub["host"], hub["port"], "notsnd", ["message-tags"])
    observer = await _client(hub["host"], hub["port"], "notobs", ["message-tags"])

    try:
        await _join_channel([sender, observer], "#noticetag")
        await sender.send(f"@+example.com/foo=notice PRIVMSG #noticetag :warmup")
        await observer.wait_for("PRIVMSG", timeout=5.0)

        await sender.send(f"@+example.com/foo=notice NOTICE #noticetag :notice tagged")
        # Ignore server status NOTICEs; wait for the channel NOTICE text.
        deadline = asyncio.get_event_loop().time() + 5.0
        msg = None
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            candidate = await observer.wait_for("NOTICE", timeout=max(remaining, 0.1))
            if candidate.params and candidate.params[-1] == "notice tagged":
                msg = candidate
                break
        assert msg is not None, "channel NOTICE not received"
        assert tag_value(msg.tags, "+example.com/foo") == "notice", msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_no_caps_client_gets_untagged_privmsg(ircd_network):
    """Client without tag caps receives plain PRIVMSG (no @ prefix)."""
    hub = ircd_network["hub"]

    sender = await _client(hub["host"], hub["port"], "plain_snd")
    observer = await _client(hub["host"], hub["port"], "plain_obs")

    try:
        await _join_channel([sender, observer], "#plain")
        await sender.send("PRIVMSG #plain :no tags")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "no tags", msg.raw
        assert not msg.tags, msg.raw
        assert not msg.raw.startswith("@"), msg.raw
    finally:
        await _cleanup(sender, observer)
