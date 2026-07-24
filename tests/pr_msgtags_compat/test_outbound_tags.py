"""Outbound message-tags: server-time and account-tag on PRIVMSG."""

import asyncio
import re
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


async def test_s2s_time_tag_relayed_with_server_time(ircd_network, services):
    """A remote PRIVMSG with @time= must be relayed to clients with server-time."""
    hub = ircd_network["hub"]

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["server-time", "message-tags"])
    await observer.register("mtagobs2", "testuser", "Tag Time Obs")

    try:
        numnick = await services.wait_for_user("mtagobs2")
        stamp = "2020-01-15T12:34:56.789Z"
        await services._send(
            f"@time={stamp} {services._num} P {numnick} :hello timed"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.tags.startswith(f"time={stamp}"), msg.raw
        assert msg.params[-1] == "hello timed"
    finally:
        try:
            await observer.send("QUIT :cleanup")
        except Exception:
            pass
        await observer.disconnect()


async def test_local_privmsg_gets_server_time(ircd_network):
    """Locally originated PRIVMSG gets a server-time tag when negotiated."""
    hub = ircd_network["hub"]

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register("mtaglocal", "testuser", "Tag Local Sender")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["server-time"])
    await observer.register("mtaglocobs", "testuser", "Tag Local Obs")

    try:
        await sender.send("JOIN #mtagtest")
        await observer.send("JOIN #mtagtest")
        await asyncio.sleep(0.3)

        await sender.send("PRIVMSG #mtagtest :local hello")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.tags.startswith("time="), msg.raw
        assert re.match(r"time=\d{4}-\d{2}-\d{2}T", msg.tags), msg.tags
        assert msg.params[-1] == "local hello"
    finally:
        for c in (sender, observer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_hub_forwards_time_tag_on_s2s_channel(ircd_network, services):
    """Hub must emit @time= on S2S channel PRIVMSG for downstream servers."""
    hub = ircd_network["hub"]
    channel = "#s2stime"

    down_num = await services.send_downstream_server("down.s2s.test", 90)
    await services.send_downstream_nick(
        down_num, "SvcBot", server_numeric=90, client_num=1,
    )
    await services.send_downstream_join("SvcBot", channel)
    await asyncio.sleep(0.3)

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("s2slocal", "testuser", "Local User")

    try:
        await user.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)
        await user.send(f"PRIVMSG {channel} :relay check")

        deadline = asyncio.get_event_loop().time() + 5.0
        tagged = None
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            # _recv auto-answers PINGs; keep tags on the returned line.
            line = await services._recv(timeout=max(remaining, 0.1))
            if "@time=" in line and " P " in f" {line} " and channel in line:
                tagged = line
                break
        assert tagged, "expected @time= on S2S channel PRIVMSG"
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_network_features_off_suppresses_s2s_tags(ircd_network, services):
    """NETWORK_FEATURES=FALSE must not prefix S2S PRIVMSG with @time=."""
    hub = ircd_network["hub"]
    channel = "#s2snofeat"

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("nofeatop", "oper", "Oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)
    await oper.send("SET NETWORK_FEATURES FALSE")
    await oper.wait_for("284", timeout=8.0)

    down_num = await services.send_downstream_server("down.nofeat.test", 91)
    await services.send_downstream_nick(
        down_num, "NoFeatBot", server_numeric=91, client_num=1,
    )
    await services.send_downstream_join("NoFeatBot", channel)
    await asyncio.sleep(0.3)

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("nofeatloc", "testuser", "Local User")

    try:
        await user.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)
        await user.send(f"PRIVMSG {channel} :no tags please")

        deadline = asyncio.get_event_loop().time() + 5.0
        saw = None
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            line = await services._recv(timeout=max(remaining, 0.1))
            if " P " in f" {line} " and channel in line and "no tags please" in line:
                saw = line
                break
        assert saw, "expected S2S PRIVMSG without requiring tags"
        assert not saw.lstrip().startswith("@"), saw
        assert "@time=" not in saw, saw
    finally:
        try:
            await oper.send("SET NETWORK_FEATURES TRUE")
            await oper.wait_for("284", timeout=8.0)
        except Exception:
            pass
        for c in (user, oper):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_network_features_off_suppresses_s2s_tagmsg(ircd_network, services):
    """NETWORK_FEATURES=FALSE must not relay TAGMSG (TM) to servers."""
    hub = ircd_network["hub"]
    channel = "#s2snotagmsg"

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("notagmsgop", "oper", "Oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)
    await oper.send("SET NETWORK_FEATURES FALSE")
    await oper.wait_for("284", timeout=8.0)

    down_num = await services.send_downstream_server("down.notm.test", 92)
    await services.send_downstream_nick(
        down_num, "NoTmBot", server_numeric=92, client_num=1,
    )
    await services.send_downstream_join("NoTmBot", channel)
    await asyncio.sleep(0.3)

    local_obs = IRCClient()
    await local_obs.connect(hub["host"], hub["port"])
    await local_obs.negotiate_cap(["message-tags"])
    await local_obs.register("notmlocobs", "testuser", "Local TAGMSG Obs")

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.negotiate_cap(["message-tags"])
    await user.register("notmloc", "testuser", "Local TAGMSG Sender")

    try:
        await user.send(f"JOIN {channel}")
        await local_obs.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)

        # Drain any join noise on the services link before the TAGMSG.
        deadline = asyncio.get_event_loop().time() + 0.5
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            try:
                await services._recv(timeout=max(remaining, 0.05))
            except (asyncio.TimeoutError, TimeoutError):
                break

        await user.send(f"@+example.com/foo=nofeat TAGMSG {channel}")

        # Local clients still receive TAGMSG when NETWORK_FEATURES is off.
        local_msg = await local_obs.wait_for("TAGMSG", timeout=5.0)
        assert local_msg.params[0] == channel, local_msg.raw

        # Remote peers must not see TM (or a tagged TM) at all.
        deadline = asyncio.get_event_loop().time() + 2.5
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            try:
                line = await services._recv(timeout=max(remaining, 0.1))
            except (asyncio.TimeoutError, TimeoutError):
                break
            body = line.lstrip()
            if body.startswith("@"):
                body = body.split(" ", 1)[-1]
            tokens = body.split()
            assert not (len(tokens) >= 2 and tokens[1] == "TM"), (
                f"TAGMSG was relayed S2S while NETWORK_FEATURES=FALSE: {line}"
            )
    finally:
        try:
            await oper.send("SET NETWORK_FEATURES TRUE")
            await oper.wait_for("284", timeout=8.0)
        except Exception:
            pass
        for c in (user, local_obs, oper):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_s2s_protocol_commands_have_no_time_tag(ircd_network, services):
    """P10 link PING/PONG (G/Z) and lag probes (RI/RO) must not get @time=."""
    # G/Z: server-link keepalive (not client PING).
    await services._send(f"{services._num} G !notime :hub.test.net")
    deadline = asyncio.get_event_loop().time() + 5.0
    saw_pong = False
    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        line = await services._recv_raw(timeout=max(remaining, 0.1))
        payload = line.lstrip()
        body = payload.split(" ", 1)[-1] if payload.startswith("@") else payload
        tokens = body.split()
        if len(tokens) >= 2 and tokens[1] == "Z":
            saw_pong = True
            assert not payload.startswith("@"), line
            assert "@time=" not in line, line
            break
        if len(tokens) >= 2 and tokens[1] == "G":
            cookie = tokens[2].lstrip("!") if len(tokens) > 2 else tokens[-1]
            await services._send(f"{services._num} Z {services._num} :{cookie}")
    assert saw_pong, "expected an S2S PONG (Z) without @time="

    # RI/RO: oper RPING lag probe between servers.
    hub = ircd_network["hub"]
    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("rpingop", "oper", "Oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)
    try:
        await oper.send("RPING services.test.net")
        deadline = asyncio.get_event_loop().time() + 8.0
        saw_ri = False
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            line = await services._recv_raw(timeout=max(remaining, 0.1))
            payload = line.lstrip()
            body = payload.split(" ", 1)[-1] if payload.startswith("@") else payload
            tokens = body.split()
            if len(tokens) >= 2 and tokens[1] in ("RI", "RO"):
                saw_ri = True
                assert not payload.startswith("@"), line
                assert "@time=" not in line, line
                break
            if len(tokens) >= 2 and tokens[1] == "G":
                cookie = tokens[2].lstrip("!") if len(tokens) > 2 else tokens[-1]
                await services._send(f"{services._num} Z {services._num} :{cookie}")
        assert saw_ri, "expected S2S RPING/RPONG (RI/RO) without @time="
    finally:
        try:
            await oper.send("QUIT :cleanup")
        except Exception:
            pass
        await oper.disconnect()


async def test_network_time_off_local_stamp_no_s2s_time(ircd_network, services):
    """NETWORK_TIME=FALSE: no @time= on P10; clients get a local stamp."""
    hub = ircd_network["hub"]
    channel = "#s2snettime"

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("nettimeop", "oper", "Oper")
    await oper.send("OPER testoper operpass")
    await oper.wait_for("381", timeout=10.0)
    await oper.send("SET NETWORK_TIME FALSE")
    await oper.wait_for("284", timeout=8.0)

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.negotiate_cap(["server-time", "message-tags"])
    await observer.register("nettimeobs", "testuser", "Net Time Obs")

    down_num = await services.send_downstream_server("down.nettime.test", 92)
    await services.send_downstream_nick(
        down_num, "NetTimeBot", server_numeric=92, client_num=1,
    )
    await services.send_downstream_join("NetTimeBot", channel)
    await asyncio.sleep(0.3)

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("nettimeloc", "testuser", "Local User")

    try:
        numnick = await services.wait_for_user("nettimeobs")
        stamp = "2020-01-15T12:34:56.789Z"
        await services._send(
            f"@time={stamp} {services._num} P {numnick} :hello remote"
        )
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.tags.startswith("time="), msg.raw
        assert stamp not in msg.tags, msg.raw
        assert re.match(r"time=\d{4}-\d{2}-\d{2}T", msg.tags), msg.tags
        assert msg.params[-1] == "hello remote"

        await user.send(f"JOIN {channel}")
        await observer.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)
        await user.send(f"PRIVMSG {channel} :no federated time")

        deadline = asyncio.get_event_loop().time() + 5.0
        saw = None
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            line = await services._recv(timeout=max(remaining, 0.1))
            if " P " in f" {line} " and channel in line and "no federated time" in line:
                saw = line
                break
        assert saw, "expected S2S PRIVMSG"
        assert "@time=" not in saw, saw
    finally:
        try:
            await oper.send("SET NETWORK_TIME TRUE")
            await oper.wait_for("284", timeout=8.0)
        except Exception:
            pass
        for c in (user, observer, oper):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
