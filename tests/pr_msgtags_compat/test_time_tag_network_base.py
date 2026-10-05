"""@time= must be stamped from network time (TStime), not the raw system clock.

Every P10 epoch (channel creation, lastnick, topic time, ...) is TStime(),
i.e. the system clock adjusted by SETTIME.  The server-time tag must share
that base so that stamps agree with the timestamps clients already see and
with what every peer stamps.  We shift the hub's network time with SETTIME
from a linked server and check that both the invented S2S @time= and the
locally-stamped client-facing @time= follow the shift.
"""

import asyncio
import re
import time
from datetime import datetime, timezone

import pytest

from irc_client import IRCClient
from p10_server import P10Server

pytestmark = pytest.mark.multi_server

_SHIFT = 3600  # seconds; well above the 60s CREATE skew threshold
_SLACK = 10    # tolerated distance between stamp and expected network time

_S2S_TIME = re.compile(r"^@time=(\S+) ")
_CLIENT_TIME = re.compile(r"(?:^|;)time=([^;]+)")


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


def _iso_to_epoch(value: str) -> float:
    dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.replace(tzinfo=timezone.utc).timestamp()


async def _wait_s2s(services: P10Server, token: str, *, contain: str,
                    timeout: float = 8.0) -> str:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        line = await services._recv(timeout=max(remaining, 0.1))
        if services._get_token(line) == token and contain in line:
            return line
    raise TimeoutError(f"timed out waiting for S2S {token!r} containing {contain!r}")


async def _settime(services: P10Server, when: int) -> None:
    """SETTIME the hub (and, via the hub, the rest of the test network)."""
    await services._send(f"{services.server_numnick} SE {when}")
    await asyncio.sleep(0.3)


async def test_time_tag_follows_settime(ircd_network, services):
    """After SETTIME +1h, S2S and client @time= are ~1h ahead of wall clock."""
    hub = ircd_network["hub"]
    channel = "#tsbase"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.negotiate_cap(["server-time"])
    await user.register("tsbaseuser", "testuser", "TS Base User")

    shifted = False
    try:
        await user.send(f"JOIN {channel}")
        await asyncio.sleep(0.3)

        down_num = await services.send_downstream_server("down.tsbase.test", 94)
        bot = await services.send_downstream_nick(
            down_num, "TsBot", server_numeric=94, client_num=1,
        )
        await services.send_downstream_join("TsBot", channel)
        await asyncio.sleep(0.3)
        user_num = await services.wait_for_user("tsbaseuser")

        # Baseline: with TSoffset 0, the stamp tracks the wall clock.
        await user.send(f"PRIVMSG {channel} :before shift")
        line = await _wait_s2s(services, "P", contain="before shift")
        m = _S2S_TIME.match(line)
        assert m, f"expected @time= on S2S PRIVMSG: {line}"
        assert abs(_iso_to_epoch(m.group(1)) - time.time()) < _SLACK, line

        # Shift the network clock forward one hour.
        await _settime(services, int(time.time()) + _SHIFT)
        shifted = True

        # Invented S2S @time= (client -> server P line) must follow TStime.
        await user.send(f"PRIVMSG {channel} :after shift")
        line = await _wait_s2s(services, "P", contain="after shift")
        m = _S2S_TIME.match(line)
        assert m, f"expected @time= on S2S PRIVMSG: {line}"
        s2s_delta = _iso_to_epoch(m.group(1)) - time.time()
        assert abs(s2s_delta - _SHIFT) < _SLACK, (
            f"S2S @time= did not follow SETTIME: delta {s2s_delta:.0f}s, line {line}"
        )

        # Locally stamped client-facing @time= (untagged upstream P line,
        # so the hub uses its own delivery time) must follow TStime too.
        await services.send_privmsg(bot, user_num, "hello from bot")
        msg = await user.wait_for_message_with_text("PRIVMSG", "hello from bot", timeout=8.0)
        m = _CLIENT_TIME.search(msg.tags)
        assert m, f"expected time= tag on client PRIVMSG: {msg.raw}"
        client_delta = _iso_to_epoch(m.group(1)) - time.time()
        assert abs(client_delta - _SHIFT) < _SLACK, (
            f"client server-time did not follow SETTIME: delta {client_delta:.0f}s, "
            f"raw {msg.raw}"
        )
    finally:
        if shifted:
            # Put the whole test network back on the wall clock so later
            # tests in this session are unaffected.
            await _settime(services, int(time.time()))
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()
