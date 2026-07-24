"""Edge cases for TRUST_USERNAME: bans, glines, feature toggle, remote users."""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server

from trust_username.helpers import (
    HIDDEN_HOST_SUFFIX,
    add_gline,
    hidden_host,
    hide_via_services,
    oper_up,
    remove_gline,
    whois_userline,
)


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


async def test_ban_matches_tilded_username_mask(ircd_network, services):
    """Channel bans on ~user must still match the real (tilded) username."""
    hub = ircd_network["hub"]
    channel = "#tu71_ban1"
    account = "BanAcct71"

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tu71bo", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tu71bv", "testuser", "Test User")

    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")
        await chanop.wait_for("JOIN")

        await hide_via_services(services, "tu71bv", account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        await chanop.send(f"MODE {channel} +b *!~testuser@*")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("474", timeout=5.0)
        assert msg.command == "474", f"Expected ban, got: {msg}"
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_ban_matches_untilded_username_mask(ircd_network, services):
    """A ban on the visible (untilded) username must match a fully hidden user."""
    hub = ircd_network["hub"]
    channel = "#tu71_ban2"
    account = "BanAcct72"

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tu72bo", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tu72bv", "testuser", "Test User")

    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        await hide_via_services(services, "tu72bv", account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        await chanop.send(f"MODE {channel} +b *!testuser@*")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("474", timeout=5.0)
        assert msg.command == "474", (
            f"Untilded username ban should match hidden user: {msg}"
        )
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_ban_matches_hidden_host_mask(ircd_network, services):
    """Bans targeting account.hidden.host should match a hidden user."""
    hub = ircd_network["hub"]
    channel = "#tu71_ban3"
    account = "BanAcct73"

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tu73bo", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tu73bv", "testuser", "Test User")

    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        await hide_via_services(services, "tu73bv", account)
        ban_host = hidden_host(account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        await chanop.send(f"MODE {channel} +b *!*@{ban_host}")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("474", timeout=5.0)
        assert msg.command == "474"
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_ban_matches_visible_userhost_mask(ircd_network, services):
    """Ban on visible user@hiddenhost (no ~) must match a fully hidden user."""
    hub = ircd_network["hub"]
    channel = "#tu71_ban4"
    account = "BanAcct74"

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tu74bo", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tu74bv", "testuser", "Test User")

    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        await hide_via_services(services, "tu74bv", account)
        ban_host = hidden_host(account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        await chanop.send(f"MODE {channel} +b *!testuser@{ban_host}")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("474", timeout=5.0)
        assert msg.command == "474", (
            f"Visible user@hiddenhost ban should match: {msg}"
        )
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_ban_does_not_match_mixed_user_realhost(ircd_network, services):
    """Visible username must not match when paired with the real host."""
    hub = ircd_network["hub"]
    channel = "#tu71_ban5"
    account = "BanAcct75"

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tu75bo", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tu75bv", "testuser", "Test User")

    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        # Capture real host before hide; WHOIS will show the hidden host after.
        _, real_host = await whois_userline(chanop, "tu75bv")
        assert not real_host.endswith(HIDDEN_HOST_SUFFIX), (
            f"Expected real host before hide, got {real_host!r}"
        )

        await hide_via_services(services, "tu75bv", account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        # Mixed identity: untilded user + real host must not ban.
        await chanop.send(f"MODE {channel} +b *!testuser@{real_host}")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("366", timeout=5.0)
        assert msg.command == "366", (
            f"Mixed user@realhost ban should not match: {msg}"
        )
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_gline_matches_tilded_username(ircd_network):
    """GLINE on ~user@host must still match users whose internal username is ~user."""
    hub = ircd_network["hub"]

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("tu71op", "operuser", "Test User")
    await oper_up(oper)

    victim = IRCClient()
    gline_mask = None
    try:
        await victim.connect(hub["host"], hub["port"])
        await victim.register("tu71gv", "testuser", "Test User")

        username, host = await whois_userline(oper, "tu71gv")
        assert username.startswith("~"), f"Expected tilded WHOIS user, got {username!r}"

        gline_mask = f"{username}@{host}"
        await add_gline(oper, gline_mask)

        msg = await victim.wait_for("465", timeout=10.0)
        assert msg.command == "465", f"Expected G-line kill, got {msg}"
    finally:
        if gline_mask:
            await remove_gline(oper, gline_mask)
        try:
            await victim.disconnect()
        except Exception:
            pass
        try:
            await oper.send("QUIT :cleanup")
        except Exception:
            pass
        await oper.disconnect()


async def test_gline_does_not_match_untilded_username(ircd_network):
    """GLINE on user@host (no tilde) must not match a ~user connection."""
    hub = ircd_network["hub"]

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("tu72op", "operuser", "Test User")
    await oper_up(oper)

    victim = IRCClient()
    gline_mask = None
    try:
        await victim.connect(hub["host"], hub["port"])
        await victim.register("tu72gv", "testuser", "Test User")

        username, host = await whois_userline(oper, "tu72gv")
        assert username.startswith("~"), f"Expected tilded user, got {username!r}"

        # Mask without tilde must not match the internal ~user record.
        gline_mask = f"testuser@{host}"
        await add_gline(oper, gline_mask)

        await victim.send("PING :alive")
        pong = await victim.wait_for("PONG", timeout=5.0)
        assert pong.command == "PONG", (
            f"Untilded GLINE {gline_mask!r} should not match ~user"
        )
    finally:
        if gline_mask:
            await remove_gline(oper, gline_mask)
        try:
            await victim.send("QUIT :cleanup")
        except Exception:
            pass
        await victim.disconnect()
        try:
            await oper.send("QUIT :cleanup")
        except Exception:
            pass
        await oper.disconnect()


async def test_feature_disabled_keeps_tilde_in_whois(ircd_network, services):
    """SET TRUST_USERNAME FALSE should restore tilded WHOIS display."""
    hub = ircd_network["hub"]
    account = "OffAcct71"

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("tu71fo", "testuser", "Test User")
    await oper_up(oper)

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71fu", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("tu71fw", "testuser", "Test User")

    try:
        await oper.send("SET TRUST_USERNAME FALSE")
        set_reply = await oper.wait_for("NOTICE", timeout=5.0)
        assert set_reply.command != "ERR", f"SET failed: {set_reply}"

        await hide_via_services(services, "tu71fu", account)

        username, host = await whois_userline(observer, "tu71fu")
        assert username.startswith("~"), (
            f"With TRUST_USERNAME off, WHOIS should keep tilde: {username!r}"
        )
        assert host == hidden_host(account)
    finally:
        try:
            await oper.send("SET TRUST_USERNAME TRUE")
            await oper.wait_for("NOTICE", timeout=3.0)
        except Exception:
            pass
        for client in (oper, user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_remote_leaf_user_hidden_via_services(ircd_network, services):
    """Services ACCOUNT/+x on a leaf-connected user should untilde display."""
    leaf1 = ircd_network["leaf1"]
    account = "LeafAcct71"

    user = IRCClient()
    await user.connect(leaf1["host"], leaf1["port"])
    await user.register("tu71lv", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(leaf1["host"], leaf1["port"])
    await observer.register("tu71lw", "testuser", "Test User")

    try:
        await hide_via_services(services, "tu71lv", account)

        username, host = await whois_userline(observer, "tu71lv")
        assert username == "testuser"
        assert host == hidden_host(account)
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_both_account_and_x_required_not_either_or(ircd_network, services):
    """Hidden host and untilded WHOIS user require both ACCOUNT and +x."""
    hub = ircd_network["hub"]
    account = "BothReq71"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71br", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("tu71bw", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("tu71br")

        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        username, host = await whois_userline(observer, "tu71br")
        assert username.startswith("~"), (
            f"+x alone must not strip tilde: {username!r}"
        )
        assert host != hidden_host(account), (
            f"+x alone must not hide host: {host!r}"
        )

        await services.send_account(numnick, account)
        await asyncio.sleep(0.5)

        username, host = await whois_userline(observer, "tu71br")
        assert username.startswith("~"), (
            f"ACCOUNT alone must not strip tilde: {username!r}"
        )
        assert host != hidden_host(account), (
            f"ACCOUNT alone must not hide host: {host!r}"
        )

        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        username, host = await whois_userline(observer, "tu71br")
        assert username == "testuser", (
            f"Both ACCOUNT and +x should untilde username: {username!r}"
        )
        assert host == hidden_host(account), (
            f"Both ACCOUNT and +x should hide host: {host!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_opmode_before_account_requires_second_opmode(ircd_network, services):
    """+x sent before ACCOUNT is ignored until account exists, then +x applies."""
    hub = ircd_network["hub"]
    account = "OrderAcct71"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71or", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("tu71ow", "testuser", "Test User")

    try:
        numnick = await services.wait_for_user("tu71or")
        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        await services.send_account(numnick, account)
        await asyncio.sleep(0.3)

        # Host should not be hidden yet because +x was ignored without account
        username, host = await whois_userline(observer, "tu71or")
        assert host != hidden_host(account), (
            f"Host should not hide until +x is applied with account: {host!r}"
        )

        await services.send_opmode(numnick, "+x")
        await asyncio.sleep(0.5)

        username, host = await whois_userline(observer, "tu71or")
        assert username == "testuser"
        assert host == hidden_host(account)
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
