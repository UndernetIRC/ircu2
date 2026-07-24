"""Integration tests for TRUST_USERNAME (+x visible username without ~).

When TRUST_USERNAME is enabled and a user is fully hidden (+x with account),
other users should see the username without a leading tilde alongside the
hidden host. Internal records and server propagation must keep the tilded
username.
"""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server

from trust_username.helpers import (
    hidden_host,
    hide_via_services,
    oper_up,
    user_from_prefix,
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


async def test_services_account_then_opmode_shows_untilded_whois(
    ircd_network, services
):
    """ACCOUNT then OPMODE +x via services should expose untilded WHOIS user."""
    hub = ircd_network["hub"]
    account = "SvcAcct71"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71u", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("tu71o", "testuser", "Test User")

    try:
        await hide_via_services(services, "tu71u", account)

        username, host = await whois_userline(observer, "tu71u")
        assert username == "testuser", f"Expected untilded username, got {username!r}"
        assert username != "~testuser"
        assert host == hidden_host(account), f"Expected hidden host, got {host!r}"
        assert not username.startswith("~")
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_join_without_chghost_shows_untilded_prefix(ircd_network, services):
    """Clients without chghost should see QUIT/JOIN with untilded user@hidden.host."""
    hub = ircd_network["hub"]
    account = "JoinAcct71"
    channel = "#tu71_join"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71j", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("tu71w", "testuser", "Test User")

    try:
        await user.send(f"JOIN {channel}")
        await user.wait_for("366")
        await observer.send(f"JOIN {channel}")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await hide_via_services(services, "tu71j", account)

        join_msg = None
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            msg = await observer.wait_for("JOIN", timeout=2.0)
            if msg.prefix and msg.prefix.startswith("tu71j!"):
                join_msg = msg
                break
        assert join_msg is not None, "Did not see hidden user's re-JOIN"
        prefix_user = user_from_prefix(join_msg.prefix)
        assert prefix_user == "testuser", (
            f"JOIN prefix should use untilded username, got {join_msg.prefix!r}"
        )
        assert join_msg.prefix.endswith(f"@{hidden_host(account)}"), (
            f"JOIN prefix should use hidden host, got {join_msg.prefix!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_chghost_shows_untilded_username(ircd_network, services):
    """Clients with CAP chghost should see CHGHOST with untilded username."""
    hub = ircd_network["hub"]
    account = "ChgAcct71"
    channel = "#tu71_chghost"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71c", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    acked = await observer.negotiate_cap(["chghost"])
    if "chghost" not in acked:
        await observer.disconnect()
        pytest.skip("chghost not supported on this build")
    await observer.register("tu71cg", "testuser", "Test User")

    try:
        await user.send(f"JOIN {channel}")
        await user.wait_for("366")
        await observer.send(f"JOIN {channel}")
        await observer.wait_for("366")
        await user.wait_for("JOIN")

        await hide_via_services(services, "tu71c", account)

        chg_msg = None
        seen = []
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            msg = await observer.recv(timeout=2.0)
            seen.append(msg)
            if msg.command == "CHGHOST" and msg.prefix and msg.prefix.startswith("tu71c!"):
                chg_msg = msg
                break
            if msg.command == "JOIN" and msg.prefix and msg.prefix.startswith("tu71c!"):
                pytest.fail(
                    f"chghost client saw QUIT/JOIN hide cycle instead of CHGHOST: {msg}"
                )
        assert chg_msg is not None, f"Did not see CHGHOST for tu71c; got: {seen}"
        assert len(chg_msg.params) >= 2, f"CHGHOST params incomplete: {chg_msg}"
        assert chg_msg.params[0] == "testuser", (
            f"CHGHOST user should be untilded, got {chg_msg.params[0]!r}"
        )
        assert not chg_msg.params[0].startswith("~"), chg_msg.params[0]
        assert chg_msg.params[1] == hidden_host(account), (
            f"CHGHOST host should be hidden host, got {chg_msg.params[1]!r}"
        )
        prefix_user = user_from_prefix(chg_msg.prefix)
        assert prefix_user == "testuser", (
            f"CHGHOST prefix should use untilded username, got {chg_msg.prefix!r}"
        )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_s2s_nick_keeps_tilded_username(ircd_network, services):
    """Server propagation must still carry the tilded username in NICK bursts."""
    hub = ircd_network["hub"]

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71s", "testuser", "Test User")

    try:
        await services.wait_for_user("tu71s")
        recorded = services.users["tu71s"]["username"]
        assert recorded.startswith("~"), (
            f"S2S NICK should keep tilded username, got {recorded!r}"
        )

        await hide_via_services(services, "tu71s", "S2SAcct")

        assert services.users["tu71s"]["username"].startswith("~"), (
            "Hiding must not rewrite the propagated username"
        )
    finally:
        try:
            await user.send("QUIT :cleanup")
        except Exception:
            pass
        await user.disconnect()


async def test_userhost_shows_untilded_username(ircd_network, services):
    hub = ircd_network["hub"]
    account = "UhAcct71"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register("tu71uh", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register("tu71uh2", "testuser", "Test User")

    try:
        await hide_via_services(services, "tu71uh", account)
        await observer.send("USERHOST tu71uh")
        msg = await observer.wait_for("302", timeout=5.0)
        entry = msg.params[1]
        assert "=+testuser@" in entry, f"USERHOST should be untilded: {entry!r}"
        assert f"@{hidden_host(account)}" in entry
        assert "=+~testuser@" not in entry
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_uhnames_shows_untilded_username(ircd_network, services):
    hub = ircd_network["hub"]
    account = "NamesAcct71"
    channel = "#tu71_names"

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    acked = await user.negotiate_cap(["userhost-in-names"])
    assert "userhost-in-names" in acked
    await user.register("tu71n", "testuser", "Test User")

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    acked = await observer.negotiate_cap(["userhost-in-names"])
    assert "userhost-in-names" in acked
    await observer.register("tu71n2", "testuser", "Test User")

    try:
        await user.send(f"JOIN {channel}")
        await user.wait_for("366")
        await observer.send(f"JOIN {channel}")
        await observer.wait_for("366")

        await hide_via_services(services, "tu71n", account)
        await asyncio.sleep(1.0)

        await observer.send(f"NAMES {channel}")
        msgs = await observer.collect_until("366", timeout=5.0)
        names = [m for m in msgs if m.command == "353"]
        assert names, "Expected NAMES reply after hide"
        joined = " ".join(m.params[-1] for m in names)

        hidden_entry = f"tu71n!testuser@{hidden_host(account)}"
        assert hidden_entry in joined, f"Missing untilded hidden NAMES entry: {joined!r}"
        for token in joined.split():
            nickpart = token[1:] if token.startswith("@") else token
            if nickpart.startswith("tu71n!") and hidden_host(account) in nickpart:
                assert nickpart.startswith(hidden_entry), (
                    f"Hidden user NAMES entry should be untilded: {nickpart!r}"
                )
    finally:
        for client in (user, observer):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
