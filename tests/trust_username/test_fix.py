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
    apply_hide,
    hidden_host,
    hide_via_services,
    user_from_prefix,
    whois_userline,
)


pytestmark = pytest.mark.multi_server

# Local hub client: account via AC; +x via services OPMODE or client MODE.
_HIDE_PATHS = [
    pytest.param("ac", "opmode", id="ac-opmode"),
    pytest.param("ac", "mode", id="ac-mode"),
]


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


async def _wait_join_from(observer: IRCClient, nick: str, timeout: float = 5.0):
    """Wait for JOIN from ``nick`` (skip observer's own buffered JOIN)."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        msg = await observer.wait_for("JOIN", timeout=timeout)
        if msg.prefix and msg.prefix.startswith(f"{nick}!"):
            return msg
    raise AssertionError(f"Did not see JOIN from {nick!r}")


async def _setup_hide_subject(
    hub,
    services,
    *,
    nick: str,
    channel: str,
    observer: IRCClient,
):
    """Register local nick on channel with observer; return (user, numnick, real_host)."""
    await observer.send(f"JOIN {channel}")
    await observer.wait_for("366")

    user = IRCClient()
    await user.connect(hub["host"], hub["port"])
    await user.register(nick, "testuser", "Test User")
    await user.send(f"JOIN {channel}")
    await user.wait_for("366")
    await _wait_join_from(observer, nick)
    numnick = await services.wait_for_user(nick)
    old_user, real_host = await whois_userline(observer, nick)
    assert old_user == "~testuser", f"Expected tilded WHOIS user, got {old_user!r}"
    return user, numnick, real_host


@pytest.mark.parametrize("account_via,x_via", _HIDE_PATHS)
async def test_hide_quit_keeps_tilded_prefix_then_untilded_join(
    ircd_network, services, account_via, x_via
):
    """No-chghost clients: QUIT prefix stays ~user@realhost; JOIN is user@hidden.

    Covers +x via services OPMODE or local client MODE after ACCOUNT.
    """
    hub = ircd_network["hub"]
    account = f"Join{account_via}{x_via}"[:12]
    channel = f"#tu_j_{account_via}_{x_via}"
    # Distinct nicks: observer must not be a prefix-extension of the subject.
    nick = f"tj{account_via[0]}{x_via[0]}"
    onick = f"oj{account_via[0]}{x_via[0]}"

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    await observer.register(onick, "testuser", "Test User")

    user = None
    try:
        user, numnick, real_host = await _setup_hide_subject(
            hub,
            services,
            nick=nick,
            channel=channel,
            observer=observer,
        )
        assert real_host != hidden_host(account)

        await apply_hide(
            services,
            nick,
            account,
            account_via=account_via,
            x_via=x_via,
            user=user,
            numnick=numnick,
        )

        quit_msg = None
        join_msg = None
        seen = []
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            msg = await observer.recv(timeout=2.0)
            seen.append(msg)
            if not (msg.prefix and msg.prefix.startswith(f"{nick}!")):
                continue
            if msg.command == "QUIT":
                quit_msg = msg
            elif msg.command == "JOIN":
                join_msg = msg
                break

        assert quit_msg is not None, f"Did not see transitional QUIT; got: {seen}"
        assert user_from_prefix(quit_msg.prefix) == "~testuser", (
            f"QUIT prefix should keep old tilded username, got {quit_msg.prefix!r}"
        )
        assert quit_msg.prefix.endswith(f"@{real_host}"), (
            f"QUIT prefix should keep old real host {real_host!r}, got {quit_msg.prefix!r}"
        )
        assert not quit_msg.prefix.endswith(f"@{hidden_host(account)}"), (
            f"QUIT prefix must not use hidden host yet, got {quit_msg.prefix!r}"
        )

        assert join_msg is not None, f"Did not see hidden user's re-JOIN; got: {seen}"
        assert user_from_prefix(join_msg.prefix) == "testuser", (
            f"JOIN prefix should use untilded username, got {join_msg.prefix!r}"
        )
        assert join_msg.prefix.endswith(f"@{hidden_host(account)}"), (
            f"JOIN prefix should use hidden host, got {join_msg.prefix!r}"
        )
    finally:
        for client in (user, observer):
            if client is None:
                continue
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


@pytest.mark.parametrize("account_via,x_via", _HIDE_PATHS)
async def test_hide_chghost_keeps_tilded_prefix_params_untilded(
    ircd_network, services, account_via, x_via
):
    """chghost clients: CHGHOST prefix stays ~user@realhost; params are new identity.

    Covers +x via services OPMODE or local client MODE after ACCOUNT.
    """
    hub = ircd_network["hub"]
    account = f"Chg{account_via}{x_via}"[:12]
    channel = f"#tu_c_{account_via}_{x_via}"
    nick = f"tc{account_via[0]}{x_via[0]}"
    onick = f"oc{account_via[0]}{x_via[0]}"

    observer = IRCClient()
    await observer.connect(hub["host"], hub["port"])
    acked = await observer.negotiate_cap(["chghost"])
    if "chghost" not in acked:
        await observer.disconnect()
        pytest.skip("chghost not supported on this build")
    await observer.register(onick, "testuser", "Test User")
    user = None
    try:
        user, numnick, real_host = await _setup_hide_subject(
            hub,
            services,
            nick=nick,
            channel=channel,
            observer=observer,
        )
        assert real_host != hidden_host(account)

        await apply_hide(
            services,
            nick,
            account,
            account_via=account_via,
            x_via=x_via,
            user=user,
            numnick=numnick,
        )

        chg_msg = None
        seen = []
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            msg = await observer.recv(timeout=2.0)
            seen.append(msg)
            if msg.command == "CHGHOST" and msg.prefix and msg.prefix.startswith(f"{nick}!"):
                chg_msg = msg
                break
            if msg.command == "JOIN" and msg.prefix and msg.prefix.startswith(f"{nick}!"):
                pytest.fail(
                    f"chghost client saw QUIT/JOIN hide cycle instead of CHGHOST: {msg}"
                )
        assert chg_msg is not None, f"Did not see CHGHOST for {nick}; got: {seen}"
        assert len(chg_msg.params) >= 2, f"CHGHOST params incomplete: {chg_msg}"
        assert chg_msg.params[0] == "testuser", (
            f"CHGHOST user should be untilded, got {chg_msg.params[0]!r}"
        )
        assert not chg_msg.params[0].startswith("~"), chg_msg.params[0]
        assert chg_msg.params[1] == hidden_host(account), (
            f"CHGHOST host should be hidden host, got {chg_msg.params[1]!r}"
        )
        prefix_user = user_from_prefix(chg_msg.prefix)
        assert prefix_user == "~testuser", (
            f"CHGHOST prefix should keep old tilded username, got {chg_msg.prefix!r}"
        )
        assert chg_msg.prefix.endswith(f"@{real_host}"), (
            f"CHGHOST prefix should keep old real host {real_host!r}, got {chg_msg.prefix!r}"
        )
        assert not chg_msg.prefix.endswith(f"@{hidden_host(account)}"), (
            f"CHGHOST prefix must not use hidden host, got {chg_msg.prefix!r}"
        )
    finally:
        for client in (user, observer):
            if client is None:
                continue
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
