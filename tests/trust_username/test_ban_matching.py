"""Comprehensive channel-ban matching for TRUST_USERNAME paired identities.

When a user is fully hidden (+x + account), bans must match these identities:

  ~user@realhost          (real)
  user@account.hiddenhost (visible)

Mixed forms such as user@realhost must not match.
"""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server

from trust_username.helpers import (
    HIDDEN_HOST_SUFFIX,
    hidden_host,
    hide_via_services,
    oper_up,
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


async def _ban_join_check(
    ircd_network,
    services,
    *,
    channel: str,
    account: str,
    nick_op: str,
    nick_victim: str,
    ban_mask: str,
    expect_banned: bool,
    capture_real_host: bool = False,
):
    """Hide victim, set ban_mask, re-JOIN, assert 474 or 366."""
    hub = ircd_network["hub"]

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register(nick_op, "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register(nick_victim, "testuser", "Test User")

    real_host = None
    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        if capture_real_host:
            _, real_host = await whois_userline(chanop, nick_victim)
            assert not real_host.endswith(HIDDEN_HOST_SUFFIX), real_host

        await hide_via_services(services, nick_victim, account)
        vis_host = hidden_host(account)

        # Confirm visible WHOIS form after hide.
        vis_user, whois_host = await whois_userline(chanop, nick_victim)
        assert vis_user == "testuser", f"Expected visible untilded user, got {vis_user!r}"
        assert whois_host == vis_host

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        mask = ban_mask.format(real_host=real_host, vis_host=vis_host)
        await chanop.send(f"MODE {channel} +b {mask}")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        if expect_banned:
            msg = await victim.wait_for("474", timeout=5.0)
            assert msg.command == "474", f"Expected ban for {mask!r}, got: {msg}"
        else:
            msg = await victim.wait_for("366", timeout=5.0)
            assert msg.command == "366", (
                f"Expected JOIN success for {mask!r}, got: {msg}"
            )
        return mask, real_host, vis_host
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


# --- Should match: real identity ---

async def test_ban_real_tilded_user_any_host(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_r1", account="TuBanR1",
        nick_op="tubr1o", nick_victim="tubr1v",
        ban_mask="*!~testuser@*",
        expect_banned=True,
    )


async def test_ban_real_tilded_user_realhost(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_r2", account="TuBanR2",
        nick_op="tubr2o", nick_victim="tubr2v",
        ban_mask="*!~testuser@{real_host}",
        expect_banned=True,
        capture_real_host=True,
    )


async def test_ban_real_tilded_user_hiddenhost(ircd_network, services):
    """Classic path: real ~user still matches against the hidden host field."""
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_r3", account="TuBanR3",
        nick_op="tubr3o", nick_victim="tubr3v",
        ban_mask="*!~testuser@{vis_host}",
        expect_banned=True,
    )


# --- Should match: visible identity ---

async def test_ban_visible_user_any_host(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_v1", account="TuBanV1",
        nick_op="tubv1o", nick_victim="tubv1v",
        ban_mask="*!testuser@*",
        expect_banned=True,
    )


async def test_ban_visible_user_hiddenhost(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_v2", account="TuBanV2",
        nick_op="tubv2o", nick_victim="tubv2v",
        ban_mask="*!testuser@{vis_host}",
        expect_banned=True,
    )


async def test_ban_any_user_hiddenhost(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_v3", account="TuBanV3",
        nick_op="tubv3o", nick_victim="tubv3v",
        ban_mask="*!*@{vis_host}",
        expect_banned=True,
    )


async def test_ban_nick_visible_user_hiddenhost(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_v4", account="TuBanV4",
        nick_op="tubv4o", nick_victim="tubv4v",
        ban_mask="tubv4v!testuser@{vis_host}",
        expect_banned=True,
    )


# --- Must not match: mixed / wrong identities ---

async def test_ban_rejects_visible_user_realhost(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_n1", account="TuBanN1",
        nick_op="tubn1o", nick_victim="tubn1v",
        ban_mask="*!testuser@{real_host}",
        expect_banned=False,
        capture_real_host=True,
    )


async def test_ban_rejects_wrong_visible_user(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_n2", account="TuBanN2",
        nick_op="tubn2o", nick_victim="tubn2v",
        ban_mask="*!otheruser@{vis_host}",
        expect_banned=False,
    )


async def test_ban_rejects_wrong_hidden_account(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_n3", account="TuBanN3",
        nick_op="tubn3o", nick_victim="tubn3v",
        ban_mask="*!testuser@WrongAcct.users.undernet.org",
        expect_banned=False,
    )


async def test_ban_rejects_unrelated_nick(ircd_network, services):
    await _ban_join_check(
        ircd_network, services,
        channel="#tuban_n4", account="TuBanN4",
        nick_op="tubn4o", nick_victim="tubn4v",
        ban_mask="someoneelse!testuser@{vis_host}",
        expect_banned=False,
    )


# --- Feature off: visible (untilded) identity must not match ---

async def test_ban_feature_off_untilded_does_not_match(ircd_network, services):
    hub = ircd_network["hub"]
    channel = "#tuban_off1"
    account = "TuBanOff1"

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("tuboffo", "testuser", "Test User")
    await oper_up(oper)

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tuboffc", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tuboffv", "testuser", "Test User")

    try:
        await oper.send("SET TRUST_USERNAME FALSE")
        await oper.wait_for("NOTICE", timeout=5.0)

        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        await hide_via_services(services, "tuboffv", account)
        username, host = await whois_userline(chanop, "tuboffv")
        assert username.startswith("~"), username
        assert host == hidden_host(account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        await chanop.send(f"MODE {channel} +b *!testuser@*")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("366", timeout=5.0)
        assert msg.command == "366", (
            f"With TRUST_USERNAME off, untilded ban must not match: {msg}"
        )
    finally:
        try:
            await oper.send("SET TRUST_USERNAME TRUE")
            await oper.wait_for("NOTICE", timeout=3.0)
        except Exception:
            pass
        for client in (oper, chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


async def test_ban_feature_off_tilded_still_matches(ircd_network, services):
    hub = ircd_network["hub"]
    channel = "#tuban_off2"
    account = "TuBanOff2"

    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("tubof2o", "testuser", "Test User")
    await oper_up(oper)

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tubof2c", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tubof2v", "testuser", "Test User")

    try:
        await oper.send("SET TRUST_USERNAME FALSE")
        await oper.wait_for("NOTICE", timeout=5.0)

        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        await hide_via_services(services, "tubof2v", account)

        await victim.send(f"PART {channel}")
        await victim.wait_for("PART")

        await chanop.send(f"MODE {channel} +b *!~testuser@{hidden_host(account)}")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        await victim.send(f"JOIN {channel}")
        msg = await victim.wait_for("474", timeout=5.0)
        assert msg.command == "474"
    finally:
        try:
            await oper.send("SET TRUST_USERNAME TRUE")
            await oper.wait_for("NOTICE", timeout=3.0)
        except Exception:
            pass
        for client in (oper, chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()


# --- Already present: MODE +b should mark banned member ---

async def test_ban_applies_to_existing_member_visible_mask(ircd_network, services):
    """A +b on the visible identity must ban an already-joined hidden user."""
    hub = ircd_network["hub"]
    channel = "#tuban_exm"
    account = "TuBanExM"

    chanop = IRCClient()
    await chanop.connect(hub["host"], hub["port"])
    await chanop.register("tubemo", "testuser", "Test User")

    victim = IRCClient()
    await victim.connect(hub["host"], hub["port"])
    await victim.register("tubemv", "testuser", "Test User")

    try:
        await chanop.send(f"JOIN {channel}")
        await chanop.wait_for("366")
        await victim.send(f"JOIN {channel}")
        await victim.wait_for("366")

        await hide_via_services(services, "tubemv", account)
        vis_host = hidden_host(account)

        await chanop.send(f"MODE {channel} +b *!testuser@{vis_host}")
        await chanop.wait_for("MODE")
        await asyncio.sleep(0.3)

        # Banned members cannot speak.
        await victim.send(f"PRIVMSG {channel} :should be blocked")
        msg = await victim.wait_for("404", timeout=5.0)
        assert msg.command == "404", f"Expected cannot send to channel: {msg}"
    finally:
        for client in (chanop, victim):
            try:
                await client.send("QUIT :cleanup")
            except Exception:
                pass
            await client.disconnect()
