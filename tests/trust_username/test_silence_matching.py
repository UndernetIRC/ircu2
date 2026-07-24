"""SILENCE matching for TRUST_USERNAME paired identities.

is_silenced() uses find_ban(), so the same paired forms apply:

  ~user@realhost          (real)
  user@account.hiddenhost (visible)

Mixed forms such as user@realhost must not silence.
Silence exceptions use SILENCE +~mask (not channel +e).
"""

import asyncio
import pytest

from irc_client import IRCClient
from p10_server import P10Server

from trust_username.helpers import (
    HIDDEN_HOST_SUFFIX,
    hidden_host,
    hide_via_services,
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


async def _setup_hidden_pair(ircd_network, services, *, nick_target, nick_sender, account):
    """Register target+sender, hide sender, return (target, sender, real_host, vis_host)."""
    hub = ircd_network["hub"]

    target = IRCClient()
    await target.connect(hub["host"], hub["port"])
    await target.register(nick_target, "testuser", "Test User")

    sender = IRCClient()
    await sender.connect(hub["host"], hub["port"])
    await sender.register(nick_sender, "testuser", "Test User")

    _, real_host = await whois_userline(target, nick_sender)
    assert not real_host.endswith(HIDDEN_HOST_SUFFIX), real_host

    await hide_via_services(services, nick_sender, account)
    vis_user, vis_host = await whois_userline(target, nick_sender)
    assert vis_user == "testuser", vis_user
    assert vis_host == hidden_host(account), vis_host

    return target, sender, real_host, vis_host


async def _cleanup(*clients):
    for client in clients:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()


async def _assert_silenced(target: IRCClient, sender: IRCClient, token: str):
    await sender.send(f"PRIVMSG {target.nick} :{token}")
    await target.assert_no_message(command="PRIVMSG")


async def _assert_not_silenced(target: IRCClient, sender: IRCClient, token: str):
    await sender.send(f"PRIVMSG {target.nick} :{token}")
    msg = await target.wait_for("PRIVMSG", timeout=5.0)
    assert msg.command == "PRIVMSG"
    assert token in (msg.params[-1] if msg.params else "")


# --- Should silence: real identity ---

async def test_silence_real_tilded_user_any_host(ircd_network, services):
    target, sender, _, _ = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_r1t", nick_sender="tusil_r1s", account="TuSilR1",
    )
    try:
        await target.silence("*!~testuser@*")
        await _assert_silenced(target, sender, "silenced-real-any")
    finally:
        await _cleanup(target, sender)


async def test_silence_real_tilded_user_realhost(ircd_network, services):
    target, sender, real_host, _ = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_r2t", nick_sender="tusil_r2s", account="TuSilR2",
    )
    try:
        await target.silence(f"*!~testuser@{real_host}")
        await _assert_silenced(target, sender, "silenced-real-host")
    finally:
        await _cleanup(target, sender)


async def test_silence_real_tilded_user_hiddenhost(ircd_network, services):
    """Classic path: real ~user still matches against the hidden host field."""
    target, sender, _, vis_host = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_r3t", nick_sender="tusil_r3s", account="TuSilR3",
    )
    try:
        await target.silence(f"*!~testuser@{vis_host}")
        await _assert_silenced(target, sender, "silenced-real-hidden")
    finally:
        await _cleanup(target, sender)


# --- Should silence: visible identity ---

async def test_silence_visible_user_any_host(ircd_network, services):
    target, sender, _, _ = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_v1t", nick_sender="tusil_v1s", account="TuSilV1",
    )
    try:
        await target.silence("*!testuser@*")
        await _assert_silenced(target, sender, "silenced-vis-any")
    finally:
        await _cleanup(target, sender)


async def test_silence_visible_user_hiddenhost(ircd_network, services):
    target, sender, _, vis_host = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_v2t", nick_sender="tusil_v2s", account="TuSilV2",
    )
    try:
        await target.silence(f"*!testuser@{vis_host}")
        await _assert_silenced(target, sender, "silenced-vis-host")
    finally:
        await _cleanup(target, sender)


async def test_silence_any_user_hiddenhost(ircd_network, services):
    target, sender, _, vis_host = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_v3t", nick_sender="tusil_v3s", account="TuSilV3",
    )
    try:
        await target.silence(f"*!*@{vis_host}")
        await _assert_silenced(target, sender, "silenced-any-hidden")
    finally:
        await _cleanup(target, sender)


# --- Must not silence: mixed / wrong ---

async def test_silence_rejects_visible_user_realhost(ircd_network, services):
    target, sender, real_host, _ = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_n1t", nick_sender="tusil_n1s", account="TuSilN1",
    )
    try:
        await target.silence(f"*!testuser@{real_host}")
        await _assert_not_silenced(target, sender, "not-silenced-mixed")
    finally:
        await _cleanup(target, sender)


async def test_silence_rejects_wrong_visible_user(ircd_network, services):
    target, sender, _, vis_host = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_n2t", nick_sender="tusil_n2s", account="TuSilN2",
    )
    try:
        await target.silence(f"*!otheruser@{vis_host}")
        await _assert_not_silenced(target, sender, "not-silenced-wronguser")
    finally:
        await _cleanup(target, sender)


# --- Silence exception (~) with visible identity ---

async def test_silence_exception_visible_identity_allows_message(ircd_network, services):
    """SILENCE +~mask exempts; visible user@hiddenhost exception must work."""
    target, sender, _, vis_host = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_e1t", nick_sender="tusil_e1s", account="TuSilE1",
    )
    try:
        await target.silence("*!*@*")
        await target.silence(f"~*!testuser@{vis_host}")
        await asyncio.sleep(0.2)
        await _assert_not_silenced(target, sender, "excepted-visible")
    finally:
        await _cleanup(target, sender)


async def test_silence_exception_real_identity_allows_message(ircd_network, services):
    target, sender, real_host, _ = await _setup_hidden_pair(
        ircd_network, services,
        nick_target="tusil_e2t", nick_sender="tusil_e2s", account="TuSilE2",
    )
    try:
        await target.silence("*!*@*")
        await target.silence(f"~*!~testuser@{real_host}")
        await asyncio.sleep(0.2)
        await _assert_not_silenced(target, sender, "excepted-real")
    finally:
        await _cleanup(target, sender)
