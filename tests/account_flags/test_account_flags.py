"""ACCOUNT id/flags parameter (commit aa4fa7c).

S2S ACCOUNT may carry ``<account> [<acc_id> [<acc_flags>]]``. Flags are
not shown on the client ACCOUNT CAP wire; they appear in the NICK burst
as ``account:id:flags``.

Prod rolling-upgrade behaviour, multi-hop flag relay after bare-name
registration, and NETWORK_FEATURES gating live in
``pr_network_features_compat/`` (A prod — B — C + spies).
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import burst_lines, connect_services, make_cap_client, nick_burst_modes
from p10_server import P10Server, strip_msg_tags

pytestmark = pytest.mark.multi_server


@pytest.fixture
async def services(ircd_network):
    srv = await connect_services(ircd_network["hub"])
    yield srv
    await srv.disconnect()


async def test_account_flags_in_nick_burst(ircd_network, services):
    """After ACCOUNT with id+flags, a later server burst includes account:id:flags."""
    hub = ircd_network["hub"]

    user = await make_cap_client(hub["host"], hub["port"], "acctflg")
    numnick = await services.wait_for_user("acctflg")
    await services.send_account(numnick, "FlagAcct", acc_id=99, acc_flags=5)
    await asyncio.sleep(0.4)

    await services.disconnect()
    observer = P10Server(
        name="services.test.net",
        numeric=4,
        password="testpass",
    )
    await observer.connect(hub["host"], hub["server_port"])
    await observer.handshake()
    try:
        nick_lines = [
            line for line in burst_lines(observer, "N")
            if strip_msg_tags(line).split()[2:3] == ["acctflg"]
        ]
        assert nick_lines, f"No NICK burst for acctflg in {observer.received[-30:]!r}"
        modes = nick_burst_modes(nick_lines[-1])
        assert "FlagAcct:99:5" in modes, (
            f"Expected account:id:flags in NICK burst modes {modes!r} "
            f"from line {nick_lines[-1]!r}"
        )
    finally:
        await observer.disconnect()
        await user.disconnect()


async def test_account_flags_not_on_client_account_line(ircd_network, services):
    """Client ACCOUNT CAP wire is account name only, even when flags were set."""
    hub = ircd_network["hub"]
    chan = "#acct_flags_cap"

    subject = await make_cap_client(
        hub["host"], hub["port"], "flgself", ["account-notify"]
    )
    peer = await make_cap_client(
        hub["host"], hub["port"], "flgpeer", ["account-notify"]
    )

    try:
        await subject.send(f"JOIN {chan}")
        await subject.wait_for("JOIN")
        await peer.send(f"JOIN {chan}")
        await peer.wait_for("JOIN")
        await asyncio.sleep(0.3)

        numnick = await services.wait_for_user("flgself")
        await services.send_account(numnick, "FlagOnly", acc_id=7, acc_flags=3)
        await asyncio.sleep(0.4)

        for client in (subject, peer):
            msg = await client.wait_for_user_msg("ACCOUNT", timeout=3.0)
            assert msg.params[0] == "FlagOnly"
            assert len(msg.params) == 1
    finally:
        for c in (subject, peer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
