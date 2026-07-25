"""account-notify CAP including notify to self (commit d4109f5).

Clients with the CAP (including the logged-in user) see ``ACCOUNT <name>``.
Clients without the CAP — including the logged-in user themselves — must
not receive ACCOUNT. Covers local and hub-services→leaf.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import connect_services, drain_briefly, make_cap_client

pytestmark = pytest.mark.multi_server


@pytest.fixture
async def services(ircd_network):
    srv = await connect_services(ircd_network["hub"])
    yield srv
    await srv.disconnect()


async def test_account_notify_with_and_without_cap(ircd_network, services):
    """Self + peers with CAP see ACCOUNT; without CAP they do not."""
    hub = ircd_network["hub"]
    chan = "#acct_notify"

    subject = await make_cap_client(
        hub["host"], hub["port"], "acctself", ["account-notify"]
    )
    cap = await make_cap_client(
        hub["host"], hub["port"], "acctcap", ["account-notify"]
    )
    nocap = await make_cap_client(hub["host"], hub["port"], "acctnoc")

    try:
        for c in (subject, cap, nocap):
            await c.send(f"JOIN {chan}")
            await c.wait_for("JOIN")
        await asyncio.sleep(0.3)
        await drain_briefly(subject)
        await drain_briefly(cap)
        await drain_briefly(nocap)

        numnick = await services.wait_for_user("acctself")
        await services.send_account(numnick, "AcctName")
        await asyncio.sleep(0.4)

        self_msg = await subject.wait_for_user_msg("ACCOUNT", timeout=3.0)
        assert self_msg.prefix and self_msg.prefix.lower().startswith("acctself!")
        assert self_msg.params[0] == "AcctName"

        peer_msg = await cap.wait_for_user_msg("ACCOUNT", timeout=3.0)
        assert peer_msg.prefix and peer_msg.prefix.lower().startswith("acctself!")
        assert peer_msg.params[0] == "AcctName"

        await nocap.assert_no_message("ACCOUNT", timeout=1.5)
    finally:
        for c in (subject, cap, nocap):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_account_notify_self_without_cap_gets_nothing(ircd_network, services):
    """The logged-in user without account-notify must not receive ACCOUNT."""
    hub = ircd_network["hub"]
    chan = "#acct_self_nocap"

    subject = await make_cap_client(hub["host"], hub["port"], "selfnoc")
    cap_peer = await make_cap_client(
        hub["host"], hub["port"], "selfpeer", ["account-notify"]
    )

    try:
        await subject.send(f"JOIN {chan}")
        await subject.wait_for("JOIN")
        await cap_peer.send(f"JOIN {chan}")
        await cap_peer.wait_for("JOIN")
        await asyncio.sleep(0.3)
        await drain_briefly(subject)
        await drain_briefly(cap_peer)

        numnick = await services.wait_for_user("selfnoc")
        await services.send_account(numnick, "NoCapAcct")
        await asyncio.sleep(0.4)

        # CAP peer still sees it
        peer_msg = await cap_peer.wait_for_user_msg("ACCOUNT", timeout=3.0)
        assert peer_msg.params[0] == "NoCapAcct"

        # Subject without CAP must not
        await subject.assert_no_message("ACCOUNT", timeout=1.5)
    finally:
        for c in (subject, cap_peer):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_account_notify_across_servers(ircd_network, services):
    """ACCOUNT via hub services notifies CAP clients on a leaf."""
    leaf = ircd_network["leaf1"]
    chan = "#acct_s2s"

    leaf_user = await make_cap_client(
        leaf["host"], leaf["port"], "leafusr", ["account-notify"]
    )
    leaf_peer = await make_cap_client(
        leaf["host"], leaf["port"], "leafpeer", ["account-notify"]
    )
    leaf_nocap = await make_cap_client(leaf["host"], leaf["port"], "leafnoc")

    try:
        for c in (leaf_user, leaf_peer, leaf_nocap):
            await c.send(f"JOIN {chan}")
            await c.wait_for("JOIN")
        await asyncio.sleep(0.4)
        await drain_briefly(leaf_user)
        await drain_briefly(leaf_peer)
        await drain_briefly(leaf_nocap)

        leaf_numnick = await services.wait_for_user("leafusr")
        await services.send_account(leaf_numnick, "LeafLocal")
        await asyncio.sleep(0.5)

        self_msg = await leaf_user.wait_for_user_msg("ACCOUNT", timeout=5.0)
        assert self_msg.params[0] == "LeafLocal"

        peer_msg = await leaf_peer.wait_for_user_msg("ACCOUNT", timeout=5.0)
        assert peer_msg.params[0] == "LeafLocal"

        await leaf_nocap.assert_no_message("ACCOUNT", timeout=1.5)
    finally:
        for c in (leaf_user, leaf_peer, leaf_nocap):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
