"""invite-notify CAP (commit f78fe06).

Chanops with the CAP see INVITE announcements; without CAP (and with
FEAT_ANNOUNCE_INVITES default FALSE) they see nothing. Invitee always
gets INVITE. Covers local and hub→leaf paths.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import drain_briefly, make_cap_client

pytestmark = pytest.mark.multi_server


async def test_invite_notify_cap_negotiation(ircd_network):
    """invite-notify is offered and can be acknowledged."""
    hub = ircd_network["hub"]
    client = await make_cap_client(
        hub["host"], hub["port"], "invcap1", ["invite-notify"]
    )
    try:
        # make_cap_client already required the CAP; re-check via CAP LIST.
        await client.send("CAP LIST")
        msg = await client.wait_for("CAP", timeout=5.0)
        caps = " ".join(msg.params).lower()
        assert "invite-notify" in caps, f"CAP LIST missing invite-notify: {msg.raw}"
    finally:
        await client.disconnect()


async def test_invite_notify_ops_with_and_without_cap(ircd_network):
    """Chanops with invite-notify see INVITE; without CAP they see nothing."""
    hub = ircd_network["hub"]
    chan = "#inv_cap_local"

    inviter = await make_cap_client(hub["host"], hub["port"], "inviter1")
    cap_op = await make_cap_client(
        hub["host"], hub["port"], "capop1", ["invite-notify"]
    )
    nocap_op = await make_cap_client(hub["host"], hub["port"], "nocapop1")
    target = await make_cap_client(hub["host"], hub["port"], "target1")

    try:
        await inviter.send(f"JOIN {chan}")
        await inviter.wait_for("JOIN")
        await cap_op.send(f"JOIN {chan}")
        await cap_op.wait_for("JOIN")
        await nocap_op.send(f"JOIN {chan}")
        await nocap_op.wait_for("JOIN")
        await inviter.send(f"MODE {chan} +oo capop1 nocapop1")
        await asyncio.sleep(0.4)
        await drain_briefly(cap_op)
        await drain_briefly(nocap_op)

        await inviter.send(f"INVITE target1 {chan}")
        await inviter.wait_for("341")

        invitee_msg = await target.wait_for_user_msg("INVITE", timeout=3.0)
        assert invitee_msg.params[0].lower() == "target1"
        assert invitee_msg.params[1].lower() == chan.lower()

        cap_msg = await cap_op.wait_for_user_msg("INVITE", timeout=3.0)
        assert "target1" in " ".join(cap_msg.params).lower()
        assert chan.lower() in " ".join(cap_msg.params).lower()

        await nocap_op.assert_no_message("INVITE", timeout=1.5)
        await nocap_op.assert_no_message("345", timeout=0.5)
    finally:
        for c in (inviter, cap_op, nocap_op, target):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_invite_notify_across_servers(ircd_network):
    """Invite from hub reaches leaf invitee; CAP op on leaf sees notify."""
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    chan = "#inv_cap_s2s"

    inviter = await make_cap_client(hub["host"], hub["port"], "hinviter")
    leaf_cap_op = await make_cap_client(
        leaf["host"], leaf["port"], "lcapop", ["invite-notify"]
    )
    leaf_nocap_op = await make_cap_client(leaf["host"], leaf["port"], "lnocapop")
    target = await make_cap_client(leaf["host"], leaf["port"], "ltarget")

    try:
        await inviter.send(f"JOIN {chan}")
        await inviter.wait_for("JOIN")
        await asyncio.sleep(0.5)

        await leaf_cap_op.send(f"JOIN {chan}")
        await leaf_cap_op.wait_for("JOIN")
        await leaf_nocap_op.send(f"JOIN {chan}")
        await leaf_nocap_op.wait_for("JOIN")
        await inviter.send(f"MODE {chan} +oo lcapop lnocapop")
        await asyncio.sleep(0.5)
        await drain_briefly(leaf_cap_op)
        await drain_briefly(leaf_nocap_op)

        await inviter.send(f"INVITE ltarget {chan}")
        await inviter.wait_for("341")

        invitee_msg = await target.wait_for_user_msg("INVITE", timeout=5.0)
        assert "ltarget" in " ".join(invitee_msg.params).lower()

        cap_msg = await leaf_cap_op.wait_for_user_msg("INVITE", timeout=5.0)
        assert "ltarget" in " ".join(cap_msg.params).lower()

        await leaf_nocap_op.assert_no_message("INVITE", timeout=1.5)
    finally:
        for c in (inviter, leaf_cap_op, leaf_nocap_op, target):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
