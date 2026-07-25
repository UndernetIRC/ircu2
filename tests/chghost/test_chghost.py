"""CAP chghost (host-hide without QUIT/JOIN for capable clients).

When a user becomes fully hidden (account + +x), channel peers with
``chghost`` receive ``CHGHOST <user> <newhost>``. Peers without the CAP
see the legacy ``QUIT :Registered`` / ``JOIN`` cycle instead. The
hiding user without chghost gets RPL_HOSTHIDDEN (396).

Covers the username field on CHGHOST (commit d4109f5 used
``cli_user()->username`` so unidented users are included correctly).
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import connect_services, drain_briefly, make_cap_client

pytestmark = pytest.mark.multi_server

HIDDEN_HOST_SUFFIX = "users.undernet.org"


def hidden_host(account: str) -> str:
    return f"{account}.{HIDDEN_HOST_SUFFIX}"


async def _hide(services, nick: str, account: str) -> None:
    numnick = await services.wait_for_user(nick)
    await services.send_account(numnick, account)
    await asyncio.sleep(0.3)
    await services.send_opmode(numnick, "+x")
    await asyncio.sleep(0.4)


@pytest.fixture
async def services(ircd_network):
    srv = await connect_services(ircd_network["hub"])
    yield srv
    await srv.disconnect()


async def test_chghost_cap_sees_chghost_not_quit_join(ircd_network, services):
    """Peers with chghost get CHGHOST; must not see QUIT/JOIN hide cycle."""
    hub = ircd_network["hub"]
    chan = "#chg_cap"
    account = "ChgAcct"

    subject = await make_cap_client(hub["host"], hub["port"], "chgsubj", username="chguser")
    cap = await make_cap_client(
        hub["host"], hub["port"], "chgcap", ["chghost"], username="obsuser"
    )

    try:
        await subject.send(f"JOIN {chan}")
        await subject.wait_for("JOIN")
        await cap.send(f"JOIN {chan}")
        await cap.wait_for("JOIN")
        await asyncio.sleep(0.3)
        await drain_briefly(cap)

        await _hide(services, "chgsubj", account)

        seen = []
        chg = None
        deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < deadline:
            msg = await cap.recv(timeout=2.0)
            seen.append(msg)
            if msg.command == "CHGHOST" and msg.prefix and msg.prefix.lower().startswith("chgsubj!"):
                chg = msg
                break
            if msg.command == "QUIT" and msg.prefix and msg.prefix.lower().startswith("chgsubj!"):
                pytest.fail(f"chghost peer saw QUIT hide cycle: {msg.raw}")
            if msg.command == "JOIN" and msg.prefix and msg.prefix.lower().startswith("chgsubj!"):
                pytest.fail(f"chghost peer saw JOIN hide cycle: {msg.raw}")

        assert chg is not None, f"Expected CHGHOST, got: {[m.raw for m in seen]}"
        assert len(chg.params) >= 2, chg.raw
        # Username from cli_user()->username (may be ~idented depending on auth).
        assert "chguser" in chg.params[0], (
            f"CHGHOST username should include registered user, got {chg.params[0]!r}"
        )
        assert chg.params[1] == hidden_host(account), (
            f"CHGHOST host should be {hidden_host(account)!r}, got {chg.params[1]!r}"
        )
    finally:
        for c in (subject, cap):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_without_chghost_sees_quit_join(ircd_network, services):
    """Peers without chghost see QUIT :Registered then JOIN with new host."""
    hub = ircd_network["hub"]
    chan = "#chg_nocap"
    account = "NoCapAcct"

    subject = await make_cap_client(hub["host"], hub["port"], "chgsubj2", username="chguser")
    nocap = await make_cap_client(hub["host"], hub["port"], "chgnocap", username="obsuser")

    try:
        await subject.send(f"JOIN {chan}")
        await subject.wait_for("JOIN")
        await nocap.send(f"JOIN {chan}")
        await nocap.wait_for("JOIN")
        await asyncio.sleep(0.3)
        await drain_briefly(nocap)

        await _hide(services, "chgsubj2", account)

        quit_msg = None
        join_msg = None
        deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < deadline and (quit_msg is None or join_msg is None):
            msg = await nocap.recv(timeout=2.0)
            if msg.command == "CHGHOST":
                pytest.fail(f"non-chghost peer saw CHGHOST: {msg.raw}")
            if msg.command == "QUIT" and msg.prefix and msg.prefix.lower().startswith("chgsubj2!"):
                quit_msg = msg
            if msg.command == "JOIN" and msg.prefix and msg.prefix.lower().startswith("chgsubj2!"):
                join_msg = msg

        assert quit_msg is not None, "Expected QUIT :Registered for non-chghost peer"
        assert quit_msg.params and "Registered" in quit_msg.params[-1]
        assert join_msg is not None, "Expected re-JOIN with hidden host"
        assert join_msg.prefix.endswith(f"@{hidden_host(account)}"), (
            f"JOIN should use hidden host, got {join_msg.prefix!r}"
        )
    finally:
        for c in (subject, nocap):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()


async def test_subject_without_chghost_gets_hosthidden(ircd_network, services):
    """Hiding user without chghost CAP receives RPL_HOSTHIDDEN (396)."""
    hub = ircd_network["hub"]
    account = "SelfAcct"

    subject = await make_cap_client(hub["host"], hub["port"], "chgself", username="selfuser")
    try:
        await subject.send("JOIN #chg_self")
        await subject.wait_for("JOIN")
        await drain_briefly(subject)

        await _hide(services, "chgself", account)

        msg = await subject.wait_for("396", timeout=5.0)
        assert hidden_host(account) in " ".join(msg.params), (
            f"RPL_HOSTHIDDEN should mention hidden host: {msg.raw}"
        )
    finally:
        try:
            await subject.send("QUIT :cleanup")
        except Exception:
            pass
        await subject.disconnect()


async def test_chghost_across_servers(ircd_network, services):
    """Hub user hide notifies leaf peers with chghost via CHGHOST."""
    hub = ircd_network["hub"]
    leaf = ircd_network["leaf1"]
    chan = "#chg_s2s"
    account = "S2SAcct"

    subject = await make_cap_client(hub["host"], hub["port"], "hchgusr", username="hubuser")
    leaf_cap = await make_cap_client(
        leaf["host"], leaf["port"], "lchgcap", ["chghost"], username="leafuser"
    )
    leaf_nocap = await make_cap_client(
        leaf["host"], leaf["port"], "lchgnoc", username="leafuser"
    )

    try:
        await subject.send(f"JOIN {chan}")
        await subject.wait_for("JOIN")
        await asyncio.sleep(0.4)
        await leaf_cap.send(f"JOIN {chan}")
        await leaf_cap.wait_for("JOIN")
        await leaf_nocap.send(f"JOIN {chan}")
        await leaf_nocap.wait_for("JOIN")
        await asyncio.sleep(0.3)
        await drain_briefly(leaf_cap)
        await drain_briefly(leaf_nocap)

        await _hide(services, "hchgusr", account)

        chg = await leaf_cap.wait_for_user_msg("CHGHOST", timeout=5.0)
        assert chg.prefix and chg.prefix.lower().startswith("hchgusr!")
        assert chg.params[1] == hidden_host(account)

        quit_msg = await leaf_nocap.wait_for_user_msg("QUIT", timeout=5.0)
        assert quit_msg.prefix and quit_msg.prefix.lower().startswith("hchgusr!")
        assert "Registered" in (quit_msg.params[-1] if quit_msg.params else "")
        join_msg = await leaf_nocap.wait_for_user_msg("JOIN", timeout=5.0)
        assert join_msg.prefix and join_msg.prefix.endswith(f"@{hidden_host(account)}")
    finally:
        for c in (subject, leaf_cap, leaf_nocap):
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            await c.disconnect()
