"""CAP command edge cases beyond pr66_capsasl coverage.

Exercises m_cap.c / capab.h: unknown subcommands, post-registration
behaviour, REQ parsing quirks, feature gating, sticky caps, and
client-originated ACK/NAK/NEW/DEL no-ops.
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import make_cap_client, oper_up
from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def _collect_cap_ls(client: IRCClient, timeout: float = 5.0) -> list[str]:
    """Drain CAP LS reply line(s); return capability tokens (name or name=value)."""
    tokens: list[str] = []
    while True:
        msg = await client.wait_for("CAP", timeout=timeout)
        assert msg.params[1] == "LS", msg.raw
        tokens.extend(msg.params[-1].split())
        if len(msg.params) < 4 or msg.params[2] != "*":
            return tokens


def _cap_names(tokens: list[str]) -> set[str]:
    return {t.split("=", 1)[0] for t in tokens}


async def _alive_unregistered(client: IRCClient, token: str = "alive") -> None:
    """Unregistered PING is rejected with 451, not PONG — proves the link is live."""
    await client.send(f"PING :{token}")
    err = await client.wait_for("451", timeout=5.0)
    assert err.command == "451"


async def test_unknown_cap_subcommand_returns_410(ircd_hub):
    """Unknown CAP subcommand must yield ERR_UNKNOWNCAPCMD (410)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP CLEAR")
        err = await client.wait_for("410", timeout=5.0)
        assert any("CLEAR" in p for p in err.params), err.raw
        assert any("Unknown CAP" in p for p in err.params), err.raw
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_without_subcommand_is_silent(ircd_hub):
    """Bare CAP (parc < 2) is ignored — no 410, no crash."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP")
        await _alive_unregistered(client, "bare-cap")
        await client.assert_no_message("410", timeout=0.5)
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_subcommand_case_insensitive(ircd_hub):
    """Subcommands are matched case-insensitively (ircd_strcmp)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP ls")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "LS"
        assert _cap_names(msg.params[-1].split())
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_client_originated_ack_nak_new_del_ignored(ircd_hub):
    """Client-sent ACK/NAK/NEW/DEL have NULL handlers and must be ignored.

    cmdlist is bsearch'd and must be sorted; a prior ordering bug made NEW/DEL
    return 410 instead of being no-ops.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        for sub in ("ACK", "NAK", "NEW", "DEL"):
            await client.send(f"CAP {sub} :account-notify")
            await client.assert_no_message("410", timeout=0.3)
            await client.assert_no_message("CAP", timeout=0.2)
        await _alive_unregistered(client, "noop-subs")
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_req_mixed_add_and_remove(ircd_hub):
    """One REQ can add and remove caps atomically when all are valid."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("CAP REQ :account-notify away-notify")
        ack1 = await client.wait_for("CAP", timeout=5.0)
        assert ack1.params[1] == "ACK"
        await client.send("CAP REQ :chghost -away-notify")
        ack2 = await client.wait_for("CAP", timeout=5.0)
        assert ack2.params[1] == "ACK"
        ack_caps = set(ack2.params[-1].split())
        assert "chghost" in ack_caps
        assert "-away-notify" in ack_caps

        await client.send("CAP LIST")
        listing = await client.wait_for("CAP", timeout=5.0)
        names = set(listing.params[-1].split())
        assert "chghost" in names
        assert "account-notify" in names
        assert "away-notify" not in names
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_req_whitespace_and_duplicates(ircd_hub):
    """Extra spaces and duplicate names in REQ must still ACK cleanly."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("CAP REQ :  account-notify   account-notify  chghost  ")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", msg.raw
        names = set(msg.params[-1].split())
        assert "account-notify" in names
        assert "chghost" in names
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_req_lone_minus_is_nak(ircd_hub):
    """A lone '-' is not a capability name — all-or-nothing REQ must NAK."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("CAP REQ :-")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK", msg.raw
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_req_unknown_cap_naks_all_or_nothing(ircd_hub):
    """One unknown name in a mixed REQ must NAK the entire request."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("CAP REQ :account-notify not-a-real-cap")
        nak = await client.wait_for("CAP", timeout=5.0)
        assert nak.params[1] == "NAK", nak.raw
        await client.send("CAP LIST")
        listing = await client.wait_for("CAP", timeout=5.0)
        names = set(listing.params[-1].split()) if listing.params[-1] else set()
        assert "account-notify" not in names
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_sticky_cap_notify_cannot_be_removed_after_302(ircd_hub):
    """After LS 302, -cap-notify must NAK (CAPFL_STICKY_302)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("CAP REQ :-cap-notify")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK", msg.raw
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_unavailable_sasl_naks_req(ircd_hub):
    """SASL starts CAPFL_UNAVAILABLE; REQ must NAK when no agent is present."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        names = _cap_names(await _collect_cap_ls(client))
        assert "sasl" not in names
        await client.send("CAP REQ :sasl")
        nak = await client.wait_for("CAP", timeout=5.0)
        assert nak.params[1] == "NAK", nak.raw
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_post_registration_list_req_ls_still_work(ircd_hub):
    """After CAP END + register, LIST/REQ/LS remain usable; END is a no-op."""
    client = await make_cap_client(
        ircd_hub["host"], ircd_hub["port"], "cappost1", ["account-notify"]
    )
    try:
        await client.send("CAP LIST")
        listing = await client.wait_for("CAP", timeout=5.0)
        assert listing.params[1] == "LIST"
        assert "account-notify" in listing.params[-1].split()

        await client.send("CAP LS 302")
        tokens = await _collect_cap_ls(client)
        assert "chghost" in _cap_names(tokens)

        await client.send("CAP REQ :chghost")
        ack = await client.wait_for("CAP", timeout=5.0)
        assert ack.params[1] == "ACK"
        assert "chghost" in ack.params[-1].split()

        await client.send("CAP END")  # post-reg: ignored
        await client.send("PING :post-end")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert "post-end" in (pong.params[-1] if pong.params else "")
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_feature_false_hides_and_rejects_cap(ircd_hub):
    """FEAT_CAP_* = FALSE removes the cap from LS and NAKs REQ."""
    hub = ircd_hub
    oper = await make_cap_client(hub["host"], hub["port"], "capfeatop")
    await oper_up(oper)
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    try:
        await oper.send("SET CAP_UHNAMES FALSE")
        await oper.wait_for("284", timeout=8.0)

        await client.send("CAP LS 302")
        names = _cap_names(await _collect_cap_ls(client))
        assert "userhost-in-names" not in names

        await client.send("CAP REQ :userhost-in-names")
        nak = await client.wait_for("CAP", timeout=5.0)
        assert nak.params[1] == "NAK"
    finally:
        try:
            await oper.send("SET CAP_UHNAMES TRUE")
            await oper.wait_for("284", timeout=8.0)
        except Exception:
            pass
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()
        await oper.send("QUIT :done")
        await oper.disconnect()


async def test_cap_end_required_before_registration(ircd_hub):
    """NICK/USER during CAP negotiation must not complete until CAP END."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("NICK capblock1")
        await client.send("USER testuser 0 * :blocked")
        # Must not see 001 while CAP is pending
        try:
            msg = await client.wait_for("001", timeout=1.5)
            pytest.fail(f"Registered before CAP END: {msg.raw}")
        except (asyncio.TimeoutError, TimeoutError):
            pass
        await client.send("CAP END")
        welcome = await client.wait_for("001", timeout=10.0)
        assert welcome.command == "001"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_list_empty_before_any_req(ircd_hub):
    """CAP LIST with no negotiated caps returns an empty capability list."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await _collect_cap_ls(client)
        await client.send("CAP LIST")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "LIST"
        caps = msg.params[-1].split() if msg.params[-1] else []
        # 302 LS sets cap-notify in cli_active only; LIST uses cli_capab.
        assert caps == [] or caps == [""], f"Unexpected LIST caps: {caps!r}"
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()
