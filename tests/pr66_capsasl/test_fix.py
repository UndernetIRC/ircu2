"""TDD tests for PR #66: CAP LS 302, cap-notify, and SASL capability support.

PR #66 adds:
- CAP LS 302 (IRCv3.2 capability negotiation with version)
- cap-notify capability (auto-enabled for 302 clients, hidden from their LS)
- SASL capability (hidden/prohibited until a SASL server is available)
- AUTHENTICATE command handler
- Removal of CAP ACK and CAP CLEAR subcommands
- Removal of ~ (proto) and = (sticky) modifiers from CAP LS output

These tests verify the CAP negotiation changes. SASL authentication
flow cannot be tested end-to-end without a SASL authentication server,
but capability advertisement and AUTHENTICATE error handling are tested.
"""

import asyncio
import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.single_server


async def test_cap_ls_302_no_modifiers(ircd_hub):
    """CAP LS 302 should not include ~ or = modifiers on capability names.

    PR #66 removes the old behavior where CAP LS included ~ for proto
    caps and = for sticky caps. IRCv3.2 does not use these modifiers.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.command == "CAP"
        assert len(msg.params) >= 3
        cap_str = msg.params[-1]
        # No capability should start with ~ or = modifiers
        for cap in cap_str.split():
            cap_name = cap.split("=")[0]  # strip value if present
            assert not cap_name.startswith("~"), (
                f"Cap '{cap}' has ~ modifier (removed in PR #66)"
            )
            assert not cap_name.startswith("="), (
                f"Cap '{cap}' has = modifier (removed in PR #66)"
            )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_302_cap_notify_hidden(ircd_hub):
    """cap-notify should NOT appear in CAP LS for 302 clients.

    302 clients get cap-notify implicitly enabled; it should be hidden
    from the LS listing via CAPFL_HIDDEN_302.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        assert "cap-notify" not in cap_names, (
            "cap-notify should be hidden from 302 CAP LS"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_legacy_shows_cap_notify(ircd_hub):
    """cap-notify SHOULD appear in CAP LS for non-302 (legacy) clients.

    Without the 302 version, cap-notify is visible and can be REQ'd.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        assert "cap-notify" in cap_names, (
            "cap-notify should be visible in legacy CAP LS"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_302_implicit_cap_notify(ircd_hub):
    """CAP LS 302 should implicitly enable cap-notify.

    After CAP LS 302, the client should be able to REQ other caps
    and cap-notify is automatically active (verified indirectly by
    the fact that -cap-notify is NAK'd as sticky).
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)

        # Try to remove cap-notify — should be NAK'd (sticky for 302)
        await client.send("CAP REQ :-cap-notify")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK", (
            "Removing cap-notify should be NAK'd for 302 clients (STICKY_302)"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_sasl_not_advertised_without_server(ircd_hub):
    """SASL should NOT appear in CAP LS when no SASL server is configured.

    SASL starts with CAPFL_UNAVAILABLE (HIDDEN | PROHIBIT) and only
    becomes available when a SASL authentication server connects.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        assert "sasl" not in cap_names, (
            "SASL should not be advertised without a SASL server"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_sasl_rejected_when_unavailable(ircd_hub):
    """CAP REQ sasl should be NAK'd when SASL is unavailable.

    With no SASL server, the SASL cap has CAPFL_PROHIBIT set,
    so requesting it should fail.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK", (
            "CAP REQ sasl should be NAK'd when SASL is unavailable"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_authenticate_ignored_without_sasl_cap(ircd_hub):
    """AUTHENTICATE should be silently ignored without SASL capability active.

    The server checks CapHas(cli_active(cptr), CAP_SASL) and returns 0
    (no response) if the client doesn't have SASL capability enabled.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        # Don't REQ sasl (and it would be NAK'd anyway)
        await client.send("AUTHENTICATE PLAIN")
        # Server should not send any response — verify with a follow-up
        await client.send("CAP END")
        await client.send("NICK authtest66")
        await client.send("USER testuser 0 * :Test")
        # We should get registration messages, not SASL errors
        msg = await client.wait_for("001", timeout=10.0)
        assert msg.command == "001", "Should register successfully"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_302_standard_caps_present(ircd_hub):
    """CAP LS 302 should list standard capabilities like userhost-in-names.

    Verifies that the standard caps (enabled by default features) are
    still advertised correctly after the PR #66 changes.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        # These should be present with default features
        expected_caps = [
            "userhost-in-names",
            "extended-join",
            "account-notify",
        ]
        for cap in expected_caps:
            assert cap in cap_names, (
                f"Expected cap '{cap}' in CAP LS 302, got: {cap_names}"
            )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_negotiate_and_register_with_302(ircd_hub):
    """Full CAP LS 302 negotiation followed by registration should work.

    Tests the complete flow: CAP LS 302 → CAP REQ → CAP END → NICK/USER.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        acked = await client.negotiate_cap(["userhost-in-names", "extended-join"])
        assert "userhost-in-names" in acked or "extended-join" in acked, (
            f"Expected at least one cap to be ACK'd, got: {acked}"
        )
        await client.send("NICK capreg66")
        await client.send("USER testuser 0 * :Test")
        msg = await client.wait_for("001", timeout=10.0)
        assert msg.command == "001"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ack_subcommand_removed(ircd_hub):
    """CAP ACK from client should be ignored (subcommand removed in PR #66).

    PR #66 removes the cap_ack handler — ACK from clients is no longer
    processed. The server should not crash or error.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        # Send ACK from client (was valid before PR #66, now ignored)
        await client.send("CAP ACK :userhost-in-names")
        # Should not crash. Send CAP END and register to verify.
        await client.send("CAP END")
        await client.send("NICK acktest66")
        await client.send("USER testuser 0 * :Test")
        msg = await client.wait_for("001", timeout=10.0)
        assert msg.command == "001"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()
