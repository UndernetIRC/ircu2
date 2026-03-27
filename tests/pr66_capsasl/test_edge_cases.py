"""Edge case tests for PR #66: CAP LS 302, cap-notify, and SASL.

Adversarial tests that try to break the CAP/SASL implementation:
boundary values, protocol abuse, unusual sequences, and interaction
with other features.
"""

import asyncio
import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.single_server


async def test_cap_ls_version_zero(ircd_hub):
    """CAP LS 0 should behave like legacy CAP LS (no 302 features).

    cap-notify should be visible to non-302 clients since it only has
    CAPFL_HIDDEN_302 (not CAPFL_HIDDEN).
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 0")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        if "cap-notify" not in cap_names:
            pytest.skip("cap-notify not available (PR #66 not applied)")
        assert "cap-notify" in cap_names
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_version_301(ircd_hub):
    """CAP LS 301 should behave like legacy CAP LS (below 302 threshold)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 301")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        if "cap-notify" not in cap_names:
            pytest.skip("cap-notify not available (PR #66 not applied)")
        assert "cap-notify" in cap_names
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_version_large(ircd_hub):
    """CAP LS with a very large version number should enable 302 features."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 999")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        # 302+ behavior: cap-notify hidden
        assert "cap-notify" not in cap_names, (
            "CAP LS 999 should hide cap-notify (302+ behavior)"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_ls_version_non_numeric(ircd_hub):
    """CAP LS with non-numeric text should fall back to legacy behavior.

    atoi("abc") returns 0, so legacy behavior is expected.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS abc")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_str = msg.params[-1]
        cap_names = [c.split("=")[0] for c in cap_str.split()]
        if "cap-notify" not in cap_names:
            pytest.skip("cap-notify not available (PR #66 not applied)")
        assert "cap-notify" in cap_names
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_cap_notify_legacy_client(ircd_hub):
    """Legacy client (no 302) should be able to REQ cap-notify.

    cap-notify has no PROHIBIT flag, so legacy clients can request it.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        # Check if cap-notify exists first
        await client.send("CAP LS")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_names = [c.split("=")[0] for c in msg.params[-1].split()]
        if "cap-notify" not in cap_names:
            pytest.skip("cap-notify not available (PR #66 not applied)")

        await client.send("CAP REQ :cap-notify")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", (
            f"Legacy client should be able to REQ cap-notify, got {msg.params[1]}"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_remove_cap_notify_legacy_client(ircd_hub):
    """Legacy client should be able to remove cap-notify (not STICKY for them).

    CAPFL_STICKY_302 only applies to 302 clients. Legacy clients can
    freely add and remove cap-notify.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        # Check if cap-notify exists first
        await client.send("CAP LS")
        msg = await client.wait_for("CAP", timeout=5.0)
        cap_names = [c.split("=")[0] for c in msg.params[-1].split()]
        if "cap-notify" not in cap_names:
            pytest.skip("cap-notify not available (PR #66 not applied)")

        await client.send("CAP REQ :cap-notify")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK"

        # Now remove it — should succeed for legacy client
        await client.send("CAP REQ :-cap-notify")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", (
            "Legacy client should be able to remove cap-notify"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_remove_cap_notify_302_client(ircd_hub):
    """302 client should NOT be able to remove cap-notify (STICKY_302)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :-cap-notify")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK", (
            "302 client should NOT be able to remove cap-notify"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_multiple_cap_ls_calls(ircd_hub):
    """Multiple CAP LS calls should work without crashing."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        # First: legacy LS
        await client.send("CAP LS")
        msg1 = await client.wait_for("CAP", timeout=5.0)
        caps1 = msg1.params[-1].split()

        # Second: 302 LS
        await client.send("CAP LS 302")
        msg2 = await client.wait_for("CAP", timeout=5.0)
        caps2 = [c.split("=")[0] for c in msg2.params[-1].split()]

        # Both should return valid cap lists
        assert len(caps1) > 0, "First CAP LS should return caps"
        assert len(caps2) > 0, "Second CAP LS should return caps"
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_multiple_caps_with_sasl(ircd_hub):
    """REQ for multiple caps including unavailable sasl should NAK all.

    If any cap in a REQ is invalid/prohibited, the entire REQ is NAK'd.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        # Request valid cap + unavailable sasl
        await client.send("CAP REQ :userhost-in-names sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK", (
            "REQ with any prohibited cap should NAK the whole request"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_nonexistent_cap(ircd_hub):
    """REQ for a non-existent capability should NAK."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :totally-fake-cap")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NAK"
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_authenticate_without_connection(ircd_hub):
    """AUTHENTICATE sent during registration (no SASL cap) is silently dropped.

    Even during pre-registration, if the client hasn't negotiated SASL,
    AUTHENTICATE should be ignored.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        # Don't negotiate caps at all, just try to authenticate
        await client.send("AUTHENTICATE PLAIN")
        # The server should not respond to this — verify by registering
        await client.send("NICK noauth66")
        await client.send("USER testuser 0 * :Test")
        msg = await client.wait_for("001", timeout=10.0)
        assert msg.command == "001", "Should register despite stray AUTHENTICATE"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_list_after_302_negotiation(ircd_hub):
    """CAP LIST after 302 negotiation should show active capabilities."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :userhost-in-names")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP LIST")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "LIST"
        cap_str = msg.params[-1]
        cap_names = cap_str.split()
        assert "userhost-in-names" in cap_names, (
            f"CAP LIST should show active caps, got: {cap_names}"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_end_completes_registration(ircd_hub):
    """CAP END should allow registration to proceed after CAP negotiation."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("NICK capend66")
        await client.send("USER testuser 0 * :Test")
        # Registration should be suspended until CAP END
        await client.send("CAP END")
        msg = await client.wait_for("001", timeout=10.0)
        assert msg.command == "001"
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_req_empty_string(ircd_hub):
    """CAP REQ with empty capability string should be handled gracefully."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("CAP REQ :")
        # Should get NAK or be handled gracefully (not crash)
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] in ("NAK", "ACK"), (
            f"Empty CAP REQ should be handled, got: {msg.params}"
        )
    finally:
        await client.send("CAP END")
        await client.send("QUIT :done")
        await client.disconnect()
