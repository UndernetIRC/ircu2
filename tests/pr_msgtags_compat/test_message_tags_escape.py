"""IRCv3 message-tags escaping, malformed input, and TAGMSG speak checks."""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient

from .helpers import escape_tag_value, tag_has, tag_value, unescape_tag_value

pytestmark = pytest.mark.multi_server

# Docker default CLIENTTAGDENY allows only this client tag.
ALLOW = "+example.com/foo"


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _client(hub: dict, nick: str, caps: list[str] | None = None) -> IRCClient:
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    if caps:
        await c.negotiate_cap(caps)
    await c.register(nick, "testuser", f"User {nick}")
    return c


async def _join(clients: list[IRCClient], channel: str):
    for c in clients:
        await c.send(f"JOIN {channel}")
        await c.wait_for("JOIN", timeout=5.0)
    await asyncio.sleep(0.3)


# --- Escaping / unescaping (IRCv3 message-tags table) ----------------------
#
# Character     Escaped form
# ;             \:
# SPACE         \s
# \             \\
# CR            \r
# LF            \n
# all others    themselves
# trailing \    dropped
# invalid \X    drop \, keep X


# (id, wire_value_sent_by_client, expected_logical, expected_wire_fragment)
_ESCAPE_CASES = [
    ("semicolon", "x\\:y", "x;y", "\\:"),
    ("space", "x\\sy", "x y", "\\s"),
    ("backslash", "x\\\\y", "x\\y", "\\\\"),
    ("cr", "x\\ry", "x\ry", "\\r"),
    ("lf", "x\\ny", "x\ny", "\\n"),
    ("passthrough_text", "hello", "hello", "hello"),
    ("passthrough_colon", "a:b", "a:b", "a:b"),
    ("passthrough_equals", "a=b", "a=b", "a=b"),
    ("passthrough_plus_slash", "a+b/c", "a+b/c", "a+b/c"),
    ("empty", "", "", None),
    # Spec examples
    ("trailing_backslash", "test\\", "test", "test"),
    ("invalid_escape_b", "\\b", "b", "b"),
    # Nested: wire \\s → logical \s → re-escape \\s
    ("nested_backslash_s", "\\\\s", "\\s", "\\\\s"),
    ("nested_backslash_colon", "\\\\:", "\\:", "\\\\:"),
    # Combined
    (
        "combined",
        "a\\sb\\:c\\\\d\\re\\nf",
        "a b;c\\d\re\nf",
        None,  # check logical only; fragments asserted via unescape
    ),
]


async def test_escape_rule_matrix_via_relay(ircd_network):
    """Each IRCv3 escape rule: client wire → unescape → re-escape on delivery."""
    hub = ircd_network["hub"]
    sender = await _client(hub, "escmtx", ["message-tags"])
    observer = await _client(hub, "escmtxo", ["message-tags"])

    try:
        await _join([sender, observer], "#escmtx")
        for case_id, wire_in, logical, wire_frag in _ESCAPE_CASES:
            label = f"case-{case_id}"
            await sender.send(f"@{ALLOW}={wire_in} PRIVMSG #escmtx :{label}")
            msg = await observer.wait_for("PRIVMSG", timeout=5.0)
            assert msg.params[-1] == label, (case_id, msg.raw)
            raw = tag_value(msg.tags, ALLOW)
            assert raw is not None, (case_id, msg.raw)
            got = unescape_tag_value(raw)
            assert got == logical, (
                f"{case_id}: logical {got!r} != {logical!r} (wire out {raw!r})"
            )
            if wire_frag is not None:
                assert wire_frag in raw, (
                    f"{case_id}: expected {wire_frag!r} in wire {raw!r}"
                )
            # Server's outbound form must match a fresh escape of the logical value
            assert raw == escape_tag_value(logical), (
                f"{case_id}: wire {raw!r} != escape({logical!r})"
            )
    finally:
        await _cleanup(sender, observer)


async def test_valueless_client_tag_relays(ircd_network):
    """A client tag without '=value' is still relayed."""
    hub = ircd_network["hub"]
    sender = await _client(hub, "escflag", ["message-tags"])
    observer = await _client(hub, "escflago", ["message-tags"])

    try:
        await _join([sender, observer], "#escflag")
        await sender.send(f"@{ALLOW} PRIVMSG #escflag :flag")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "flag", msg.raw
        assert tag_has(msg.tags, ALLOW), msg.raw
        assert tag_value(msg.tags, ALLOW) is None, msg.raw
    finally:
        await _cleanup(sender, observer)


# --- Malformed ------------------------------------------------------------


async def test_tags_without_separating_space_dropped(ircd_network):
    """'@tagsCOMMAND' (no space) must not be treated as a tagged command."""
    hub = ircd_network["hub"]
    user = await _client(hub, "malspace", ["message-tags"])

    try:
        await user.send("JOIN #malspace")
        await user.wait_for("JOIN", timeout=5.0)
        # No space between tags and command — parse_msg_tags fails; line ignored.
        await user.send(f"@{ALLOW}=1PRIVMSG #malspace :oops")
        # Server stays up and still accepts a normal command.
        await user.send("PING :aftermal")
        pong = await user.wait_for("PONG", timeout=5.0)
        assert "aftermal" in pong.params[-1], pong.raw
    finally:
        await _cleanup(user)


async def test_empty_tag_key_skipped(ircd_network):
    """Empty key between semicolons is skipped; sibling tags still work."""
    hub = ircd_network["hub"]
    sender = await _client(hub, "malempty", ["message-tags"])
    observer = await _client(hub, "malemptyo", ["message-tags"])

    try:
        await _join([sender, observer], "#malempty")
        await sender.send(f"@;{ALLOW}=ok;; PRIVMSG #malempty :emptykey")
        msg = await observer.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "emptykey", msg.raw
        assert tag_value(msg.tags, ALLOW) == "ok", msg.raw
    finally:
        await _cleanup(sender, observer)


async def test_bare_at_prefix_dropped(ircd_network):
    """A lone '@' with a space before the command is ignored safely."""
    hub = ircd_network["hub"]
    user = await _client(hub, "malbare", ["message-tags"])

    try:
        await user.send("JOIN #malbare")
        await user.wait_for("JOIN", timeout=5.0)
        await user.send("@ PRIVMSG #malbare :bare")
        # Either delivered without tags, or dropped; either way no crash.
        try:
            msg = await user.wait_for("PRIVMSG", timeout=2.0)
            assert not msg.tags or "bare" in msg.raw
        except asyncio.TimeoutError:
            pass
        await user.send("PING :alive")
        await user.wait_for("PONG", timeout=5.0)
    finally:
        await _cleanup(user)


# --- TAGMSG speak restrictions --------------------------------------------


async def _assert_tagmsg_blocked(
    muted: IRCClient, observer: IRCClient, channel: str, label: str
):
    await muted.send(f"@{ALLOW}={label} TAGMSG {channel}")
    err = await muted.wait_for("404", timeout=5.0)
    assert err.command == "404", err.raw
    assert channel.lower() in " ".join(err.params).lower(), err.raw
    try:
        leaked = await observer.wait_for("TAGMSG", timeout=1.0)
        raise AssertionError(f"TAGMSG leaked to channel: {leaked.raw}")
    except asyncio.TimeoutError:
        pass


async def test_tagmsg_blocked_when_banned(ircd_network):
    """Banned (+b) member cannot TAGMSG; 404 and no channel delivery."""
    hub = ircd_network["hub"]
    chan = "#tagban"
    chanop = await _client(hub, "tagbanop", ["message-tags"])
    muted = await _client(hub, "tagbanu", ["message-tags"])
    observer = await _client(hub, "tagbano", ["message-tags"])

    try:
        await _join([chanop, muted, observer], chan)
        await chanop.send(f"MODE {chan} +b tagbanu!*@*")
        await chanop.wait_for("MODE", timeout=5.0)
        await asyncio.sleep(0.2)

        await _assert_tagmsg_blocked(muted, observer, chan, "banned")
        # Sanity: PRIVMSG is also blocked the same way.
        await muted.send(f"PRIVMSG {chan} :also banned")
        err = await muted.wait_for("404", timeout=5.0)
        assert err.command == "404", err.raw
    finally:
        await _cleanup(chanop, muted, observer)


async def test_tagmsg_blocked_when_moderated(ircd_network):
    """Unvoiced member on +m cannot TAGMSG; +v restores it."""
    hub = ircd_network["hub"]
    chan = "#tagmod"
    chanop = await _client(hub, "tagmodop", ["message-tags"])
    muted = await _client(hub, "tagmodu", ["message-tags"])
    observer = await _client(hub, "tagmodo", ["message-tags"])

    try:
        await _join([chanop, muted, observer], chan)
        await chanop.send(f"MODE {chan} +m")
        await chanop.wait_for("MODE", timeout=5.0)
        await asyncio.sleep(0.2)

        await _assert_tagmsg_blocked(muted, observer, chan, "mod")

        await chanop.send(f"MODE {chan} +v tagmodu")
        await chanop.wait_for("MODE", timeout=5.0)
        await asyncio.sleep(0.2)

        await muted.send(f"@{ALLOW}=voiced TAGMSG {chan}")
        msg = await observer.wait_for("TAGMSG", timeout=5.0)
        assert msg.params[0].lower() == chan, msg.raw
        assert tag_value(msg.tags, ALLOW) == "voiced", msg.raw
    finally:
        await _cleanup(chanop, muted, observer)


async def test_tagmsg_blocked_when_moderate_noreg(ircd_network):
    """Unauthed member on +M cannot TAGMSG."""
    hub = ircd_network["hub"]
    chan = "#tagMmod"
    chanop = await _client(hub, "tagMop", ["message-tags"])
    muted = await _client(hub, "tagMu", ["message-tags"])
    observer = await _client(hub, "tagMo", ["message-tags"])

    try:
        await _join([chanop, muted, observer], chan)
        await chanop.send(f"MODE {chan} +M")
        await chanop.wait_for("MODE", timeout=5.0)
        await asyncio.sleep(0.2)

        await _assert_tagmsg_blocked(muted, observer, chan, "Mmod")
    finally:
        await _cleanup(chanop, muted, observer)
