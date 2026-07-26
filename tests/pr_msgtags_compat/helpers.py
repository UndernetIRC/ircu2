"""Shared helpers for message-tags integration tests."""

from __future__ import annotations


async def join_synced(channel: str, *clients, timeout: float = 15.0) -> None:
    """JOIN each client to `channel` and wait for its own JOIN echo.

    Input throttling (2s+/command penalties, larger for tagged lines) can
    hold a JOIN in the server's recvQ for several seconds after a CAP/
    registration burst.  A sender must not fire until every member's JOIN
    has echoed back, or the message is silently lost to non-members.
    """
    for c in clients:
        await c.send(f"JOIN {channel}")
        await c.wait_for("JOIN", timeout=timeout)


def escape_tag_value(value: str) -> str:
    """Escape a tag value per IRCv3 message-tags rules."""
    out: list[str] = []
    for ch in value:
        if ch == ";":
            out.append("\\:")
        elif ch == " ":
            out.append("\\s")
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        else:
            out.append(ch)
    return "".join(out)


def unescape_tag_value(value: str) -> str:
    """Unescape an IRCv3 tag value (message-tags escaping rules)."""
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\":
            if i + 1 >= len(value):
                break  # trailing lone backslash dropped
            nxt = value[i + 1]
            if nxt == "s":
                out.append(" ")
            elif nxt == ":":
                out.append(";")
            elif nxt == "\\":
                out.append("\\")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "n":
                out.append("\n")
            else:
                # Invalid escape: drop backslash, keep next char.
                out.append(nxt)
            i += 2
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def parse_tag_list(tags: str, *, unescape: bool = False) -> dict[str, str | None]:
    """Parse IRCv3 tag string into a key -> value map (None if no '=')."""
    out: dict[str, str | None] = {}
    if not tags:
        return out
    for part in tags.split(";"):
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            if unescape:
                val = unescape_tag_value(val)
        else:
            key, val = part, None
        out[key] = val
    return out


def tag_has(tags: str, key: str) -> bool:
    return key in parse_tag_list(tags)


def tag_value(tags: str, key: str, *, unescape: bool = False) -> str | None:
    return parse_tag_list(tags, unescape=unescape).get(key)
