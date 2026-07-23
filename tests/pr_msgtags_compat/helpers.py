"""Shared helpers for message-tags integration tests."""

from __future__ import annotations


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
