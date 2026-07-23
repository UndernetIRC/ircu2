"""Pure unit tests for IRCv3 tag value escape/unescape (no ircd).

Mirrors the mapping in ircd/msg_tag.c and the message-tags specification.
"""

from __future__ import annotations

import pytest

from .helpers import escape_tag_value, unescape_tag_value


@pytest.mark.parametrize(
    "logical,escaped",
    [
        (";", "\\:"),
        (" ", "\\s"),
        ("\\", "\\\\"),
        ("\r", "\\r"),
        ("\n", "\\n"),
        ("a;b", "a\\:b"),
        ("a b", "a\\sb"),
        ("a\\b", "a\\\\b"),
        ("a\rb", "a\\rb"),
        ("a\nb", "a\\nb"),
        # "all others" pass through unchanged
        ("hello", "hello"),
        ("a:b", "a:b"),
        ("a=b", "a=b"),
        ("+", "+"),
        ("/", "/"),
        ("", ""),
        # combined
        ("a b;c\\d\re\nf", "a\\sb\\:c\\\\d\\re\\nf"),
    ],
)
def test_escape_mapping(logical: str, escaped: str):
    assert escape_tag_value(logical) == escaped


@pytest.mark.parametrize(
    "escaped,logical",
    [
        ("\\:", ";"),
        ("\\s", " "),
        ("\\\\", "\\"),
        ("\\r", "\r"),
        ("\\n", "\n"),
        ("a\\:b", "a;b"),
        ("a\\sb", "a b"),
        ("a\\\\b", "a\\b"),
        ("a\\rb", "a\rb"),
        ("a\\nb", "a\nb"),
        ("hello", "hello"),
        ("a:b", "a:b"),
        ("a=b", "a=b"),
        ("", ""),
        # Spec: trailing lone backslash dropped
        ("test\\", "test"),
        ("\\", ""),
        # Spec: invalid escape drops the backslash
        ("\\b", "b"),
        ("x\\byz", "xbyz"),
        # Nested: \\s is backslash + 's', not a space
        ("\\\\s", "\\s"),
        ("\\\\:", "\\:"),
        # Adjacent escapes
        ("\\s\\:\\\\", " ;\\"),
        ("a\\sb\\:c\\\\d\\re\\nf", "a b;c\\d\re\nf"),
    ],
)
def test_unescape_mapping(escaped: str, logical: str):
    assert unescape_tag_value(escaped) == logical


@pytest.mark.parametrize(
    "logical",
    [
        "",
        "plain",
        "a b;c\\d\re\nf",
        ":",
        "=",
        "+",
        "vendor/name",
    ],
)
def test_escape_unescape_roundtrip(logical: str):
    assert unescape_tag_value(escape_tag_value(logical)) == logical
