"""INFO hides the source-file hash section from non-operators (commit 9cbac8b,
issue #29; reworked on main to stop at the "Sources:" marker instead of a
hard-coded line offset).

Non-opers get the fixed text up to (excluding) "Sources:"; an operator who
names a server (``INFO hub.test.net``) additionally gets the hash section.
"""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.single_server

HASH_LINE = re.compile(r"^\[ .+: [0-9a-f]{32} .*\]$")
FOOTER = ("Birth Date:", "On-line since", "TLS library:")


async def _info(client, arg=""):
    await client.send(f"INFO {arg}".strip())
    msgs = await client.collect_until("374", timeout=10.0)
    return [m.params[-1] for m in msgs if m.command == "371"]


def _hashes(lines):
    return [l for l in lines if HASH_LINE.match(l)]


async def test_non_oper_does_not_see_hashes(make_client):
    client = await make_client("info1")
    lines = await _info(client)
    assert lines and lines[0] == "IRC --", lines[:3]
    assert "Sources:" not in lines and "Headers:" not in lines
    assert not _hashes(lines), _hashes(lines)[:3]
    assert any(l.startswith("Birth Date:") for l in lines)
    assert any(l.startswith("On-line since") for l in lines)


async def test_non_oper_remote_info_needs_privileges(make_client):
    """INFO <server> is oper-only for the remote form (hunt_server_cmd MustBeOper)."""
    client = await make_client("info2")
    await client.send("INFO leaf1.test.net")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"


async def test_oper_sees_hashes(oper):
    """An oper naming a server gets the hash section (sources and headers)."""
    lines = await _info(oper, "hub.test.net")
    hashes = _hashes(lines)
    assert "Headers:" in lines
    assert len(hashes) > 100, f"oper saw only {len(hashes)} hash lines"
    assert any("client.h" in l for l in hashes)


async def test_oper_sees_every_source_hash(oper):
    lines = await _info(oper, "hub.test.net")
    hashes = _hashes(lines)
    assert "Sources:" in lines, lines[:3]
    assert any(l.startswith("[ IPcheck.c:") for l in hashes), hashes[:2]
    assert any(l.startswith("[ channel.c:") for l in hashes), hashes[:2]


async def test_oper_without_server_argument_sees_no_hashes(oper):
    """mo_info only sends the hash section when a server name is given."""
    lines = await _info(oper)
    assert not _hashes(lines), _hashes(lines)[:3]
    assert lines and lines[0] == "IRC --", lines[:3]
    assert "Sources:" not in lines
    assert any(l.startswith("Birth Date:") for l in lines)


async def test_oper_and_user_see_the_same_public_text(oper, make_client):
    plain = await make_client("info5")
    plain_lines = [l for l in await _info(plain) if not l.startswith(FOOTER)]
    oper_lines = [l for l in await _info(oper) if not l.startswith(FOOTER)]
    assert plain_lines == oper_lines


async def test_oper_hash_lines_are_well_formed(oper):
    """Each hash line names a source file and a 32-hex MD5 (umkpasswd -5)."""
    lines = await _info(oper, "hub.test.net")
    hashes = _hashes(lines)
    names = [l.split(":")[0].lstrip("[ ") for l in hashes]
    assert len(set(names)) == len(names), "duplicate file names in INFO"
    assert all(n.endswith((".c", ".y", ".h", ".SH")) for n in names), names[:5]
