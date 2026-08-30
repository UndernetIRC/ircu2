"""/CONNECT <server> 0 uses the port from the Connect block (commit 45ae2f0).

"notulined.test.net" is configured with port 4499 where nothing listens, so
every attempt fails quickly; what matters is which notice the oper gets.
"""

from __future__ import annotations

import pytest

from common import collect

pytestmark = pytest.mark.single_server


async def _connect_notices(oper, args):
    await oper.send(f"CONNECT {args}")
    return [
        m.params[-1]
        for m in await collect(oper, 2.5)
        if m.command == "NOTICE" and m.params[-1].startswith(("Connect:", "***"))
    ]


def _attempted(notices):
    return any("Connecting to notulined.test.net" in n or
               "Connection to notulined.test.net failed" in n for n in notices)


async def test_port_zero_uses_configured_port(oper):
    notices = await _connect_notices(oper, "notulined.test.net 0")
    assert notices, "expected a Connect notice"
    assert not any("Invalid port" in n or "missing port" in n for n in notices), notices
    assert _attempted(notices), notices


async def test_non_numeric_port_is_rejected(oper):
    notices = await _connect_notices(oper, "notulined.test.net abc")
    assert any("Invalid port number" in n for n in notices), notices
    assert not _attempted(notices), notices


async def test_explicit_port_is_used(oper):
    notices = await _connect_notices(oper, "notulined.test.net 4499")
    assert _attempted(notices), notices


async def test_unknown_server_is_reported(oper):
    notices = await _connect_notices(oper, "nowhere.test.net 0")
    assert any("not listed in ircd.conf" in n for n in notices), notices


async def test_connect_requires_oper(make_client):
    client = await make_client("connplain")
    await client.send("CONNECT notulined.test.net 0")
    err = await client.wait_for("481", timeout=5.0)
    assert err.command == "481"
