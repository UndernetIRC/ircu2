"""WHOX %l selects only the idle field (commit 17c5391 added a missing break
so 'l' no longer fell through into 'n')."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.single_server


async def _whox(client, mask, fields):
    await client.send(f"WHO {mask} %{fields}")
    msgs = await client.collect_until("315", timeout=5.0)
    return [m for m in msgs if m.command == "354"]


async def test_idle_field_alone(make_client):
    client = await make_client("whox1")
    rows = await _whox(client, "whox1", "l")
    assert len(rows) == 1
    # 354 <me> <idle>: nothing else, in particular no nick field.
    assert len(rows[0].params) == 2, rows[0].raw
    assert rows[0].params[1].isdigit(), rows[0].raw


async def test_nick_field_alone(make_client):
    client = await make_client("whox2")
    rows = await _whox(client, "whox2", "n")
    assert len(rows) == 1
    assert rows[0].params[1:] == ["whox2"], rows[0].raw


async def test_idle_and_nick_fields(make_client):
    client = await make_client("whox3")
    rows = await _whox(client, "whox3", "nl")
    assert len(rows) == 1
    assert rows[0].params[1] == "whox3", rows[0].raw
    assert rows[0].params[2].isdigit(), rows[0].raw
