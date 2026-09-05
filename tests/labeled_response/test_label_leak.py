"""A labeled command with side effects for *other* recipients must not
leak its label to them: only the requester's own response is labeled.

parse_client() reduces the current line's tags to the client-only (+)
set before the handler runs (msg_tag_filter_client()), and parse_server()
strips "label" the same way for a hunted command answered on a remote
requester's behalf, so nothing a handler broadcasts -- to local users or
over S2S -- can pick up the label from the ambient tag list.
"""

from __future__ import annotations

import pytest

from cap_helpers import make_cap_client, oper_up
from irc_client import IRCClient

from .helpers import tag_has, tag_value

pytestmark = pytest.mark.multi_server

CAPS = ["message-tags", "batch", "labeled-response"]


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _oper_with_wallops(host, port, nick):
    c = await make_cap_client(host, port, nick, caps=CAPS)
    await oper_up(c)  # OPER here grants +w already
    return c


async def test_labeled_wallops_does_not_leak_label_to_recipients(ircd_network):
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    sender = await _oper_with_wallops(hub["host"], hub["port"], "lblwsend")
    hub_other = await _oper_with_wallops(hub["host"], hub["port"], "lblwhub")
    leaf_other = await _oper_with_wallops(leaf1["host"], leaf1["port"], "lblwleaf")
    try:
        await sender.send("@label=wall1 WALLOPS :hello from a labeled wallops")

        # Local oper on the same server and oper on a linked server both
        # receive the WALLOPS -- with neither a label nor a batch tag.
        for other in (hub_other, leaf_other):
            w = await other.wait_for("WALLOPS", timeout=10.0)
            assert w.params[-1].endswith("hello from a labeled wallops"), w.raw
            assert not tag_has(w.tags, "label"), w.raw
            assert not tag_has(w.tags, "batch"), w.raw

        # The sender's own echo of the WALLOPS *is* the labeled response:
        # one line, carrying the label directly (so no ACK and no BATCH).
        echo = await sender.wait_for("WALLOPS", timeout=5.0)
        assert echo.params[-1].endswith("hello from a labeled wallops"), echo.raw
        assert tag_value(echo.tags, "label") == "wall1", echo.raw
        await sender.assert_no_message("ACK", timeout=1.0)
        await sender.assert_no_message("BATCH", timeout=1.0)
    finally:
        await _cleanup(sender, hub_other, leaf_other)
