"""Hunted commands whose answering-server handler does more than reply to
the requester.

On the answering server the requester is *remote*: it has no Connection
of its own there, only the S2S link it sits behind. Two things used to
go wrong because of that, both fixed by keying the capture on the
requester itself and by parse_server() only treating a *user*-prefixed
labeled line as a request to answer:

1. Over-capture. The capture window was keyed on the link, so anything
   the handler sent down that link during the dispatch -- not just the
   reply -- was swept into the requester's response. RPING is the
   cleanest trigger: `RPING <target> <start>` is hunted to <start>, which
   then sends an RPING *to <target>*. With the requester's own server as
   <target>, that RPING travels back down the very link the request came
   in on and was captured as if it were the reply.

2. Lost label on a single-line non-numeric reply. An answering server's
   one-line NOTICE reply comes back labeled (label_capture_finish()), and
   the relaying hop used to mistake that server-prefixed labeled line for
   a new labeled request, wrap it, and strip the label before delivering.
   Numerics never had this problem (do_numeric() relays them first).
   ms_connect()'s "Host not listed in ircd.conf" NOTICE is the trigger.
"""

from __future__ import annotations

import pytest

from cap_helpers import make_cap_client, oper_up
from irc_client import IRCClient

from .helpers import LABELED_CAPS, tag_has, tag_value

pytestmark = pytest.mark.multi_server


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def test_remote_rping_side_traffic_is_not_captured(ircd_network):
    """RPING hunted to the leaf, which pings the hub back down the
    requesting link. The leaf produced no reply *to the requester*, so the
    labeled response is a bare ACK; the RPING/RPONG exchange itself is
    ordinary S2S traffic and the eventual RPONG to the client is plain.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    client = await make_cap_client(hub["host"], hub["port"], "lblrping", caps=LABELED_CAPS)
    try:
        await oper_up(client)
        await client.send(f"@label=rp RPING {hub['name']} {leaf1['name']} :probe")

        ack = await client.wait_for("ACK", timeout=10.0)
        assert tag_value(ack.tags, "label") == "rp", ack.raw

        rpong = await client.wait_for("RPONG", timeout=10.0)
        assert not tag_has(rpong.tags, "label"), rpong.raw
        assert not tag_has(rpong.tags, "batch"), rpong.raw

        await client.assert_no_message("BATCH", timeout=1.0)
    finally:
        await _cleanup(client)


async def test_remote_single_line_notice_reply_keeps_label(ircd_network):
    """CONNECT hunted to the leaf for a server the leaf has no Connect
    block for: the leaf answers with one NOTICE, which must reach the
    requester carrying the label -- not stripped by the relaying hub.
    """
    hub = ircd_network["hub"]
    leaf1 = ircd_network["leaf1"]

    client = await make_cap_client(hub["host"], hub["port"], "lblrconn", caps=LABELED_CAPS)
    try:
        await oper_up(client)
        await client.send(f"@label=cn CONNECT nosuch.test.net 4400 {leaf1['name']}")

        while True:
            notice = await client.wait_for("NOTICE", timeout=10.0)
            if "not listed in ircd.conf" in notice.params[-1]:
                break
        assert tag_value(notice.tags, "label") == "cn", notice.raw

        await client.assert_no_message("ACK", timeout=1.0)
        await client.assert_no_message("BATCH", timeout=1.0)
    finally:
        await _cleanup(client)
