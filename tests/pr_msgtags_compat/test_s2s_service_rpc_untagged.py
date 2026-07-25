"""Regression: server<->services RPC must not carry a client @time tag on S2S.

XQUERY/XREPLY (P10 XQ/XR) are internal server-to-services RPC (SASL auth,
spamfilter). They are consumed by services software that parses P10 fields
positionally and does not strip IRCv3 message-tags. The S2S time-tagging
introduced with message-tags used a blacklist that missed XQ/XR, so the hub
began prepending `@time=...` to XQUERY -- shifting every field by one and
breaking SASL routing ('sasl:<cookie>' landed one slot over) and spamfilter
XREPLY routing (the hub numeric became the tag).

A client-facing relayed event (PRIVMSG/NOTICE/etc.) legitimately keeps its
@time on S2S; only the service-RPC commands must stay untagged.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server

pytestmark = pytest.mark.single_server


@pytest.fixture
async def services(ircd_hub):
    """Fake P10 services server linked to the hub, with SASL enabled."""
    srv = P10Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    await srv.send_config("sasl.server", "services.test.net")
    await srv.send_config("sasl.mechanisms", "PLAIN")
    await asyncio.sleep(0.5)
    yield srv
    await srv.disconnect()


async def test_xquery_has_no_time_tag(ircd_hub, services):
    """The XQUERY the hub sends to services must be plain P10 (no @tag prefix).

    Asserts on the raw wire line so a leading `@time=` is caught directly,
    independent of any tag-stripping the harness does for token matching.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])

    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert "sasl" in msg.params[-1], "hub does not advertise sasl"

        await client.send("CAP REQ :sasl")
        await client.wait_for("CAP", timeout=5.0)
        await client.send("AUTHENTICATE PLAIN")

        line = await services.wait_for_token("XQ", timeout=5.0)

        # Raw line must be classic P10: first field is the hub numeric, not a
        # message-tag section.
        assert not line.lstrip().startswith("@"), f"XQUERY carried a tag: {line!r}"
        parts = line.split()
        assert "time=" not in parts[0], f"XQUERY carried a time tag: {line!r}"
        # Classic P10 layout: <hubnum> XQ <svcnum> <routing> :<payload>.
        # A leading @time= would shift all of these one slot to the right.
        assert parts[1] == "XQ", f"unexpected XQUERY layout: {line!r}"
        assert parts[3].startswith("sasl:"), f"routing shifted by a tag: {line!r}"
    finally:
        try:
            await client.send("QUIT :cleanup")
        except Exception:
            pass
        await client.disconnect()
