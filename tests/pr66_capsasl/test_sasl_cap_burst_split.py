"""SASL capability advertisement across a bursting link and a netsplit.

Reproduces a production incident: the SASL server (``channels.*``) lived
behind a hub (``shub``) that linked half-way -- it introduced its downlinks
but never completed its burst -- and then pinged out. Clients with
cap-notify saw::

    CAP hubby NEW sasl=plain,scram-sha-256,external
    CAP hubby DEL :sasl

on the *split*. Two defects combined to produce that:

* SASL availability was only re-evaluated on END_OF_BURST_ACK, so a
  half-linked SASL server was (correctly) never advertised, but the
  capability flag stayed stale relative to ``find_match_server()``.
* ``exit_one_client()`` re-evaluated availability for every server torn
  down in the split. A sibling of the SASL server exited first, the check
  still found the SASL server linked, and emitted a spurious CAP NEW one
  message before the real CAP DEL.

Topology in these tests (fake ``services.test.net`` plays ``shub``)::

    hub.test.net --- services.test.net --+-- channels.test.net  (sasl.server)
                     (fake, P10Server)   +-- other.test.net

``other`` is introduced *after* ``channels`` so it sits at the head of the
uplink's downlink list and is torn down first on a split -- the ordering
that triggered the spurious NEW.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = [
    pytest.mark.single_server,
    pytest.mark.usefixtures("reset_sasl_netconf"),
]

SASL_SERVER = "channels.test.net"
MECHANISMS = "PLAIN"

# (name, numeric, flags, bursting) -- the production shape: an uplink
# re-introducing downlinks whose own bursts completed long ago (P10).
DEFAULT_DOWNSTREAMS = (
    (SASL_SERVER, 5, "s", False),
    ("other.test.net", 6, "", False),
)


async def _capnotify_client(ircd_hub, nick: str) -> IRCClient:
    """Registered client with cap-notify active (implicit via CAP LS 302).

    Not cap_helpers.make_cap_client(): cap-notify is CAPFL_HIDDEN_302, so
    that helper would skip these tests.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.send("CAP LS 302")
    await client.wait_for("CAP", timeout=5.0)
    await client.send("CAP END")
    await client.register(nick, "testuser", "Test User")
    return client


async def _collect_cap(client: IRCClient, timeout: float) -> list[tuple[str, str]]:
    """Return every (subcommand, argument) CAP message seen within timeout."""
    seen = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return seen
        try:
            msg = await client.wait_for("CAP", timeout=remaining)
        except asyncio.TimeoutError:
            return seen
        seen.append((msg.params[1], msg.params[-1]))


async def _expect_cap_new(client: IRCClient) -> None:
    msg = await client.wait_for("CAP", timeout=5.0)
    assert msg.params[1] == "NEW", f"expected CAP NEW, got {msg.params}"
    assert msg.params[-1] == f"sasl={MECHANISMS}", msg.params


async def _half_link_with_sasl_server(
    ircd_hub,
    *,
    sasl_server: str = SASL_SERVER,
    downstreams=DEFAULT_DOWNSTREAMS,
) -> tuple[P10Server, dict[str, str]]:
    """Link a fake hub that has not finished its burst, pointing SASL at ``sasl_server``.

    Sets sasl.server/sasl.mechanisms via CF while still bursting, then
    introduces ``downstreams`` behind us. Returns the server and a map of
    downstream name -> P10 numeric.
    """
    srv = P10Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.begin_handshake()
    # Mid-burst from the hub's point of view: it has sent us EB, we have
    # not sent ours.
    await srv.send_config("sasl.server", sasl_server)
    await srv.send_config("sasl.mechanisms", MECHANISMS)
    numerics = {}
    for name, numeric, flags, bursting in downstreams:
        numerics[name] = await srv.send_downstream_server(
            name, numeric, flags=flags, bursting=bursting
        )
    return srv, numerics


async def _authenticate_target(ircd_hub, srv: P10Server, nick: str) -> str:
    """Start SASL from a fresh client; return the numeric AUTHENTICATE was routed to."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert "sasl" in msg.params[-1], "hub does not advertise sasl"
        await client.send("CAP REQ :sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", f"expected CAP ACK, got {msg.params}"
        await client.send(f"AUTHENTICATE {MECHANISMS}")
        # "<hubnum> XQ <target> sasl:<cookie> :SASL ..."
        line = await srv.wait_for_token("XQ", timeout=5.0)
        return line.split()[2]
    finally:
        await client.send("AUTHENTICATE *")
        await client.send("QUIT :done")
        await client.disconnect()


async def test_no_cap_new_when_half_linked_sasl_server_splits(ircd_hub):
    """A link that dies mid-burst must not produce CAP NEW (nor DEL) for sasl.

    The SASL server was never advertised, so there is nothing to withdraw
    and certainly nothing to announce.
    """
    client = await _capnotify_client(ircd_hub, "capsplit1")
    try:
        srv, _ = await _half_link_with_sasl_server(ircd_hub)

        # Still bursting: nothing may be advertised yet.
        assert await _collect_cap(client, 1.5) == []

        # Link collapses without ever sending EB (ping timeout in production).
        await srv.disconnect()

        assert await _collect_cap(client, 2.0) == [], (
            "sasl must not be announced/withdrawn for a server that never "
            "finished bursting"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_new_on_end_of_burst_and_single_del_on_split(ircd_hub):
    """sasl is announced when the link finishes bursting, withdrawn once on split."""
    client = await _capnotify_client(ircd_hub, "capsplit2")
    try:
        srv, _ = await _half_link_with_sasl_server(ircd_hub)
        assert await _collect_cap(client, 1.5) == []

        # Our EB completes the path to the SASL server. Advertise now --
        # without waiting for the EA exchange, which a services package
        # may never send.
        await srv.send_end_of_burst()
        await _expect_cap_new(client)

        await srv.complete_handshake()
        # The EA exchange must not re-announce anything.
        assert await _collect_cap(client, 1.0) == []

        # Now the whole subtree goes away. Exactly one DEL, no NEW.
        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_new_waits_for_sasl_server_own_end_of_burst(ircd_hub):
    """A SASL server introduced with J10 is not advertised until *its* EB.

    Every hop on the path to the SASL server must be out of burst, not just
    the direct link.
    """
    client = await _capnotify_client(ircd_hub, "capsplit3")
    try:
        srv, nums = await _half_link_with_sasl_server(
            ircd_hub, downstreams=((SASL_SERVER, 5, "s", True),)
        )

        # Our link finishes bursting, but channels.* is still in burst.
        await srv.send_end_of_burst()
        await srv.complete_handshake()
        assert await _collect_cap(client, 1.5) == [], (
            "sasl advertised while the SASL server itself is still bursting"
        )

        await srv.send_end_of_burst_for(nums[SASL_SERVER])
        await _expect_cap_new(client)

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_directly_linked_sasl_server_available_at_end_of_burst(ircd_hub):
    """SASL server that is our direct link: hidden while bursting, NEW at its EB.

    sasl.server is set (via CF during the burst) before the link completes,
    so the transition must come from END_OF_BURST itself, not from the
    netconf change callback.
    """
    client = await _capnotify_client(ircd_hub, "capsplit4")
    try:
        srv, _ = await _half_link_with_sasl_server(
            ircd_hub, sasl_server="services.test.net", downstreams=()
        )

        # Direct link still bursting: config points at us, but no NEW yet.
        assert await _collect_cap(client, 1.5) == [], (
            "sasl advertised while the directly linked SASL server is bursting"
        )

        await srv.send_end_of_burst()
        await _expect_cap_new(client)

        await srv.complete_handshake()
        assert await _collect_cap(client, 1.0) == []

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_new_when_sasl_server_introduced_past_burst_over_established_link(ircd_hub):
    """A P10 (already past burst) SASL server behind an established link is advertised at once.

    Nothing else fires for it: no EB will ever arrive for a server
    introduced as past its burst, so introduction itself must trigger the
    re-check. Services packages introducing virtual servers do exactly this.
    """
    client = await _capnotify_client(ircd_hub, "capsplit5")
    try:
        srv, _ = await _half_link_with_sasl_server(ircd_hub, downstreams=())
        await srv.send_end_of_burst()
        await srv.complete_handshake()
        # Config points at a server that does not exist yet.
        assert await _collect_cap(client, 1.0) == []

        await srv.send_downstream_server(SASL_SERVER, 5, flags="s", bursting=False)
        await _expect_cap_new(client)

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_wildcard_mask_prefers_fully_linked_match_and_routes_to_it(ircd_hub):
    """With a wildcard sasl.server, a bursting lower-numnick match must not hide an established one.

    ``chan*.test.net`` matches both ``chanb`` (numeric 5, re-linking and still
    bursting) and ``channels`` (numeric 6, established). Availability must
    stay on, no DEL/NEW churn may be emitted, and AUTHENTICATE must be
    routed to the server that was actually validated -- ``channels``.
    """
    client = await _capnotify_client(ircd_hub, "capsplit6")
    try:
        srv, _ = await _half_link_with_sasl_server(
            ircd_hub, sasl_server="chan*.test.net", downstreams=()
        )
        await srv.send_end_of_burst()
        await srv.complete_handshake()
        assert await _collect_cap(client, 1.0) == []

        channels_num = await srv.send_downstream_server(
            SASL_SERVER, 6, flags="s", bursting=False
        )
        await _expect_cap_new(client)

        # A lower-numnick match appears, still bursting. find_match_server()
        # would return it first; sasl must keep using channels.
        chanb_num = await srv.send_downstream_server(
            "chanb.test.net", 5, flags="s", bursting=True
        )
        assert await _collect_cap(client, 1.5) == [], (
            "bursting lower-numnick match flipped sasl availability"
        )

        target = await _authenticate_target(ircd_hub, srv, "capauth6")
        assert target == channels_num, (
            f"AUTHENTICATE routed to {target}, expected {channels_num} "
            f"(channels); chanb is {chanb_num}"
        )

        # chanb finishing its burst changes nothing that clients can see.
        await srv.send_end_of_burst_for(chanb_num)
        assert await _collect_cap(client, 1.0) == []

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_new_reaches_client_still_registering(ircd_hub):
    """A CAP LS 302 client that has not finished registering still gets NEW.

    A restarted leaf takes its clients back while it is still bursting with
    the network: they see no sasl in CAP LS, and the path to the SASL server
    completes before they are registered.  cap-notify is implicit from the
    moment of CAP LS 302, not from registration, so the NEW must reach them
    -- otherwise they register and never learn sasl exists.
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert "sasl" not in msg.params[-1], msg.params
        # Registration stays suspended: no CAP END yet.
        await client.send("NICK capsplit7")
        await client.send("USER testuser 0 * :Test User")

        srv, _ = await _half_link_with_sasl_server(ircd_hub)
        assert await _collect_cap(client, 1.0) == []
        await srv.send_end_of_burst()
        await _expect_cap_new(client)

        # The announced capability is usable before registration completes.
        await client.send("CAP REQ :sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", msg.params

        await srv.complete_handshake()
        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.disconnect()


async def test_cap_del_aborts_sasl_exchange_in_progress(ircd_hub):
    """A client mid-AUTHENTICATE hears 904 with the DEL, not at the timeout.

    Once sasl is DEL'd, m_sasl() drops every AUTHENTICATE because the
    client no longer holds the capability, so the session must be ended
    and the client told right away instead of after sasl.timeout (30s).
    """
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    try:
        await client.send("CAP LS 302")
        await client.wait_for("CAP", timeout=5.0)

        srv, _ = await _half_link_with_sasl_server(
            ircd_hub, sasl_server="services.test.net", downstreams=()
        )
        await srv.send_end_of_burst()
        await _expect_cap_new(client)
        await srv.complete_handshake()

        await client.send("CAP REQ :sasl")
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "ACK", msg.params
        await client.send(f"AUTHENTICATE {MECHANISMS}")
        await srv.wait_for_token("XQ", timeout=5.0)

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
        msg = await client.wait_for("904", timeout=3.0)
        assert "disconnected" in msg.params[-1], msg.params
    finally:
        await client.disconnect()


async def test_cap_new_and_del_reach_client_on_highest_fd(ircd_hub):
    """The local client holding HighestFd gets NEW and DEL too.

    cap_new()/cap_del() used to loop ``i < HighestFd`` and skip it.  The
    kernel hands out the lowest free fd, so fillers plug any holes below
    the newest fd before the cap-notify client connects; closing them
    afterwards leaves the client as HighestFd (close_connection() shrinks
    it to the highest occupied slot).
    """
    srv, _ = await _half_link_with_sasl_server(ircd_hub, downstreams=())
    await srv.send_end_of_burst()
    await srv.complete_handshake()

    fillers = []
    for _ in range(20):
        fillers.append(await asyncio.open_connection(ircd_hub["host"], ircd_hub["port"]))
    client = await _capnotify_client(ircd_hub, "capsplit9")
    try:
        for _, writer in fillers:
            writer.close()
        await asyncio.sleep(1.0)

        await srv.send_downstream_server(SASL_SERVER, 5, flags="s", bursting=False)
        await _expect_cap_new(client)

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_sasl_server_mask_longer_than_hostlen_is_not_truncated(ircd_hub):
    """A sasl.server mask over HOSTLEN (63) characters is matched in full.

    It used to be cut to 63 characters before matching: 60 stars plus
    ``services.test.net`` became ``*serv`` after collapse(), which matches
    nothing, so SASL silently never became available.
    """
    long_mask = "*" * 60 + "services.test.net"
    client = await _capnotify_client(ircd_hub, "capsplit10")
    try:
        srv, _ = await _half_link_with_sasl_server(
            ircd_hub, sasl_server=long_mask, downstreams=()
        )
        await srv.send_end_of_burst()
        await _expect_cap_new(client)

        await srv.complete_handshake()
        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()
