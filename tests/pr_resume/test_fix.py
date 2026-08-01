"""M1 tests for IRCv3 session resume (draft/resume-0.5).

Milestone 1 scope: a registered secure-WebSocket (WSS + TLS) client is offered
the ``draft/resume-0.5`` capability and, once it is acknowledged, receives a
``RESUME TOKEN`` line.  The capability MUST NOT be offered on any other
transport.  Detach/resume/expiry are later milestones and are not tested here.

The positive path runs against the TLS hub's WSS port (websocket + tls); the
negatives pin down the ``IsWebsocket && IsTLS`` gate: plain WebSocket (websocket,
no tls) and a plain TCP connection (neither) must not see the capability.
"""

import ssl

import pytest

from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient

RESUME_CAP = "draft/resume-0.5"


def _tls_ctx():
    """Unverified client TLS context (the test PKI uses self-signed certs)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _collect_cap_ls(client):
    """Send CAP LS 302 and return the full set of advertised capability names."""
    await client.send("CAP LS 302")
    caps = set()
    while True:
        msg = await client.recv(timeout=10.0)
        if msg.command != "CAP":
            continue
        # :server CAP <nick|*> LS [*] :<space-separated caps>
        more = len(msg.params) >= 4 and msg.params[-2] == "*"
        for tok in msg.params[-1].split():
            caps.add(tok.split("=", 1)[0])  # strip any =value
        if not more:
            return caps


# --------------------------------------------------------------------------
# Positive path: WSS + TLS
# --------------------------------------------------------------------------

@pytest.mark.tls
@pytest.mark.asyncio
async def test_resume_cap_advertised_on_wss(ircd_tls_network):
    """draft/resume-0.5 is offered on a secure WebSocket connection."""
    hub = ircd_tls_network["hub"]
    client = IRCWebSocketClient()
    await client.connect(
        f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx()
    )
    try:
        caps = await _collect_cap_ls(client)
        assert RESUME_CAP in caps, f"{RESUME_CAP} missing from WSS CAP LS: {caps}"
    finally:
        await client.disconnect()


@pytest.mark.tls
@pytest.mark.asyncio
async def test_resume_token_issued_after_ack(ircd_tls_network):
    """After ACKing the capability the client receives one RESUME TOKEN line."""
    hub = ircd_tls_network["hub"]
    client = IRCWebSocketClient()
    await client.connect(
        f"wss://{hub['host']}:{hub['wss_port']}/", ssl=_tls_ctx()
    )
    try:
        caps = await _collect_cap_ls(client)
        assert RESUME_CAP in caps

        await client.send(f"CAP REQ :{RESUME_CAP}")
        acked = False
        token = None
        # Expect a CAP ... ACK and a RESUME TOKEN line, in some order.
        for _ in range(10):
            msg = await client.recv(timeout=10.0)
            if msg.command == "CAP" and "ACK" in msg.params:
                assert RESUME_CAP in msg.params[-1]
                acked = True
            elif msg.command == "RESUME" and msg.params[:1] == ["TOKEN"]:
                token = msg.params[-1]
                break
        assert acked, "capability was not ACKed"
        assert token, "no RESUME TOKEN was issued"
        # Token is <base64url-id>.<base64url-secret>: one dot, both parts set.
        assert token.count(".") == 1, f"malformed token: {token!r}"
        id_part, secret_part = token.split(".")
        assert id_part and secret_part
    finally:
        await client.disconnect()


# --------------------------------------------------------------------------
# Negatives: the capability is transport-gated to WSS + TLS
# --------------------------------------------------------------------------

@pytest.mark.tls
@pytest.mark.asyncio
async def test_resume_cap_hidden_on_plain_websocket(ircd_tls_network):
    """WebSocket without TLS must not see draft/resume-0.5 (TLS half of gate)."""
    hub = ircd_tls_network["hub"]
    client = IRCWebSocketClient()
    await client.connect(f"ws://{hub['host']}:{hub['ws_plain_port']}/")
    try:
        caps = await _collect_cap_ls(client)
        assert RESUME_CAP not in caps, (
            f"{RESUME_CAP} leaked onto a plaintext WebSocket: {caps}"
        )
    finally:
        await client.disconnect()


@pytest.mark.tls
@pytest.mark.asyncio
async def test_resume_cap_hidden_on_plain_tcp(ircd_tls_network):
    """A plain TCP client (neither WebSocket nor TLS) must not see the cap."""
    hub = ircd_tls_network["hub"]
    client = IRCClient()
    await client.connect(hub["host"], hub["port"])
    try:
        await client.send("CAP LS 302")
        msg = await client.wait_for("CAP", timeout=5.0)
        caps = {t.split("=", 1)[0] for t in msg.params[-1].split()}
        assert RESUME_CAP not in caps, (
            f"{RESUME_CAP} leaked onto a plaintext TCP connection: {caps}"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()
