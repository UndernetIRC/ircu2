"""TLS certificate rotation via REHASH under a live connection.

`REHASH s` -> ircd_tls_rehash() -> ircd_tls_init() rebuilds the server SSL
context from the on-disk cert/key and drops the daemon's reference to the old
one; an already-negotiated session must keep the context it handshaked on alive
on its own, so live connections must survive while new connections pick up the
rotated certificate.  This is the routine ops path (cert renewal) and is
verified across all three backends.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl

import pytest

import tls_certs
from debug_support import docker_exec
from irc_client import IRCClient
from tls.helpers import oper_up

pytestmark = [
    pytest.mark.tls,
    pytest.mark.asyncio,
    # New connections pick up the rotated cert, and the live session must
    # survive the context swap, on every backend.  ircd_tls_rehash() rebuilds
    # the global context via ircd_tls_init(); an already-negotiated session
    # must keep the context it handshaked on alive on its own (OpenSSL by
    # SSL_CTX refcount, gnutls/libtls by their per-session credential/keypair
    # ownership).  Verified for all three backends.
]

HUB = "ircu-tls-hub"
CERTDIR = "/opt/ircu/lib/certs"


def _server_cert_fp(host: str, port: int, timeout: float = 5.0) -> str:
    """SHA-256 of the DER server certificate a fresh TLS client is presented —
    the same value ircu records as the TLS fingerprint."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


async def _pong(client: IRCClient, token: str, timeout: float = 5.0) -> bool:
    await client.send(f"PING :{token}")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            msg = await client.recv(timeout=deadline - loop.time())
        except (asyncio.TimeoutError, ConnectionError):
            return False
        if msg.command == "PONG" and token in msg.params[-1]:
            return True
    return False


def _sh(*cmd: str) -> None:
    docker_exec(HUB, "sh", "-c", " ".join(cmd))


async def test_tls_cert_rotation_via_rehash(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["tls_port"]
    fps = tls_certs.FINGERPRINTS

    # Baseline: the hub serves its own certificate.
    fp_old = await asyncio.to_thread(_server_cert_fp, host, port)
    assert fp_old == fps["hub"], f"unexpected baseline cert {fp_old}"

    # A TLS client that must survive the rehash, and an oper to drive it.
    survivor = IRCClient()
    await survivor.connect_tls(host, port)
    await survivor.register("rehashsurv", "surv", "rehash survivor")
    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("rehashop", "op", "rehash oper")
    assert (await oper_up(oper)).command == "381"

    # Back up the live cert/key so we can put them back afterwards.
    await asyncio.to_thread(
        _sh,
        f"cp {CERTDIR}/hub.pem {CERTDIR}/hub.pem.orig",
        f"&& cp {CERTDIR}/hub.key {CERTDIR}/hub.key.orig",
    )
    try:
        # Rotate: install a different valid cert/key as the hub's own.
        await asyncio.to_thread(
            _sh,
            f"cp {CERTDIR}/tlspeer.pem {CERTDIR}/hub.pem",
            f"&& cp {CERTDIR}/tlspeer.key {CERTDIR}/hub.key",
            f"&& chown ircu:ircu {CERTDIR}/hub.pem {CERTDIR}/hub.key",
        )
        await oper.send("REHASH s")
        await asyncio.sleep(1.0)  # ircd_tls_init() is synchronous; small settle

        # 1) The live connection survives the rehash.
        assert await _pong(survivor, "rehash-alive"), "live TLS client dropped by rehash"

        # 2) New connections are served the rotated certificate.
        fp_new = await asyncio.to_thread(_server_cert_fp, host, port)
        assert fp_new == fps["tlspeer"], f"rotated cert not served: {fp_new}"
        assert fp_new != fp_old

        # 3) A fresh client can still fully register against the new cert.
        fresh = IRCClient()
        await fresh.connect_tls(host, port)
        msgs = await fresh.register("rehashfresh", "fr", "post-rotation")
        assert any(m.command == "001" for m in msgs)
        await fresh.disconnect()
    finally:
        # Restore the original cert/key and rehash back, so the shared topology
        # is left as we found it for any later tests.
        await asyncio.to_thread(
            _sh,
            f"cp {CERTDIR}/hub.pem.orig {CERTDIR}/hub.pem",
            f"&& cp {CERTDIR}/hub.key.orig {CERTDIR}/hub.key",
            f"&& chown ircu:ircu {CERTDIR}/hub.pem {CERTDIR}/hub.key",
        )
        await oper.send("REHASH s")
        await asyncio.sleep(1.0)
        try:
            await survivor.disconnect()
            await oper.disconnect()
        except Exception:
            pass
