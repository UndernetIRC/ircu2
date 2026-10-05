"""Reproductions for the TLS data-path findings of the 2026-08-30 review.

Run against fix/tls-handshake-events:

  test_fatal_read_error_does_not_leak_queued_plaintext   -> FAILS (bug #2)
  test_handshake_failure_does_not_leak_plaintext_error   -> PASSES (see note)

Finding #2 (CONFIRMED, peer-observable):
  A fatal error inside ircd_tls_recv() frees the SSL session and NULLs s_tls
  but leaves FLAG_TLS set and does NOT mark the socket dead (read_packet's
  FLAG_DEADSOCKET line is commented out).  deliver_it() then tests
  `IsTLS && s_tls`, finds s_tls NULL, and falls back to the *plaintext*
  os_sendv path.  When the server-initiated exit queues its
  "ERROR :Closing Link: <nick> by <server> (...)" line, that line is flushed
  in the clear onto the still-open TLS socket.  This test observes the server
  name in cleartext on the wire.  A one-line fix (SetFlag(cptr,
  FLAG_DEADSOCKET) in the OpenSSL fatal-cleanup branch) makes it pass.

Finding #3 (present in code, NOT peer-observable):
  ircd_tls_negotiate() writes "ERROR :TLS handshake failed\r\n" to the raw fd
  with write(2) on a fatal handshake -- cleartext into a TLS stream.  In
  practice the peer never sees it: the misbehaving peer leaves unconsumed
  input in ircd's receive buffer, so close() emits an RST that discards the
  just-written plaintext.  This test documents that no cleartext reaches the
  peer; the stray write() is therefore dead code worth deleting rather than a
  live leak.
"""

from __future__ import annotations

import asyncio
import os
import re

import pytest

from tls.bogus_peer import BogusTLSClient, wait_for_eof

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]


async def test_handshake_failure_does_not_leak_plaintext_error(ircd_tls_network):
    """Finding #3: no cleartext 'ERROR :TLS' line reaches a peer that sends
    garbage after its ClientHello (the write(2) is discarded by RST-on-close)."""
    hub = ircd_tls_network["hub"]
    peer = BogusTLSClient(hub["host"], hub["tls_port"])
    try:
        await peer.connect()
        hello = peer.start_tls()
        await peer.send_raw(hello)
        await peer.feed(timeout=5.0)                    # server flight
        await peer.send_raw(os.urandom(2048))           # garbage -> fatal
        data, _ = await wait_for_eof(peer.reader, 8.0)
        # Only TLS records (an encrypted alert), then EOF -- no cleartext.
        assert b"ERROR" not in data, (
            f"cleartext leaked on handshake failure: "
            f"{data[data.find(b'ERROR'):][:60]!r}"
        )
    finally:
        await peer.close()


async def _register_over_tls(peer: BogusTLSClient, nick: str, timeout: float = 15.0) -> None:
    """Drive NICK/USER to 001 over a completed handshake, answering the
    nospoof PING."""
    await peer.send_app(f"NICK {nick}\r\nUSER {nick} 0 * :repro\r\n")
    got = ""
    answered = 0
    deadline = asyncio.get_running_loop().time() + timeout
    while " 001 " not in got:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise AssertionError(f"did not register; last saw {got[-200:]!r}")
        try:
            got += await peer.recv_app(timeout=min(remaining, 5.0))
        except (asyncio.TimeoutError, ConnectionError):
            continue
        for m in re.finditer(r"PING :(\S+)", got):
            if m.end() > answered:
                await peer.send_app(f"PONG :{m.group(1)}\r\n")
                answered = m.end()


async def test_fatal_read_error_does_not_leak_queued_plaintext(ircd_tls_network):
    """Finding #2: a corrupt application record after registration frees the
    TLS session; queued server output must not be flushed as plaintext during
    teardown.  On fix/tls-handshake-events this FAILS -- the "ERROR :Closing
    Link ... tls-hub.test.net" line appears in cleartext on the TLS socket."""
    hub = ircd_tls_network["hub"]
    # Tiny receive window so ircd cannot drain its sendq to us: queued replies
    # stay queued when the fatal read tears the client down.
    peer = BogusTLSClient(hub["host"], hub["tls_port"], rcvbuf=512)
    try:
        await peer.connect()
        await peer.complete_handshake(timeout=8.0)
        await _register_over_tls(peer, "reprofatal")

        # Generate a wad of server output without reading it, so ircd's sendq
        # to us is non-empty (but under the sendq limit -> no clean dead_link).
        for _ in range(8):
            await peer.send_app("VERSION\r\nLUSERS\r\nADMIN\r\nTIME\r\n")

        # Corrupt an application record: valid length/type, broken AEAD tag.
        corrupt = bytearray(peer.app_bytes("VERSION\r\n"))
        corrupt[-1] ^= 0xFF
        corrupt[-2] ^= 0xFF
        await peer.send_raw(bytes(corrupt))

        # On a TLS socket the peer must only ever see TLS records (0x14-0x17);
        # the server name in cleartext means queued data was flushed through
        # the plaintext os_sendv path after s_tls was cleared.
        data, _ = await wait_for_eof(peer.reader, 12.0)
        runs = re.findall(rb"[\x20-\x7e]{8,}", data)
        assert b"tls-hub.test.net" not in data and b"Closing Link" not in data, (
            "plaintext server data leaked onto the TLS socket during teardown: "
            f"{[r for r in runs if b'Closing Link' in r or b'test.net' in r][:3]}"
        )
    finally:
        await peer.close()
