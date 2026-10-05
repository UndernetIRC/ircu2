"""A TLS 1.3 client that can send a real KeyUpdate, driven through libssl by
ctypes.

Python's ``ssl`` module exposes no ``key_update()`` and does not surface the
underlying ``SSL*``, so the misbehaving-peer harness (which uses
``ssl.MemoryBIO``) cannot produce the one thing the ircd's post-handshake
cross-direction machinery exists to handle: a peer-initiated KeyUpdate that
forces the server's ``SSL_read``/``SSL_write`` to block on the *opposite*
socket direction.

This peer owns the ``SSL*`` (created over two memory BIOs), so it can:
  * complete the handshake and exchange application data,
  * call ``SSL_key_update(ssl, SSL_KEY_UPDATE_UPDATE_REQUESTED)`` and emit the
    resulting encrypted KeyUpdate record,
  * put that record on the raw socket whole or truncated, with full control
    over read timing and the receive-buffer size.

Run this module directly to self-test the ctypes machinery against a local
Python TLS server (no ircd needed):  ``python tls/keyupdate_peer.py``
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket

# ---------------------------------------------------------------------------
# libssl / libcrypto bindings
# ---------------------------------------------------------------------------

_ssl = ctypes.CDLL(ctypes.util.find_library("ssl") or "libssl.so.3")
_crypto = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")

# OpenSSL constants
SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_VERIFY_NONE = 0
SSL_KEY_UPDATE_NOT_REQUESTED = 0
SSL_KEY_UPDATE_REQUESTED = 1
BIO_CTRL_PENDING = 10

_p = ctypes.c_void_p
_i = ctypes.c_int


def _sig(fn, restype, *argtypes):
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


_sig(_ssl.TLS_client_method, _p)
_sig(_ssl.SSL_CTX_new, _p, _p)
_sig(_ssl.SSL_CTX_free, None, _p)
_sig(_ssl.SSL_CTX_set_verify, None, _p, _i, _p)
_sig(_ssl.SSL_new, _p, _p)
_sig(_ssl.SSL_free, None, _p)
_sig(_ssl.SSL_set_connect_state, None, _p)
_sig(_ssl.SSL_set_bio, None, _p, _p, _p)
_sig(_ssl.SSL_do_handshake, _i, _p)
_sig(_ssl.SSL_get_error, _i, _p, _i)
_sig(_ssl.SSL_read, _i, _p, _p, _i)
_sig(_ssl.SSL_write, _i, _p, _p, _i)
_sig(_ssl.SSL_key_update, _i, _p, _i)
_sig(_ssl.SSL_is_init_finished, _i, _p)
_sig(_crypto.BIO_new, _p, _p)
_sig(_crypto.BIO_s_mem, _p)
_sig(_crypto.BIO_read, _i, _p, _p, _i)
_sig(_crypto.BIO_write, _i, _p, _p, _i)
_sig(_crypto.BIO_ctrl, ctypes.c_long, _p, _i, ctypes.c_long, _p)


def _bio_pending(bio) -> int:
    return int(_crypto.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, None))


class KeyUpdatePeer:
    """A minimal TLS 1.3 client with KeyUpdate control, over a raw socket."""

    def __init__(self, host: str, port: int, *, rcvbuf: int | None = None):
        self.host = host
        self.port = port
        self.rcvbuf = rcvbuf
        self.sock: socket.socket | None = None
        self.ctx = None
        self.ssl = None
        self.rbio = None  # data coming IN from the wire -> SSL
        self.wbio = None  # data going OUT from SSL -> the wire

    # -- lifecycle ----------------------------------------------------------

    def connect(self, timeout: float = 10.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.rcvbuf is not None:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        self.sock.settimeout(timeout)
        self.sock.connect((self.host, self.port))

        self.ctx = _ssl.SSL_CTX_new(_ssl.TLS_client_method())
        if not self.ctx:
            raise RuntimeError("SSL_CTX_new failed")
        _ssl.SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, None)
        self.ssl = _ssl.SSL_new(self.ctx)
        if not self.ssl:
            raise RuntimeError("SSL_new failed")
        self.rbio = _crypto.BIO_new(_crypto.BIO_s_mem())
        self.wbio = _crypto.BIO_new(_crypto.BIO_s_mem())
        _ssl.SSL_set_bio(self.ssl, self.rbio, self.wbio)  # SSL takes ownership
        _ssl.SSL_set_connect_state(self.ssl)

    def close(self) -> None:
        if self.ssl:
            _ssl.SSL_free(self.ssl)  # frees the attached BIOs too
            self.ssl = None
        if self.ctx:
            _ssl.SSL_CTX_free(self.ctx)
            self.ctx = None
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # -- raw wire / BIO plumbing -------------------------------------------

    def _flush_out(self) -> bytes:
        """Drain SSL's outgoing BIO and send it on the socket; return the bytes."""
        out = self._take_out()
        if out:
            self.sock.sendall(out)
        return out

    def _take_out(self) -> bytes:
        """Drain SSL's outgoing BIO without sending (caller controls the wire)."""
        chunks = []
        while True:
            n = _bio_pending(self.wbio)
            if n <= 0:
                break
            buf = ctypes.create_string_buffer(n)
            got = _crypto.BIO_read(self.wbio, buf, n)
            if got <= 0:
                break
            chunks.append(buf.raw[:got])
        return b"".join(chunks)

    def _feed_in(self, timeout: float | None = None) -> int:
        """Read one chunk from the socket into SSL's incoming BIO."""
        if timeout is not None:
            self.sock.settimeout(timeout)
        data = self.sock.recv(65536)
        if not data:
            return 0
        _crypto.BIO_write(self.rbio, data, len(data))
        return len(data)

    # -- handshake / app data ----------------------------------------------

    def handshake(self, timeout: float = 10.0) -> None:
        while True:
            r = _ssl.SSL_do_handshake(self.ssl)
            self._flush_out()
            if r == 1:
                return
            err = _ssl.SSL_get_error(self.ssl, r)
            if err == SSL_ERROR_WANT_READ:
                if self._feed_in(timeout) == 0:
                    raise ConnectionError("EOF during handshake")
            elif err == SSL_ERROR_WANT_WRITE:
                continue
            else:
                raise RuntimeError(f"handshake failed: SSL_get_error={err}")

    def write_app(self, data: bytes) -> None:
        """Encrypt and send application data."""
        buf = ctypes.create_string_buffer(data, len(data))
        n = _ssl.SSL_write(self.ssl, buf, len(data))
        if n <= 0:
            raise RuntimeError(f"SSL_write failed: {_ssl.SSL_get_error(self.ssl, n)}")
        self._flush_out()

    def read_app(self, timeout: float = 5.0) -> bytes:
        """Read and decrypt available application data (may block up to timeout)."""
        out = ctypes.create_string_buffer(65536)
        while True:
            n = _ssl.SSL_read(self.ssl, out, 65536)
            if n > 0:
                return out.raw[:n]
            err = _ssl.SSL_get_error(self.ssl, n)
            if err == SSL_ERROR_WANT_READ:
                if self._feed_in(timeout) == 0:
                    return b""
            else:
                return b""

    # -- the point of this class: KeyUpdate --------------------------------

    def key_update_record(self, requested: bool = True) -> bytes:
        """Return the encrypted KeyUpdate record bytes WITHOUT sending them.

        SSL_key_update() only arms the update; the record is produced on the
        next SSL_write, so we do a zero-length-ish write and harvest the BIO.
        """
        t = SSL_KEY_UPDATE_REQUESTED if requested else SSL_KEY_UPDATE_NOT_REQUESTED
        if _ssl.SSL_key_update(self.ssl, t) != 1:
            raise RuntimeError("SSL_key_update failed")
        # A 1-byte write flushes the pending KeyUpdate first, then the app byte.
        # We only want the KeyUpdate record, so write nothing schedulable: force
        # the update out via SSL_do_handshake (valid post-handshake for pending
        # key updates in OpenSSL 3), then harvest.
        _ssl.SSL_do_handshake(self.ssl)
        rec = self._take_out()
        return rec

    def send_raw(self, data: bytes) -> None:
        self.sock.sendall(data)


# ---------------------------------------------------------------------------
# Local self-test (no ircd): peer <-> a Python TLS echo server on 127.0.0.1
# ---------------------------------------------------------------------------

def _selftest() -> None:
    import ssl as pyssl
    import threading
    import tls_certs

    ctx = pyssl.SSLContext(pyssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls_certs.cert_path("hub"), tls_certs.key_path("hub"))
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    result = {}

    def serve():
        conn, _ = srv.accept()
        tconn = ctx.wrap_socket(conn, server_side=True)
        try:
            data = tconn.recv(4096)
            tconn.sendall(b"echo:" + data)
            # Read again — this forces the server to process the peer's KeyUpdate.
            more = tconn.recv(4096)
            result["after_keyupdate"] = more
            tconn.sendall(b"post:" + more)
        finally:
            try:
                tconn.close()
            except OSError:
                pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()

    peer = KeyUpdatePeer("127.0.0.1", port)
    peer.connect()
    peer.handshake()
    assert _ssl.SSL_is_init_finished(peer.ssl) == 1, "handshake not finished"
    peer.write_app(b"hello")
    got = peer.read_app()
    assert got == b"echo:hello", got

    rec = peer.key_update_record(requested=True)
    assert rec and rec[0] == 0x17, f"expected a TLS1.3 app-data-wrapped record, got {rec[:8]!r}"
    peer.send_raw(rec)                 # send the KeyUpdate whole
    peer.write_app(b"world")           # app data under the new key
    got2 = peer.read_app()
    assert got2 == b"post:world", got2
    peer.close()
    th.join(timeout=5)
    print("keyupdate_peer self-test OK: handshake + app data + KeyUpdate + rekeyed app data")


if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    _selftest()
