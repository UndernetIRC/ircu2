/*
 * IRC - Internet Relay Chat, include/ircd_tls.h
 * Copyright (C) 2019 Michael Poole
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Functions for handling TLS-protected connections.
 */
#ifndef INCLUDED_ircd_tls_h
#define INCLUDED_ircd_tls_h

#include "ircd_osdep.h"
#include "ircd_string.h"
#include "ircd_features.h"
#include "listener.h"

/** Resolve whether to load the OS trust store for TLS verification. */
static inline int ircd_tls_use_system_ca(int systemca, const char *cafile,
                                         const char *cadir)
{
  if (systemca == 1)
    return 1;
  if (systemca == 0)
    return 0;
  if (!EmptyString(cafile) || !EmptyString(cadir))
    return 0;
  return feature_bool(FEAT_TLS_SYSTEMCA);
}

struct Client;
struct ConfItem;
struct Listener;
struct MsgQ;
struct Socket;

/**
 * TLS peer-certificate trust policy for a listener or Connect session.
 *
 * These are the only supported combinations. Backends must map this enum
 * rather than inventing policy from independent booleans.
 *
 * TLS_TRUST_REQUEST_SOFT — Ask for a peer certificate but do not require
 *   one. PKIX is advisory (accept any presented cert). Used for client/
 *   user TLS ports without tls verifypeer.
 *
 * TLS_TRUST_REQUIRE_SOFT — Require a peer certificate; PKIX is advisory.
 *   Used for server listener ports and outbound Connect blocks without
 *   tls verifypeer. Trust is fingerprint pin or nothing.
 *
 * TLS_TRUST_REQUIRE_CA — Require a peer certificate and enforce PKIX
 *   (and hostname verification where applicable). Used when
 *   tls verifypeer is yes.
 */
typedef enum ircd_tls_trust_policy {
  TLS_TRUST_REQUEST_SOFT = 0,
  TLS_TRUST_REQUIRE_SOFT,
  TLS_TRUST_REQUIRE_CA
} ircd_tls_trust_policy;

/** Return the trust policy for inbound connections on \a listener.
 * A NULL listener (e.g. STARTTLS on a plaintext port) uses REQUEST_SOFT.
 */
ircd_tls_trust_policy ircd_tls_listener_trust_policy(const struct Listener *listener);

/** Return the trust policy for an outbound Connect block.
 * Outbound TLS always requires a peer certificate; CA enforcement
 * depends on tls verifypeer.
 */
ircd_tls_trust_policy ircd_tls_connect_trust_policy(const struct ConfItem *aconf);

/** Non-zero if \a policy requires the peer to present a certificate. */
static inline int ircd_tls_trust_requires_peer(ircd_tls_trust_policy policy)
{
  return policy != TLS_TRUST_REQUEST_SOFT;
}

/** Non-zero if \a policy enforces PKIX CA validation. */
static inline int ircd_tls_trust_verifies_ca(ircd_tls_trust_policy policy)
{
  return policy == TLS_TRUST_REQUIRE_CA;
}

/** Timeout for TLS handshake in seconds */
#define TLS_HANDSHAKE_TIMEOUT 5

/** Size of the human-readable reason buffer filled by ircd_tls_negotiate(). */
#define TLS_REASON_LEN 128

/** Which socket direction a TLS operation is blocked on.
 *
 * TLS breaks the plaintext assumption that a read waits on readable and a
 * write waits on writable: a TLS *write* can be blocked waiting to *read* the
 * socket (and vice versa).  Backends report the blocked direction with these
 * values; the core (tls_io.c) turns them into socket event interest.  This is
 * the single source of truth for cross-direction I/O — there are no separate
 * ad-hoc flags. */
enum ircd_tls_want {
  IRCD_TLS_WANT_NONE = 0,  /**< not blocked (or blocked on its natural direction) */
  IRCD_TLS_WANT_READ,      /**< the operation needs the socket to become readable */
  IRCD_TLS_WANT_WRITE      /**< the operation needs the socket to become writable */
};

/* The following variables and functions are provided by ircu2's core
 * code, not by the TLS interface.
 */

/** ircd_tls_keyfile holds this server's private key. */
extern char *ircd_tls_keyfile;

/** ircd_tls_certfile holds this server's public key certificate. */
extern char *ircd_tls_certfile;

/* The following variables are provided by the TLS interface. */

/** ircd_tls_version identifies the TLS library in current use. */
extern const char *ircd_tls_version;

/** ircd_tls_init() initializes the TLS library.
 *
 * Among any other global initialization that the library needs, this
 * function loads #ircd_tls_keyfile and #ircd_tls_certfile.  It should
 * return zero (ideally without performing other work) if either of
 * those strings are null or empty.
 *
 * This function is idempotent; it is called both at initial startup
 * and upon "REHASH s".  The TLS interface code must distinguish between
 * those cases as needed.
 *
 * \returns Zero on success, non-zero to indicate failure.
 */
int ircd_tls_init(void);

/** ircd_tls_rehash() reloads global TLS state and all listener and
 * Connect block contexts.  Called on "REHASH s" and after a full
 * configuration rehash.
 *
 * \returns Zero on success, non-zero to indicate failure.
 */
int ircd_tls_rehash(void);

/** ircd_tls_accept() creates an inbound TLS session.
 *
 * If \a listener is NULL, the client connected on a plaintext port and
 * used STARTTLS.  Otherwise, the client connected on a TLS-only port
 * configured with \a listener.  The connection uses \a .
 *
 * @param[in] listener Listening socket that accepted the connection.
 * @param[in] fd File descriptor for new connection.
 * \returns NULL on failure, otherwise a valid new TLS session.
 */
void *ircd_tls_accept(struct Listener *listener, int fd);

/** ircd_tls_connect() creates an outbound connection to another server.
 *
 * \a aconf represents the Connect block for the other server, and \a fd
 * is the file descriptor of a (connected but not yet used) connection
 * to that server.
 *
 * @param[in] aconf Connect block for the server we connected to.
 * @param[in] fd File descriptor connected to that server.
 */
void *ircd_tls_connect(struct ConfItem *aconf, int fd);

/** ircd_tls_close() destroys the TLS session \a ctx, optionally passing
 * \a message as an explanation.
 *
 * @param[in] ctx TLS session to destroy.
 * @param[in] message If not null and not empty, this string is sent to
 *   the peer as an explanation for the connection close.  (This is
 *   intended for use by add_connection().)
 */
void ircd_tls_close(void *ctx, const char *message);

/** Return non-zero if \a aconf needs its own outbound TLS context. */
int conf_tls_needs_custom_ctx(const struct ConfItem *aconf);

/** Return non-zero if peer certificate verification is enabled for \a cptr. */
int ircd_tls_verifypeer_enabled(const struct Client *cptr);

/** Return non-zero if the peer must present a certificate during TLS. */
int ircd_tls_peer_cert_required(const struct Client *cptr);

/** Return non-zero if inbound listener connections must present a cert. */
int ircd_tls_listener_peer_cert_required(const struct Listener *listener);

/** Return non-zero if inbound listener connections require PKIX validation. */
int ircd_tls_listener_verify_ca(const struct Listener *listener);

/** Return non-zero if outbound Connect block requires PKIX validation. */
int ircd_tls_connect_verify_ca(const struct ConfItem *aconf);

/** Return non-zero if Connect block requires peer hostname verification. */
int ircd_tls_connect_verify_hostname(const struct ConfItem *aconf);

/** Check whether the peer certificate matches \a name for \a cptr.
 * \returns Zero on success, non-zero on mismatch or error.
 */
int ircd_tls_check_peer_hostname(struct Client *cptr, const char *name);

/** ircd_tls_conf_free() releases outbound TLS state cached in \a aconf.
 */
void ircd_tls_conf_free(struct ConfItem *aconf);

/** ircd_tls_conf_reload() rebuilds outbound TLS state cached in \a aconf.
 * \returns Zero on success, non-zero to indicate failure.
 */
int ircd_tls_conf_reload(struct ConfItem *aconf);

/** ircd_tls_listen() configures any listener-specific TLS parameters.
 * \a listener->tls_ciphers is populated on entry.  \a listener->tls_ctx
 * may be null or may have been previously set by the TLS implementation.
 *
 * @param[in,out] listener Listener structure to configure.
 * \returns Zero on success, non-zero to indicate failure.
 */
int ircd_tls_listen(struct Listener *listener);

/** Return non-zero if \a listener has TLS state needed to accept clients.
 */
int ircd_tls_listener_ready(const struct Listener *listener);

/** ircd_tls_listen_free() releases listener-specific TLS state in
 * \a listener->tls_ctx, if any.
 */
void ircd_tls_listen_free(struct Listener *listener);

/** ircd_tls_negotiate() attempts to continue an initial TLS handshake
 * for \a cptr.  If the handshake completes, this function calls
 * \a ClearNegotiatingTLS(cptr) and returns 1.  If the handshake failed,
 * this function returns -1.  Otherwise it returns 0 and reports through
 * \a want which socket direction the handshake is blocked on, so the caller
 * can set the socket's event interest.  The backend never touches socket
 * events itself, and it does not enforce the handshake deadline (a core
 * timer does).
 *
 * @param[in] cptr Locally connected client to perform handshake for.
 * @param[out] reason If non-NULL, receives a human-readable failure reason
 *   on a -1 return (empty otherwise).  Intended for operator notices and
 *   the disconnect log, not for the peer.
 * @param[in] reasonlen Size of the \a reason buffer (see TLS_REASON_LEN).
 * @param[out] want If non-NULL, set on a 0 return to the socket direction the
 *   handshake is waiting on (IRCD_TLS_WANT_READ / IRCD_TLS_WANT_WRITE);
 *   IRCD_TLS_WANT_NONE otherwise.
 * \returns 1 on completed handshake, 0 on continuing handshake, -1 on
 *   error.
 */
int ircd_tls_negotiate(struct Client *cptr, char *reason, size_t reasonlen,
                       enum ircd_tls_want *want);

/** tls_backend_read() reads TLS application data from \a cptr into \a buf.
 *
 * Thin per-backend primitive (tls_io_recv() in the core wraps it and records
 * the blocked direction).
 *
 * @param[in] cptr Locally connected client to read from.
 * @param[out] buf Buffer to receive application data into.
 * @param[in] length Length of \a buf.
 * @param[out] count_out Number of bytes read (0 unless IO_SUCCESS).
 * @param[out] want On IO_BLOCKED, the socket direction the read is waiting on.
 * \returns IO_FAILURE on a fatal error (session torn down), IO_BLOCKED if no
 *   data is available (with \a want set), or IO_SUCCESS if data was read.
 */
/** Raw peer material a backend hands back after a completed handshake, for the
 * core (tls_io.c) to apply trust policy to.  The backend does no policy of its
 * own beyond what the TLS library enforces during the handshake. */
struct tls_peer {
  int           have_cert;             /**< peer presented a certificate */
  int           verified;              /**< PKIX/CA verification passed */
  unsigned char digest[32];            /**< SHA-256 of the peer cert */
  unsigned int  digest_len;            /**< bytes in \a digest (0 if none) */
  char          fp_hex[65];            /**< pre-formatted hex, for libtls */
  char          verify_err[TLS_REASON_LEN]; /**< backend-specific verify reason */
};

/** tls_backend_handshake() advances the TLS handshake for \a cptr.
 *
 * Thin per-backend primitive (ircd_tls_negotiate() in the core wraps it and
 * applies the cert-required / verifypeer trust policy and fingerprint storage).
 * It performs no teardown and touches no client flags.
 *
 * @param[out] peer On IO_SUCCESS, filled with the peer's raw material.
 * @param[out] reason On IO_FAILURE, a human-readable failure reason.
 * @param[out] want On IO_BLOCKED, the socket direction to wait on.
 * \returns IO_SUCCESS (handshake complete, \a peer filled), IO_BLOCKED (in
 *   progress), or IO_FAILURE (fatal; \a reason set, session left for the caller
 *   to drop).
 */
IOResult tls_backend_handshake(struct Client *cptr, struct tls_peer *peer,
                               char *reason, size_t reasonlen,
                               enum ircd_tls_want *want);

/** tls_backend_drop() hard-frees \a cptr's TLS session after a fatal error and
 * NULLs the socket's session pointer.  Unlike ircd_tls_close() it sends no
 * close_notify (the session is unusable).  The core teardown (tls_io.c) calls
 * this; the backend touches no client flags or connection state itself. */
void tls_backend_drop(struct Client *cptr);

IOResult tls_backend_read(struct Client *cptr, char *buf, unsigned int length,
                          unsigned int *count_out, enum ircd_tls_want *want);

/** tls_backend_write() writes one contiguous buffer to \a cptr's TLS session.
 *
 * This is a thin per-backend primitive: it does no message-queue or
 * retransmit bookkeeping (tls_io_sendv() in the core owns that).  It performs
 * a single non-blocking record write and classifies the outcome.
 *
 * @param[in] cptr Locally connected client to send to.
 * @param[in] buf Bytes to write.
 * @param[in] len Number of bytes in \a buf.
 * @param[out] written Number of bytes accepted (only meaningful on IO_SUCCESS).
 * @param[out] want On IO_BLOCKED, the socket direction the write is waiting on.
 * \returns IO_SUCCESS if any bytes were written, IO_BLOCKED if none could be
 *   (with \a want set), or IO_FAILURE on a fatal error (the backend has torn
 *   the session down).
 */
IOResult tls_backend_write(struct Client *cptr, const char *buf,
                           unsigned int len, unsigned int *written,
                           enum ircd_tls_want *want);

/** Compute base64(SHA1(\a data)) into \a out.
 * Used for RFC 6455 WebSocket handshakes and similar protocols.
 * \returns 0 on success, -1 on failure.
 */
int ircd_tls_sha1_base64(const void *data, size_t len, char *out, size_t outlen);

#endif /* INCLUDED_ircd_tls_h */
