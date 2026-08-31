/*
 * IRC - Internet Relay Chat, include/tls_io.h
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
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
 * @brief Core TLS I/O orchestration shared by all backends.
 *
 * This module owns the mapping from a connection's I/O state to its socket
 * event interest.  TLS breaks the plaintext assumption that "readable = want
 * to read, writable = want to send": a TLS write can be blocked waiting to
 * read the socket and vice versa (renegotiation, TLS1.3 KeyUpdate, a partial
 * record).  Rather than sprinkle special cases through the event loop, the
 * desired interest is computed from state in exactly one place here, so the
 * socket interest can never drift out of sync with what the TLS layer needs.
 */
#ifndef INCLUDED_tls_io_h
#define INCLUDED_tls_io_h

#ifndef INCLUDED_ircd_osdep_h
#include "ircd_osdep.h"      /* IOResult */
#endif

struct Client;
struct MsgQ;

/** tls_io_sendv() sends as much of \a cptr's message queue as the TLS session
 * will accept, owning the partial-write / retransmit bookkeeping so no backend
 * has to.  It drives the thin per-backend tls_backend_write() primitive.
 *
 * @param[in] cptr Locally connected TLS client to send to.
 * @param[in] buf Client's message queue.
 * @param[out] count_in Total number of bytes mapped from \a buf.
 * @param[out] count_out Number of bytes consumed from \a buf.
 * \returns IO_FAILURE on a fatal error, IO_BLOCKED if nothing could be sent,
 *   or IO_SUCCESS if any data was written.
 */
IOResult tls_io_sendv(struct Client *cptr, struct MsgQ *buf,
                      unsigned int *count_in, unsigned int *count_out);

/** tls_io_recv() reads TLS application data into \a buf, recording the blocked
 * direction so the event loop waits on the right event.  Drives the thin
 * per-backend tls_backend_read() primitive. */
IOResult tls_io_recv(struct Client *cptr, char *buf, unsigned int length,
                     unsigned int *count_out);

/** Record \a cptr's peer-certificate fingerprint from a raw SHA-256 \a digest
 * (\a len bytes): store the lowercase hex, or clear it if the digest is not a
 * 32-byte SHA-256 or the port suppresses fingerprints (Cloudflare). */
void tls_io_store_fingerprint(struct Client *cptr, const unsigned char *digest,
                              unsigned int len);

/** As tls_io_store_fingerprint(), but from an already-hex fingerprint string
 * \a hex (or NULL to clear), for backends that expose the hash pre-formatted. */
void tls_io_store_fingerprint_hex(struct Client *cptr, const char *hex);

/** Non-zero if the connection currently wants writable events.
 *
 * The plaintext rule is "there is queued output or a /LIST in progress".  TLS
 * overrides it: a write blocked waiting to read must NOT assert writable (the
 * level-triggered writable event would spin), and a read blocked waiting to
 * write must assert it even with an empty send queue.
 */
int tls_want_writable(struct Client *cptr);

/** Full socket event interest mask (SOCK_EVENT_*) the connection should hold,
 * accounting for TLS cross-direction blocking.  Used by the unified event
 * driver; readable is always wanted for a live connection. */
unsigned int tls_desired_events(struct Client *cptr);

#endif /* INCLUDED_tls_io_h */
