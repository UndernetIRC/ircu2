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

struct Client;
struct ConfItem;
struct Listener;
struct MsgQ;
struct Socket;

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

/** ircd_tls_listen() configures any listener-specific TLS parameters.
 * \a listener->tls_ciphers is populated on entry.  \a listener->tls_ctx
 * may be null or may have been previously set by the TLS implementation.
 *
 * @param[in,out] listener Listener structure to configure.
 * \returns Zero on success, non-zero to indicate failure.
 */
int ircd_tls_listen(struct Listener *listener);

/** ircd_tls_negotiate() attempts to continue an initial TLS handshake
 * for \a cptr.  If the handshake completes, this function calls
 * \a ClearNegotiatingTLS(cptr) and returns 1.  If the handshake failed,
 * this function returns -1.  Otherwise it updates event flags for the
 * client's socket and returns 0.
 *
 * @param[in] cptr Locally connected client to perform handshake for.
 * \returns 1 on completed handshake, 0 on continuing handshake, -1 on
 *   error.
 */
int ircd_tls_negotiate(struct Client *cptr);

/** ircd_tls_recv() performs a non-blocking receive of TLS application
 * data from \a cptr into \a buf.
 *
 * @param[in] cptr Locally connected client to read from.
 * @param[out] buf Buffer to receive application data into.
 * @param[in] length Length of \a buf.
 * @param[out] count_out Number of bytes actually read into \a buf.
 * \returns IO_FAILURE on error, IO_BLOCKED if no data is available, or
 *   IO_SUCCESS if any data was read into \a buf.
 */
IOResult ircd_tls_recv(struct Client *cptr, char *buf,
                       unsigned int length, unsigned int *count_out);

/** ircd_tls_sendv() performs a non-blocking send of TLS application
 * data from \a buf to \a cptr.
 *
 * This function must accomodate changes to \a buf for successive calls
 * to \a cptr.  The connection's \a con_rexmit and \a con_rexmit_len
 * fields are provided to support this requirement.
 *
 * @param[in] cptr Locally connected client to send to.
 * @param[in] buf Client's message queue.
 * @param[out] count_in Total number of bytes in \a buf at entry.
 * @param[out] count_out Number of bytes consumed from \a buf.
 * \returns IO_FAILURE on error, IO_BLOCKED if no data could be sent, or
 *   IO_SUCCESS if any data was written from \a buf.
 */
IOResult ircd_tls_sendv(struct Client *cptr, struct MsgQ *buf,
                        unsigned int *count_in, unsigned int *count_out);

#endif /* INCLUDED_ircd_tls_h */
