/*
 * IRC - Internet Relay Chat, ircd/tls_none.c
 * Copyright (C) 2019 Michael Poole
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Stub (noop) implementation of ircd TLS functions.
 */

#include "config.h"
#include "ircd_tls.h"
#include "ircd_sha1.h"
#include "client.h"
#include <stddef.h>
#include <string.h>

const char *ircd_tls_version = NULL;

int ircd_tls_init(void)
{
  return 0;
}

void *ircd_tls_accept(struct Listener *listener, int fd)
{
  return NULL;
}

void *ircd_tls_connect(struct ConfItem *aconf, int fd)
{
  return NULL;
}

void ircd_tls_close(void *ctx, const char *message)
{
  return;
}

void ircd_tls_conf_free(struct ConfItem *aconf)
{
  (void)aconf;
}

int ircd_tls_conf_reload(struct ConfItem *aconf)
{
  (void)aconf;
  return 0;
}

int ircd_tls_check_peer_hostname(struct Client *cptr, const char *name)
{
  (void)cptr;
  (void)name;
  return 0;
}

int ircd_tls_listen(struct Listener *listener)
{
  (void)listener;
  return 0;
}

int ircd_tls_listener_ready(const struct Listener *listener)
{
  (void)listener;
  return 0;
}

void ircd_tls_listen_free(struct Listener *listener)
{
  (void)listener;
}

IOResult tls_backend_handshake(struct Client *cptr, struct tls_peer *peer,
                               char *reason, size_t reasonlen,
                               enum ircd_tls_want *want)
{
  (void)cptr;
  (void)peer;
  (void)reason;
  (void)reasonlen;
  (void)want;
  return IO_FAILURE;
}

void tls_backend_drop(struct Client *cptr)
{
  (void)cptr;
}


IOResult tls_backend_read(struct Client *cptr, char *buf, unsigned int length,
                          unsigned int *count_out, enum ircd_tls_want *want)
{
  (void)cptr;
  (void)buf;
  (void)length;
  *count_out = 0;
  *want = IRCD_TLS_WANT_NONE;
  return IO_FAILURE;
}

IOResult tls_backend_write(struct Client *cptr, const char *buf,
                           unsigned int len, unsigned int *written,
                           enum ircd_tls_want *want)
{
  (void)cptr;
  (void)buf;
  (void)len;
  *written = 0;
  *want = IRCD_TLS_WANT_NONE;
  return IO_FAILURE;
}

int ircd_tls_sha1_base64(const void *data, size_t len, char *out, size_t outlen)
{
  return ircd_sha1_base64(data, len, out, outlen);
}
