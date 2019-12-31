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
}

void ircd_tls_fingerprint(void *ctx, char *fingerprint)
{
  memset(fingerprint, 0, 32);
}

int ircd_tls_negotiate(struct Client *cptr)
{
  return 1;
}

IOResult ircd_tls_recv(struct Client *cptr, char *buf,
                       unsigned int length, unsigned int *count_out)
{
  return os_recv_nonb(cli_fd(cptr), buf, length, count_out);
}

IOResult ircd_tls_sendv(struct Client *cptr, struct MsgQ *buf,
                        unsigned int *count_in, unsigned int *count_out)
{
  return os_sendv_nonb(cli_fd(cptr), buf, count_in, count_out);
}
