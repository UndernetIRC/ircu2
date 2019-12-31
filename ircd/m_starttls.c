/*
 * IRC - Internet Relay Chat, ircd/m_starttls.c
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
 * @brief STARTTLS message handlers.
 */

#include "config.h"
#include "client.h"
#include "dbuf.h"
#include "handlers.h"
#include "ircd_reply.h"
#include "ircd_tls.h"
#include "numeric.h"
#include "send.h"

int m_starttls(struct Client *cptr, struct Client *sptr, int parc, char*parv[])
{
  if (IsTLS(sptr))
    return send_reply(sptr, ERR_STARTTLS, "already using TLS");

  send_queued(sptr);

  s_tls(&cli_socket(cptr)) = ircd_tls_accept(NULL, cli_fd(cptr));
  if (!s_tls(&cli_socket(cptr)))
    return send_reply(sptr, ERR_STARTTLS, "internal TLS error");

  DBufClear(&cli_recvQ(sptr));
  send_reply(sptr, RPL_STARTTLS);

  SetNegotiatingTLS(sptr);
  SetTLS(sptr);
  ircd_tls_negotiate(sptr);

  return 0;
}
