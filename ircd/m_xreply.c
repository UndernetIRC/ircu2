/*
 * IRC - Internet Relay Chat, ircd/m_xreply.c
 * Copyright (C) 2010 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_auth.h"
#include "send.h"

#include <string.h>

/** Handles XREPLY from a service back to a server or oper.
 *
 * \a parv has the following elements:
 * \li parv[1] target server or client numnick
 * \li parv[2] routing information
 * \li parv[3] extension message reply
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_xreply(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  const char* routing;
  const char* reply;

  if (parc < 4) /* have enough parameters? */
    return need_more_params(sptr, "XREPLY");

  routing = parv[2];
  reply = parv[3];

  /* Look up the target */
  acptr = FindNClient(parv[1]);
  if (!acptr)
    return send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHSERVER,
		      "* :Server has disconnected");

  /* If it's not to us, forward the reply */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_XREPLY, acptr, "%C %s :%s", acptr, routing,
		  reply);
    return 0;
  }

  /* OK, figure out where to route the message */
  if (!ircd_strncmp("iauth:", routing, 6))
    auth_send_xreply(sptr, routing + 6, reply);
  else
    /* If we don't know where to route it, log it and drop it */
    log_write(LS_SYSTEM, L_NOTICE, 0, "Received unroutable extension reply "
	      "from %#C to %#C routing %s; message: %s", sptr, acptr,
	      routing, reply);

  return 0;
}
