/*
 * IRC - Internet Relay Chat, ircd/m_xquery.c
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
#include "send.h"

#include <string.h>

/** Handles XQUERY from an IRC or server operator.
 *
 * \a parv has the following elements:
 * \li parv[1] target server
 * \li parv[2] routing information
 * \li parv[3] extension message
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_xquery(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;

  if (parc < 4) /* have enough parameters? */
    return need_more_params(sptr, "XQUERY");

  /* Look up the target server */
  if (!(acptr = find_match_server(parv[1])))
    return send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);

  /* If it's to us, do nothing; otherwise, forward the query */
  if (!IsMe(acptr))
    sendcmdto_one(sptr, CMD_XQUERY, acptr, "%C %s :%s", acptr, parv[2],
		  parv[3]);

  return 0;
}

/** Handles XQUERY from another server.
 *
 * \a parv has the following elements:
 * \li parv[1] target server
 * \li parv[2] routing information
 * \li parv[3] extension message
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_xquery(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;

  if (parc < 4) /* have enough parameters? */
    return need_more_params(sptr, "XQUERY");

  /* Look up the target server */
  if (!(acptr = FindNServer(parv[1])))
    return send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHSERVER,
		      "* :Server has disconnected");

  /* Forward the query to its destination */
  if (!IsMe(acptr))
    sendcmdto_one(sptr, CMD_XQUERY, acptr, "%C %s :%s", acptr, parv[2],
		  parv[3]);
  else /* if it's to us, log it */
    log_write(LS_SYSTEM, L_NOTICE, 0, "Received extension query from "
	      "%#C to %#C routing %s; message: %s", sptr, acptr,
	      parv[2], parv[3]);

  return 0;
}
