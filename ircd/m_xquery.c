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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
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

/*
 * m_xquery - extension message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target server
 * parv[2] = routing information
 * parv[3] = extension message
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

/*
 * ms_xquery - extension message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target server numeric
 * parv[2] = routing information
 * parv[3] = extension message
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
