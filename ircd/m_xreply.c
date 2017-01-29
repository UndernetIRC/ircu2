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
#include "s_auth.h"
#include "send.h"

#include <string.h>

/*
 * ms_xreply - extension message reply handler
 *
 * parv[0] = sender prefix
 * parv[1] = target server numeric
 * parv[2] = routing information
 * parv[3] = extension message reply
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
  acptr = parv[1][2] ? findNUser(parv[1]) : FindNServer(parv[1]);
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
