/*
 * IRC - Internet Relay Chat, ircd/m_lusers.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_user.h"
#include "s_serv.h"
#include "send.h"

#include <assert.h>

/*
 * m_lusers - generic message handler
 *
 * parv[0] = sender
 * parv[1] = ignored
 * parv[2] = server to query
 */
int m_lusers(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int longoutput = MyUser(sptr) || IsOper(sptr);
  if (parc > 2)
    if (hunt_server_cmd(sptr, CMD_LUSERS, cptr, feature_int(FEAT_HIS_REMOTE),
			"%s :%C", 2, parc, parv) != HUNTED_ISME)
      return 0;

  send_reply(sptr, RPL_LUSERCLIENT, UserStats.clients - UserStats.inv_clients,
	     UserStats.inv_clients, UserStats.servers);
  if (longoutput && UserStats.opers)
    send_reply(sptr, RPL_LUSEROP, UserStats.opers);
  if (UserStats.unknowns > 0)
    send_reply(sptr, RPL_LUSERUNKNOWN, UserStats.unknowns);
  if (longoutput && UserStats.channels > 0)
    send_reply(sptr, RPL_LUSERCHANNELS, UserStats.channels);
  send_reply(sptr, RPL_LUSERME, UserStats.local_clients,
	     UserStats.local_servers);

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Highest connection count: "
		"%d (%d clients)", sptr, max_connection_count,
		max_client_count);

  return 0;
}

/*
 * ms_lusers - server message handler
 *
 * parv[0] = sender
 * parv[1] = ignored
 * parv[2] = server to query
 */
int ms_lusers(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int longoutput = MyUser(sptr) || IsOper(sptr);
  if (parc > 2)
    if (hunt_server_cmd(sptr, CMD_LUSERS, cptr, 0, "%s :%C", 2, parc, parv) !=
        HUNTED_ISME)
      return 0;

  send_reply(sptr, RPL_LUSERCLIENT, UserStats.clients - UserStats.inv_clients,
	     UserStats.inv_clients, UserStats.servers);
  if (longoutput && UserStats.opers)
    send_reply(sptr, RPL_LUSEROP, UserStats.opers);
  if (UserStats.unknowns > 0)
    send_reply(sptr, RPL_LUSERUNKNOWN, UserStats.unknowns);
  if (longoutput && UserStats.channels > 0)
    send_reply(sptr, RPL_LUSERCHANNELS, UserStats.channels);
  send_reply(sptr, RPL_LUSERME, UserStats.local_clients,
	     UserStats.local_servers);

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Highest connection count: "
		"%d (%d clients)", sptr, max_connection_count,
		max_client_count);

  return 0;
}
