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

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_user.h"
#include "s_serv.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a LUSERS message from a local connection.
 *
 * \a parv may either be empty or have the following elements:
 * \a \li parv[1] is ignored
 * \a \li parv[2] is the server to query
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
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

/** Handle a LUSERS message from a server connection.
 *
 * \a parv has the following elements:
 * \a \li parv[1] is ignored
 * \a \li parv[2] is the server to query
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
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
