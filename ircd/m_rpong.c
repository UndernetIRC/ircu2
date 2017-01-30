/*
 * IRC - Internet Relay Chat, ircd/m_rpong.c
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
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle an RPONG message from a server
 * -- by Run too :)
 *
 * This message is used for reporting the results of remotely
 * initiated pings.  See ms_rping() for the theory of operation.
 *
 * Going from the rping target to the rping source, \a parv has the
 * following elements:
 * \li \a parv[1] is the rping source's name (numnick is also allowed)
 * \li \a parv[2] is the rping requester's numnick
 * \li \a parv[3] is the rping start time (seconds part)
 * \li \a parv[4] is the rping start time (microseconds part)
 * \li \a parv[5] is the requester's remark
 *
 * Going from the rping source to the rping requester, \a parv has the
 * following elements:
 * \li \a parv[1] is the rping source's name (numnick is also allowed)
 * \li \a parv[2] is the rping requester's numnick
 * \li \a parv[3] is the rping round trip time in milliseconds
 * \li \a parv[4] is the requester's remark
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_rpong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;

  if (!IsServer(sptr))
    return 0;

  if (parc < 5) {
    /*
     * PROTOCOL ERROR
     */
    return need_more_params(sptr, "RPONG");
  }
  if (parc == 6) {
    /*
     * from pinged server to source server
     */
    if (!(acptr = FindServer(parv[1])) && !(acptr = FindNServer(parv[1])))
      return 0;
   
    if (IsMe(acptr)) {
      if (!(acptr = findNUser(parv[2])))
        return 0;

      sendcmdto_one(&me, CMD_RPONG, acptr, "%C %s %s :%s", acptr, cli_name(sptr),
		    militime(parv[3], parv[4]), parv[5]);
    } else
      sendcmdto_one(sptr, CMD_RPONG, acptr, "%s %s %s %s :%s", parv[1],
		    parv[2], parv[3], parv[4], parv[5]);
  } else {
    /*
     * returned from source server to client
     */
    if (!(acptr = findNUser(parv[1])))
      return 0;

    sendcmdto_one(sptr, CMD_RPONG, acptr, "%C %s %s :%s", acptr, parv[2],
		  parv[3], parv[4]);
  }
  return 0;
}
