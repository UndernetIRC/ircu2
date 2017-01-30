/*
 * IRC - Internet Relay Chat, ircd/m_rping.c
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
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */


/*
 * Old P10:
 * Sending [:defiant.atomicrevs.net RPING Z Gte- 953863987 524184 :<No client start time>] to 
 * alphatest.atomicrevs.net
 * Full P10:
 * Parsing: j RI Z jAA 953865133 0 :<No client start time>
 */

/** Handle an RPING message from a server connection.
 * -- by Run
 *
 * This is a way for an operator somewhere on the network to request
 * that some server on the network ping another server, even if the
 * operator is not connected to either of those servers.
 *
 * The operator requests an remote ping:
 *   RPING ServerA.* ServerB.* :Rping message
 * If ServerB.* is not the operator's server, this message goes to
 * ServerB.* (OpNmN is the operator's numnick, RI is the RPING token,
 * SA is ServerA.*'s numnick, SB is ServerB.*'s numnick):
 *   OpNmN RI SA SB :Rping message
 * ServerB.* then rpings ServerA.*:
 *   SB RI SA OpNmN 123456789 12345 :Rping message
 * ServerA.* responds (RO is the RPONG token):
 *   SA RO ServerB.* OpNmN 12345689 12 :Rping message
 * ServerB.* eventually gets this, and may have to send it back to the
 * operator's server (567 is the number of elapsed milliseconds):
 *   SB RO OpNmN ServerA.* 567 :Rping message
 * The operator's server informs the operator:
 *   ServerB.* RPONG OperNick ServerA.* 567 :Rping message
 *
 * If \a sptr is a server, it is the rping source and \a parv has the
 * following elements:
 * \li \a parv[1] is the rping target's numnick
 * \li \a parv[2] is the rping requester's numnick
 * \li \a parv[3] is the rping start time (seconds part)
 * \li \a parv[4] is the rping start time (microseconds part)
 * \li \a parv[5] is the requester's remark
 *
 * If \a sptr is a user, it is the rping requester and \a parv has the
 * following elements:
 * \li \a parv[1] is the rping target's numnick
 * \li \a parv[2] is the rping source's numnick
 * \li \a parv[3] is the requester's remark
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_rping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* destination = 0;
  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  /*
   * shouldn't happen
   */
  if (!IsPrivileged(sptr))
    return 0;

  if (IsServer(sptr)) {
    if (parc < 6) {
      /*
       * PROTOCOL ERROR
       */
      return need_more_params(sptr, "RPING");
    }
    if ((destination = FindNServer(parv[1]))) {
      /*
       * if it's not for me, pass it on
       */
      if (IsMe(destination))
	sendcmdto_one(&me, CMD_RPONG, sptr, "%s %s %s %s :%s", cli_name(sptr),
		      parv[2], parv[3], parv[4], parv[5]);
      else
	sendcmdto_one(sptr, CMD_RPING, destination, "%C %s %s %s :%s",
		      destination, parv[2], parv[3], parv[4], parv[5]);
    }
  }
  else {
    if (parc < 3) {
      return need_more_params(sptr, "RPING");
    }
    /*
     * Haven't made it to the start server yet, if I'm not the start server
     * pass it on.
     */
    if (hunt_server_cmd(sptr, CMD_RPING, cptr, 1, "%s %C :%s", 2, parc, parv)
	!= HUNTED_ISME)
      return 0;
    /*
     * otherwise ping the destination from here
     */
    if ((destination = find_match_server(parv[1]))) {
      assert(IsServer(destination) || IsMe(destination));
      sendcmdto_one(&me, CMD_RPING, destination, "%C %C %s :%s", destination,
		    sptr, militime(0, 0), parv[3]);
    }
    else
      send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);
  }
  return 0;
}

/** Handle an RPING message from an operator connection.
 * -- by Run
 *
 * This message is used for remotely initiated pings.  See ms_rping()
 * for the theory of operation.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the name of the rping target
 * \li \a parv[2] (optional) is the name of the rping source (defaults
 *   to this server)
 * \li \a parv[3] (optional) is a remark (defaults to "\<No client
 *   start time\>")
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_rping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr = 0;
  const char*    start_time = "<No client start time>";

  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);
  assert(IsAnOper(sptr));

  if (parc < 2)
    return need_more_params(sptr, "RPING");

  if (parc > 2) {
    if ((acptr = find_match_server(parv[2])) && !IsMe(acptr)) {
      parv[2] = cli_name(acptr);
      if (3 == parc) {
        /*
         * const_cast<char*>(start_time);
         */
        parv[parc++] = (char*) start_time;
      }
      hunt_server_cmd(sptr, CMD_RPING, cptr, 1, "%s %C :%s", 2, parc, parv);
      return 0;
    }
    else
      start_time = parv[2];
  }

  if ((acptr = find_match_server(parv[1]))) {
    assert(IsServer(acptr) || IsMe(acptr));
    sendcmdto_one(&me, CMD_RPING, acptr, "%C %C %s :%s", acptr, sptr,
		  militime(0, 0), start_time);
  }
  else
    send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);

  return 0;
}
