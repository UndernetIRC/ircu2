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
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>


/*
 * Old P10:
 * Sending [:defiant.atomicrevs.net RPING Z Gte- 953863987 524184 :<No client start time>] to 
 * alphatest.atomicrevs.net
 * Full P10:
 * Parsing: j RI Z jAA 953865133 0 :<No client start time>
 */

/*
 * ms_rping - server message handler
 * -- by Run
 *
 *    parv[0] = sender (sptr->name thus)
 * if sender is a person: (traveling towards start server)
 *    parv[1] = pinged server[mask]
 *    parv[2] = start server (current target)
 *    parv[3] = optional remark
 * if sender is a server: (traveling towards pinged server)
 *    parv[1] = pinged server (current target)
 *    parv[2] = original sender (person)
 *    parv[3] = start time in s
 *    parv[4] = start time in us
 *    parv[5] = the optional remark
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

/*
 * mo_rping - oper message handler
 * -- by Run
 *
 *
 * Receive:
 *          RPING blah.*
 *          RPING blah.* :<start time>
 *          RPING blah.* server.* :<start time>
 *
 *    parv[0] = sender (sptr->name thus)
 *    parv[1] = pinged server name or mask (required)
 *    parv[2] = start server name or mask (optional, defaults to me)
 *    parv[3] = client start time (optional) 
 * 
 * Send: NumNick(sptr) RPING blah.* server.net :<start time> (hunt_server)
 *       NumServ(&me) RPING NumServ(blah.bar.net) NumNick(sptr) :<start time> (here)
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
