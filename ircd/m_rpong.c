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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "send.h"

#include <assert.h>

/*
 * ms_rpong - server message handler
 * -- by Run too :)
 *
 * parv[0] = sender prefix
 * parv[1] = from pinged server: start server; from start server: sender
 * parv[2] = from pinged server: sender; from start server: pinged server
 * parv[3] = pingtime in ms
 * parv[4] = client info (for instance start time)
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
    if (!(acptr = FindNServer(parv[1])))
      return 0;
   
    if (IsMe(acptr)) {
      if (!(acptr = FindNUser(parv[2])))
        return 0;
      if (MyConnect(acptr))
        sendto_one(acptr, ":%s " MSG_RPONG " %s %s %s :%s",
                   me.name, acptr->name, sptr->name,
                   militime(parv[3], parv[4]), parv[5]);
      else 
        sendto_one(acptr, "%s " TOK_RPONG " %s%s %s %s :%s",
                   NumServ(&me), NumNick(acptr), sptr->name,
                   militime(parv[3], parv[4]), parv[5]);
    }
    else
      sendto_one(acptr, "%s " TOK_RPONG " %s %s %s %s :%s",
                 parv[0], parv[1], parv[2], parv[3], parv[4], parv[5]);
  }
  else {
    /*
     * returned from source server to client
     */
    if (!(acptr = FindNUser(parv[1])))
      return 0;
    if (MyConnect(acptr))
      sendto_one(acptr, ":%s " MSG_RPONG " %s %s %s :%s",
                 sptr->name, acptr->name, parv[2], parv[3], parv[4]);
    else
      sendto_one(acptr, "%s " TOK_RPONG " %s %s %s :%s",
                 parv[0], parv[1], parv[2], parv[3], parv[4]);
  }
  return 0;
}


#if 0
/*
 * m_rpong  -- by Run too :)
 *
 * parv[0] = sender prefix
 * parv[1] = from pinged server: start server; from start server: sender
 * parv[2] = from pinged server: sender; from start server: pinged server
 * parv[3] = pingtime in ms
 * parv[4] = client info (for instance start time)
 */
int m_rpong(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;

  if (!IsServer(sptr))
    return 0;

  if (parc < 5)
    return need_more_params(sptr, "RPING");

  if (!(acptr = FindClient(parv[1])))
    return 0;

  if (!IsMe(acptr))
  {
    if (IsServer(acptr) && parc > 5)
    {
      sendto_one(acptr, ":%s RPONG %s %s %s %s :%s",
          parv[0], parv[1], parv[2], parv[3], parv[4], parv[5]);
      return 0;
    }
  }
  else
  {
    parv[1] = parv[2];
    parv[2] = sptr->name;
    parv[0] = me.name;
    parv[3] = militime(parv[3], parv[4]);
    parv[4] = parv[5];
    if (!(acptr = FindUser(parv[1])))
      return 0;                 /* No bouncing between servers ! */
  }

  sendto_one(acptr, ":%s RPONG %s %s %s :%s",
      parv[0], parv[1], parv[2], parv[3], parv[4]);
  return 0;
}
#endif /* 0 */

