/*
 * IRC - Internet Relay Chat, ircd/m_away.c
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
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <string.h>

/*
 * user_set_away - set user away state
 * returns 1 if client is away or changed away message, 0 if 
 * client is removing away status.
 * NOTE: this function may modify user and message, so they
 * must be mutable.
 */
static int user_set_away(struct User* user, char* message)
{
  char* away;
  assert(0 != user);

  away = user->away;

  if (EmptyString(message)) {
    /*
     * Marking as not away
     */
    if (away) {
      MyFree(away);
      user->away = 0;
    }
  }
  else {
    /*
     * Marking as away
     */
    unsigned int len = strlen(message);

    if (len > AWAYLEN) {
      message[AWAYLEN] = '\0';
      len = AWAYLEN;
    }
    if (away)
      away = (char*) MyRealloc(away, len + 1);
    else
      away = (char*) MyMalloc(len + 1);
    assert(0 != away);

    user->away = away;
    strcpy(away, message);
  }
  return (user->away != 0);
}


/*
 * m_away - generic message handler
 * - Added 14 Dec 1988 by jto.
 *
 * parv[0] = sender prefix
 * parv[1] = away message
 *
 * TODO: Throttle aways - many people have a script which resets the away
 *       message every 10 seconds which really chews the bandwidth.
 */
int m_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* away_message = parv[1];
  int was_away = cli_user(sptr)->away != 0;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (user_set_away(cli_user(sptr), away_message)) {
    if (!was_away)
    	sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s", away_message);
    send_reply(sptr, RPL_NOWAWAY);
  }
  else {
    sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, "");
    send_reply(sptr, RPL_UNAWAY);
  }
  return 0;
}

/*
 * ms_away - server message handler
 * - Added 14 Dec 1988 by jto.
 *
 * parv[0] = sender prefix
 * parv[1] = away message
 */
int ms_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* away_message = parv[1];

  assert(0 != cptr);
  assert(0 != sptr);
  /*
   * servers can't set away
   */
  if (IsServer(sptr))
    return protocol_violation(sptr,"Server trying to set itself away");

  if (user_set_away(cli_user(sptr), away_message))
    sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s", away_message);
  else
    sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, "");
  return 0;
}


