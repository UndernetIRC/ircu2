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

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Set a user's away state.
 * @param[in] user User whose away message may be changed.
 * @param[in] message New away message for \a user (or empty/null).
 * @return Non-zero if user is away, zero if user is "here".
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
      MyFree(away);
    away = (char*) MyMalloc(len + 1);
    assert(0 != away);

    user->away = away;
    strcpy(away, message);
  }
  return (user->away != 0);
}


/** Handle an AWAY message from a local user.
 *
 * \a parv has the following elements:
 * \li \a parv[1] (optional) is the new away message.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* away_message = parv[1];
  int was_away = cli_user(sptr)->away != 0;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (user_set_away(cli_user(sptr), away_message))
  {
    if (!was_away)
      sendcmdto_serv(sptr, CMD_AWAY, cptr, ":%s", away_message);
    send_reply(sptr, RPL_NOWAWAY);
  }
  else {
    sendcmdto_serv(sptr, CMD_AWAY, cptr, "");
    send_reply(sptr, RPL_UNAWAY);
  }
  return 0;
}

/** Handle an AWAY message from a server.
 *
 * \a parv has the following elements:
 * \li \a parv[1] (optional) is the new away message.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
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
    sendcmdto_serv(sptr, CMD_AWAY, cptr, ":%s", away_message);
  else
    sendcmdto_serv(sptr, CMD_AWAY, cptr, "");
  return 0;
}


