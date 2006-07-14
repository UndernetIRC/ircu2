/*
 * IRC - Internet Relay Chat, ircd/m_wallchops.c
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

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a WALLCHOPS message from a local connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the name of the channel to which to send
 * \li \a parv[\a parc - 1] is the message to send
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_wallchops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, "WALLCHOPS");

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (IsChannelName(parv[1]) && (chptr = FindChannel(parv[1]))) {
    if (client_can_send_to_channel(sptr, chptr, 0)) {
      if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
          check_target_limit(sptr, chptr, chptr->chname, 0))
        return 0;
      sendcmdto_channel_butone(sptr, CMD_WALLCHOPS, chptr, cptr,
			       SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
			       "%H :@ %s", chptr, parv[parc - 1]);
    }
    else
      send_reply(sptr, ERR_CANNOTSENDTOCHAN, parv[1]);
  }
  else
    send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  return 0;
}

/** Handle a WALLCHOPS message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the name of the channel to which to send
 * \li \a parv[\a parc - 1] is the message to send
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_wallchops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  assert(0 != cptr);
  assert(0 != sptr);

  if (parc < 3 || !IsUser(sptr))
    return 0;

  if (!IsLocalChannel(parv[1]) && (chptr = FindChannel(parv[1]))) {
    if (client_can_send_to_channel(sptr, chptr, 0)) {
      sendcmdto_channel_butone(sptr, CMD_WALLCHOPS, chptr, cptr,
			       SKIP_DEAF | SKIP_BURST | SKIP_NONOPS,
			       "%H :%s", chptr, parv[parc - 1]);
    } else
      send_reply(sptr, ERR_CANNOTSENDTOCHAN, parv[1]);
  }
  return 0;
}
