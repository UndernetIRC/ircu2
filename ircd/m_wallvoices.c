/*
 * IRC - Internet Relay Chat, ircd/m_wallvoices.c
 * Copyright (c) 2002 hikari
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

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>

/*
 * m_wallvoices - local generic message handler
 */
int m_wallvoices(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;

  assert(0 != cptr);
  assert(cptr == sptr);

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, "WALLVOICES");

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (IsChannelName(parv[1]) && (chptr = FindChannel(parv[1]))) {
    if (client_can_send_to_channel(sptr, chptr)) {
      if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
          check_target_limit(sptr, chptr, chptr->chname, 0))
        return 0;
      sendcmdto_channel_butone(sptr, CMD_WALLVOICES, chptr, cptr,
			       SKIP_DEAF | SKIP_BURST | SKIP_NONVOICES, 
			       "%H :+ %s", chptr, parv[parc - 1]);
    }
    else
      send_reply(sptr, ERR_CANNOTSENDTOCHAN, parv[1]);
  }
  else
    send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  return 0;
}

/*
 * ms_wallvoices - server message handler
 */
int ms_wallvoices(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  assert(0 != cptr);
  assert(0 != sptr);

  if (parc < 3 || !IsUser(sptr))
    return 0;

  if (*parv[1] != '&' && (chptr = FindChannel(parv[1]))) {
    if (client_can_send_to_channel(sptr, chptr)) {
      sendcmdto_channel_butone(sptr, CMD_WALLVOICES, chptr, cptr,
			       SKIP_DEAF | SKIP_BURST | SKIP_NONVOICES, 
			       "%H :%s", chptr, parv[parc - 1]);
    } else
      send_reply(sptr, ERR_CANNOTSENDTOCHAN, parv[1]);
  }
  return 0;
}
