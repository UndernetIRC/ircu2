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
 * m_wallchops - local generic message handler
 */
int m_wallchops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;

  assert(0 != cptr);
  assert(cptr == sptr);

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 2 || EmptyString(parv[1]))
    return send_error_to_client(sptr, ERR_NORECIPIENT, "WALLCHOPS");

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_error_to_client(sptr, ERR_NOTEXTTOSEND);

  if (IsChannelName(parv[1]) && (chptr = FindChannel(parv[1]))) {
    if (client_can_send_to_channel(sptr, chptr)) {
      if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
          check_target_limit(sptr, chptr, chptr->chname, 0))
        return 0;
      /* Send to local clients: */
      sendto_lchanops_butone(cptr, sptr, chptr,
            ":%s " MSG_NOTICE " @%s :%s", sptr->name, parv[1], parv[parc - 1]);
      /* And to other servers: */
      sendto_chanopsserv_butone(cptr, sptr, chptr,
            "%s%s " TOK_WALLCHOPS " %s :%s", NumNick(sptr), parv[1], parv[parc - 1]);
    }
    else
      send_error_to_client(sptr, ERR_CANNOTSENDTOCHAN, parv[1]);
  }
  else
    send_error_to_client(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  return 0;
}

/*
 * ms_wallchops - server message handler
 */
int ms_wallchops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  assert(0 != cptr);
  assert(0 != sptr);

  if (parc < 3 || !IsUser(sptr))
    return 0;

  if ((chptr = FindChannel(parv[1]))) {
    if (client_can_send_to_channel(sptr, chptr)) {
      /*
       * Send to local clients:
       */
      sendto_lchanops_butone(cptr, sptr, chptr,
          ":%s " MSG_NOTICE " @%s :%s", sptr->name, parv[1], parv[parc - 1]);
      /*
       * And to other servers:
       */
      sendto_chanopsserv_butone(cptr, sptr, chptr,
          "%s%s " TOK_WALLCHOPS " %s :%s", NumNick(sptr), parv[1], parv[parc - 1]);
    }
    else
      sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, sptr->name, parv[1]);
  }
  return 0;
}

#if 0
/*
 * m_wallchops
 *
 * parv[0] = sender prefix
 * parv[1] = target channel
 * parv[parc - 1] = wallchops text
 */
int m_wallchops(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 2 || *parv[1] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NORECIPIENT), me.name, parv[0], "WALLCHOPS");
    return -1;
  }

  if (parc < 3 || *parv[parc - 1] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
    return -1;
  }

  if (MyUser(sptr))
    parv[1] = canonize(parv[1]);

  if (IsChannelName(parv[1]))
  {
    if ((chptr = FindChannel(parv[1])))
    {
      if (client_can_send_to_channel(sptr, chptr))
      {
        if (MyUser(sptr) && (chptr->mode.mode & MODE_NOPRIVMSGS) &&
            check_target_limit(sptr, chptr, chptr->chname, 0))
          return 0;
        /* Send to local clients: */
        sendto_lchanops_butone(cptr, sptr, chptr,
            ":%s NOTICE @%s :%s", parv[0], parv[1], parv[parc - 1]);
        /* And to other servers: */
        sendto_chanopsserv_butone(cptr, sptr, chptr,
            ":%s WC %s :%s", parv[0], parv[1], parv[parc - 1]);
      }
      else
        sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN),
            me.name, parv[0], parv[1]);
    }
  }
  else
    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], parv[1]);

  return 0;
}
#endif /* 0 */
