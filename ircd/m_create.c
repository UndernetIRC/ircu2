/*
 * IRC - Internet Relay Chat, ircd/m_create.c
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
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * m_create - generic message handler
 */
int m_create(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return 0;
}

/*
 * ms_create - server message handler
 */
int ms_create(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char            cbuf[BUFSIZE];  /* Buffer for list with channels
                                     that `sptr' really creates */
  time_t          chanTS;         /* Creation time for all channels
                                     in the comma seperated list */
  char*           p;
  char*           name;
  struct Channel* chptr;
  int             badop;

  if (IsServer(sptr)) {
    /* PROTOCOL WARNING */
    /* bail, don't core */
    return 0;
  }
  /* sanity checks: Only accept CREATE messages from servers */
  if (!IsServer(cptr) || parc < 3 || *parv[2] == '\0')
    return 0;

  chanTS = atoi(parv[2]);

  /* A create that didn't appear during a burst has that servers idea of
   * the current time.  Use it for lag calculations.
   */
  if (!IsBurstOrBurstAck(sptr) && 0 != chanTS && MAGIC_REMOTE_JOIN_TS != chanTS)
    sptr->user->server->serv->lag = TStime() - chanTS;

  *cbuf = '\0';                 /* Start with empty buffer */

  /* For each channel in the comma seperated list: */
  for (name = ircd_strtok(&p, parv[1], ","); name; name = ircd_strtok(&p, 0, ","))
  {
    badop = 0;                  /* Default is to accept the op */
    if ((chptr = FindChannel(name)))
    {
      name = chptr->chname;
      if (TStime() - chanTS > TS_LAG_TIME)
      {
        /* A bounce would not be accepted anyway - if we get here something
           is wrong with the TS clock syncing (or we have more then
           TS_LAG_TIME lag, or an admin is hacking */
        badop = 2;
        /* This causes a HACK notice on all upstream servers: */
        sendto_one(cptr, "%s " TOK_MODE " %s -o %s%s 0", NumServ(&me), name, NumNick(sptr));
        /* This causes a WALLOPS on all downstream servers and a notice to our
           own opers: */
        parv[1] = name;         /* Corrupt parv[1], it is not used anymore anyway */
        send_hack_notice(cptr, sptr, parc, parv, badop, 2);
      }
      else if (chptr->creationtime && chanTS > chptr->creationtime &&
          chptr->creationtime != MAGIC_REMOTE_JOIN_TS)
      {
        /* We (try) to bounce the mode, because the CREATE is used on an older
           channel, probably a net.ride */
        badop = 1;
        /* Send a deop upstream: */
        sendto_one(cptr, "%s " TOK_MODE " %s -o %s%s " TIME_T_FMT, NumServ(&me),
                   name, NumNick(sptr), chptr->creationtime);
      }
    }
    else                        /* Channel doesn't exist: create it */
      chptr = get_channel(sptr, name, CGT_CREATE);

    /* Add and mark ops */
    add_user_to_channel(chptr, sptr,
        (badop || IsModelessChannel(name)) ? CHFL_DEOPPED : CHFL_CHANOP);

    /* Send user join to the local clients (if any) */
    sendto_channel_butserv(chptr, sptr, ":%s " MSG_JOIN " :%s", parv[0], name);

    if (badop)                  /* handle badop: convert CREATE into JOIN */
      sendto_serv_butone(cptr, "%s%s " TOK_JOIN " %s " TIME_T_FMT,
          NumNick(sptr), name, chptr->creationtime);
    else
    {
      /* Send the op to local clients:
         (if any; extremely unlikely, but it CAN happen) */
      if (!IsModelessChannel(name))
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s +o %s",
            sptr->user->server->name, name, parv[0]);

      /* Set/correct TS and add the channel to the
         buffer for accepted channels: */
      chptr->creationtime = chanTS;
      if (*cbuf)
        strcat(cbuf, ",");
      strcat(cbuf, name);
    }
  }

  if (*cbuf)                    /* Any channel accepted with ops ? */
  {
    sendto_serv_butone(cptr, "%s%s " TOK_CREATE " %s " TIME_T_FMT,
        NumNick(sptr), cbuf, chanTS);
  }

  return 0;
}

#if 0
/*
 * m_create
 *
 * parv[0] = sender prefix
 * parv[1] = channel names
 * parv[2] = channel time stamp
 */
int m_create(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char            cbuf[BUFSIZE];  /* Buffer for list with channels
                                     that `sptr' really creates */
  time_t          chanTS;         /* Creation time for all channels
                                     in the comma seperated list */
  char*           p;
  char*           name;
  struct Channel* chptr;
  int             badop;

  /* sanity checks: Only accept CREATE messages from servers */
  if (!IsServer(cptr) || parc < 3 || *parv[2] == '\0')
    return 0;

  chanTS = atoi(parv[2]);

  /* A create that didn't appear during a burst has that servers idea of
   * the current time.  Use it for lag calculations.
   */
  if (!IsBurstOrBurstAck(sptr) && 0 != chanTS && MAGIC_REMOTE_JOIN_TS != chanTS)
    sptr->user->server->serv->lag = TStime() - chanTS;

  *cbuf = '\0';                 /* Start with empty buffer */

  /* For each channel in the comma seperated list: */
  for (name = ircd_strtok(&p, parv[1], ","); name; name = ircd_strtok(&p, 0, ","))
  {
    badop = 0;                  /* Default is to accept the op */
    if ((chptr = FindChannel(name)))
    {
      name = chptr->chname;
      if (TStime() - chanTS > TS_LAG_TIME)
      {
        /* A bounce would not be accepted anyway - if we get here something
           is wrong with the TS clock syncing (or we have more then
           TS_LAG_TIME lag, or an admin is hacking */
        badop = 2;
        /* This causes a HACK notice on all upstream servers: */
        sendto_one(cptr, "%s " TOK_MODE " %s -o %s%s 0", NumServ(&me), name, NumNick(sptr));
        /* This causes a WALLOPS on all downstream servers and a notice to our
           own opers: */
        parv[1] = name;         /* Corrupt parv[1], it is not used anymore anyway */
        send_hack_notice(cptr, sptr, parc, parv, badop, 2);
      }
      else if (chptr->creationtime && chanTS > chptr->creationtime &&
          chptr->creationtime != MAGIC_REMOTE_JOIN_TS)
      {
        /* We (try) to bounce the mode, because the CREATE is used on an older
           channel, probably a net.ride */
        badop = 1;
        /* Send a deop upstream: */
        sendto_one(cptr, "%s " TOK_MODE " %s -o %s%s " TIME_T_FMT, NumServ(&me),
                   name, NumNick(sptr), chptr->creationtime);
      }
    }
    else                        /* Channel doesn't exist: create it */
      chptr = get_channel(sptr, name, CGT_CREATE);

    /* Add and mark ops */
    add_user_to_channel(chptr, sptr,
        (badop || IsModelessChannel(name)) ? CHFL_DEOPPED : CHFL_CHANOP);

    /* Send user join to the local clients (if any) */
    sendto_channel_butserv(chptr, sptr, ":%s " MSG_JOIN " :%s", parv[0], name);

    if (badop)                  /* handle badop: convert CREATE into JOIN */
      sendto_serv_butone(cptr, "%s%s " TOK_JOIN " %s " TIME_T_FMT,
          NumNick(sptr), name, chptr->creationtime);
    else
    {
      /* Send the op to local clients:
         (if any; extremely unlikely, but it CAN happen) */
      if (!IsModelessChannel(name))
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s +o %s",
            sptr->user->server->name, name, parv[0]);

      /* Set/correct TS and add the channel to the
         buffer for accepted channels: */
      chptr->creationtime = chanTS;
      if (*cbuf)
        strcat(cbuf, ",");
      strcat(cbuf, name);
    }
  }

  if (*cbuf)                    /* Any channel accepted with ops ? */
  {
    sendto_serv_butone(cptr, "%s%s " TOK_CREATE " %s " TIME_T_FMT,
        NumNick(sptr), cbuf, chanTS);
  }

  return 0;
}
#endif /* 0 */

