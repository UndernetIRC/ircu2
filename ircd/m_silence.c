/*
 * IRC - Internet Relay Chat, ircd/m_silence.c
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
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * m_silence - generic message handler
 *
 *   parv[0] = sender prefix
 * From local client:
 *   parv[1] = mask (NULL sends the list)
 * From remote client:
 *   parv[1] = Numeric nick that must be silenced
 *   parv[2] = mask
 *
 * XXX - ugh 
 */
int m_silence(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct SLink*  lp;
  struct Client* acptr;
  char           c;
  char*          cp;

  assert(0 != cptr);
  assert(cptr == sptr);

  acptr = sptr;

  if (parc < 2 || EmptyString(parv[1]) || (acptr = FindUser(parv[1]))) {
    if (!(acptr->user))
      return 0;
    for (lp = acptr->user->silence; lp; lp = lp->next)
      sendto_one(sptr, rpl_str(RPL_SILELIST), me.name,
	         sptr->name, acptr->name, lp->value.cp);
    sendto_one(sptr, rpl_str(RPL_ENDOFSILELIST), me.name, sptr->name,
	       acptr->name);
    return 0;
  }
  cp = parv[1];
  c = *cp;
  if (c == '-' || c == '+')
    cp++;
  else if (!(strchr(cp, '@') || strchr(cp, '.') || strchr(cp, '!') || strchr(cp, '*'))) {
    return send_error_to_client(sptr, ERR_NOSUCHNICK, parv[1]);
  }
  else
    c = '+';
  cp = pretty_mask(cp);
  if ((c == '-' && !del_silence(sptr, cp)) || (c != '-' && !add_silence(sptr, cp))) {
    sendto_prefix_one(sptr, sptr, ":%s " MSG_SILENCE " %c%s", parv[0], c, cp);
    if (c == '-')
      sendto_serv_butone(0, "%s%s " TOK_SILENCE " * -%s", NumNick(sptr), cp);
  }
  return 0;
}

/*
 * ms_silence - server message handler
 *
 *   parv[0] = sender prefix
 * From local client:
 *   parv[1] = mask (NULL sends the list)
 * From remote client:
 *   parv[1] = Numeric nick that must be silenced
 *   parv[2] = mask
 */
int ms_silence(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;

  if (IsServer(sptr)) {
    /* PROTOCOL WARNING */
    /* bail, don't core */
    return 0;
  }
  if (parc < 3 || EmptyString(parv[2])) {
    /* PROTOCOL WARNING */
    return need_more_params(sptr, "SILENCE");
  }

  if (*parv[1])        /* can be a server */
    acptr = findNUser(parv[1]);
  else
    acptr = FindNServer(parv[1]);

  if (*parv[2] == '-') {
    if (!del_silence(sptr, parv[2] + 1))
      sendto_serv_butone(cptr, ":%s SILENCE * %s", parv[0], parv[2]);
  }
  else {
    add_silence(sptr, parv[2]);
    if (acptr && IsServer(acptr->from)) {
      if (IsServer(acptr))
	sendto_one(acptr, ":%s SILENCE %s %s",
	           parv[0], NumServ(acptr), parv[2]);
      else
	sendto_one(acptr, ":%s SILENCE %s%s %s",
	           parv[0], NumNick(acptr), parv[2]);
    }
  }
  return 0;
}


#if 0
/*
 * m_silence() - Added 19 May 1994 by Run.
 *
 *   parv[0] = sender prefix
 * From local client:
 *   parv[1] = mask (NULL sends the list)
 * From remote client:
 *   parv[1] = Numeric nick that must be silenced
 *   parv[2] = mask
 */
int m_silence(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct SLink *lp;
  struct Client *acptr;
  char c, *cp;

  if (MyUser(sptr))
  {
    acptr = sptr;
    if (parc < 2 || *parv[1] == '\0' || (acptr = FindUser(parv[1])))
    {
      if (!(acptr->user))
        return 0;
      for (lp = acptr->user->silence; lp; lp = lp->next)
        sendto_one(sptr, rpl_str(RPL_SILELIST), me.name,
            sptr->name, acptr->name, lp->value.cp);
      sendto_one(sptr, rpl_str(RPL_ENDOFSILELIST), me.name, sptr->name,
          acptr->name);
      return 0;
    }
    cp = parv[1];
    c = *cp;
    if (c == '-' || c == '+')
      cp++;
    else if (!(strchr(cp, '@') || strchr(cp, '.') ||
        strchr(cp, '!') || strchr(cp, '*')))
    {
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
      return -1;
    }
    else
      c = '+';
    cp = pretty_mask(cp);
    if ((c == '-' && !del_silence(sptr, cp)) ||
        (c != '-' && !add_silence(sptr, cp)))
    {
      sendto_prefix_one(sptr, sptr, ":%s SILENCE %c%s", parv[0], c, cp);
      if (c == '-')
        sendto_serv_butone(0, ":%s SILENCE * -%s", sptr->name, cp);
    }
  }
  else if (parc < 3 || *parv[2] == '\0')
    return need_more_params(sptr, "SILENCE");

  else
  {
    if (*parv[1])        /* can be a server */
      acptr = findNUser(parv[1]);
    else
      acptr = FindNServer(parv[1]);

    if (*parv[2] == '-')
    {
      if (!del_silence(sptr, parv[2] + 1))
        sendto_serv_butone(cptr, ":%s SILENCE * %s", parv[0], parv[2]);
    }
    else
    {
      add_silence(sptr, parv[2]);
      if (acptr && IsServer(acptr->from))
      {
        if (IsServer(acptr))
          sendto_one(acptr, ":%s SILENCE %s %s",
              parv[0], NumServ(acptr), parv[2]);
        else
          sendto_one(acptr, ":%s SILENCE %s%s %s",
              parv[0], NumNick(acptr), parv[2]);
      }
    }
  }
  return 0;
}
#endif /* 0 */
