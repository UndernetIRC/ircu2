/*
 * IRC - Internet Relay Chat, ircd/m_userip.c
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

#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msgq.h"
#include "numeric.h"
#include "s_user.h"
#include "struct.h"

#include <assert.h>

static void userip_formatter(struct Client* cptr, struct MsgBuf* mb)
{
  assert(IsUser(cptr));
  msgq_append(0, mb, "%s%s=%c%s@%s", cli_name(cptr),
	      HasPriv(cptr, PRIV_DISPLAY) ? "*" : "",
	      cli_user(cptr)->away ? '-' : '+', cli_user(cptr)->username,
	      ircd_ntoa((const char*) &(cli_ip(cptr))));
}

/*
 * m_userip - generic message handler
 */
int m_userip(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 2)
    return need_more_params(sptr, "USERIP");
  send_user_info(sptr, parv[1], RPL_USERIP, userip_formatter); 
  return 0;
}


#if 0
/*
 * m_userip added by Carlo Wood 3/8/97.
 *
 * The same as USERHOST, but with the IP-number instead of the hostname.
 */
int m_userip(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *s;
  int i, j = 5;
  char *p = 0, *sbuf;
  struct Client *acptr;

  if (parc < 2)
    return need_more_params(sptr, "USERIP");

  sbuf = sprintf_irc(sendbuf, rpl_str(RPL_USERIP), me.name, parv[0]); /* XXX DEAD */
  for (i = j, s = ircd_strtok(&p, parv[1], " "); i && s;
      s = ircd_strtok(&p, (char *)0, " "), i--)
    if ((acptr = FindUser(s)))
    {
      if (i < j)
        *sbuf++ = ' ';
      sbuf = sprintf_irc(sbuf, "%s%s=%c%s@%s", acptr->name,
          IsAnOper(acptr) ? "*" : "", (acptr->user->away) ? '-' : '+',
          acptr->user->username, ircd_ntoa((const char*) &acptr->ip));
    }
    else
    {
      if (i < j)
        sendbufto_one(sptr); /* XXX DEAD */
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], s); /* XXX DEAD */
      sbuf = sprintf_irc(sendbuf, rpl_str(RPL_USERIP), me.name, parv[0]); /* XXX DEAD */
      j = i - 1;
    }
  if (i < j)
    sendbufto_one(sptr); /* XXX DEAD */
  return 0;
}
#endif /* 0 */

