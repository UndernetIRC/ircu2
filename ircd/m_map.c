/*
 * IRC - Internet Relay Chat, ircd/m_map.c
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
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "s_user.h"
#include "s_serv.h"
#include "send.h"
#include "querycmds.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void dump_map(struct Client *cptr, struct Client *server, char *mask, int prompt_length)
{
  static char prompt[64];
  struct DLink *lp;
  char *p = &prompt[prompt_length];
  int cnt = 0;

  *p = '\0';
  if (prompt_length > 60)
    send_reply(cptr, RPL_MAPMORE, prompt, cli_name(server));
  else {
    char lag[512];
    if (cli_serv(server)->lag>10000)
    	lag[0]=0;
    else if (cli_serv(server)->lag<0)
    	strcpy(lag,"(0s)");
    else
    	sprintf(lag,"(%is)",cli_serv(server)->lag);
    send_reply(cptr, RPL_MAP, prompt, (
    		(IsBurst(server)) ? "*" : (IsBurstAck(server) ? "!" : "")),
	       cli_name(server), lag, (server == &me) ? UserStats.local_clients :
	       cli_serv(server)->clients);
  }
  if (prompt_length > 0)
  {
    p[-1] = ' ';
    if (p[-2] == '`')
      p[-2] = ' ';
  }
  if (prompt_length > 60)
    return;
  strcpy(p, "|-");
  for (lp = cli_serv(server)->down; lp; lp = lp->next)
    if (match(mask, cli_name(lp->value.cptr)))
      ClrFlag(lp->value.cptr, FLAG_MAP);
    else
    {
      SetFlag(lp->value.cptr, FLAG_MAP);
      cnt++;
    }
  for (lp = cli_serv(server)->down; lp; lp = lp->next)
  {
    if (!HasFlag(lp->value.cptr, FLAG_MAP))
      continue;
    if (--cnt == 0)
      *p = '`';
    dump_map(cptr, lp->value.cptr, mask, prompt_length + 2);
  }
  if (prompt_length > 0)
    p[-1] = '-';
}


/*
 * m_map - generic message handler
 * -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = server mask
 */
int m_map(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (feature_bool(FEAT_HIS_MAP) && !IsAnOper(sptr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s %s", sptr,
		  "/MAP has been disabled, from CFV-165.  "
		  "Visit ", feature_str(FEAT_HIS_URLSERVERS));
    return 0;
  }
  if (parc < 2)
    parv[1] = "*";

  dump_map(sptr, &me, parv[1], 0);
  send_reply(sptr, RPL_MAPEND);

  return 0;
}
