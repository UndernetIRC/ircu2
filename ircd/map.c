/*
 * IRC - Internet Relay Chat, ircd/map.c
 * Copyright (C) 1994 Carlo Wood ( Run @ undernet.org )
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
#include "map.h"
#include "client.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "list.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "struct.h"

#include <stdio.h> /* sprintf */

void dump_map(struct Client *cptr, struct Client *server, char *mask, int prompt_length)
{
  static char prompt[64];
  struct DLink *lp;
  char *p = &prompt[prompt_length];
  int cnt = 0;

  *p = '\0';
  if (prompt_length > 60)
    send_reply(cptr, RPL_MAPMORE, prompt, server->name);
  else {
    char lag[512];
    if (server->serv->lag>10000)
    	strcpy(lag,"(--s)");
    else if (server->serv->lag<0)
    	strcpy(lag,"(0s)");
    else
    	sprintf(lag,"(%is)",server->serv->lag);
    send_reply(cptr, RPL_MAP, prompt, ((IsBurstOrBurstAck(server)) ? "*" : ""),
	       server->name, lag, (server == &me) ? UserStats.local_clients :
	       server->serv->clients);
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
  for (lp = server->serv->down; lp; lp = lp->next)
    if (match(mask, lp->value.cptr->name))
      lp->value.cptr->flags &= ~FLAGS_MAP;
    else
    {
      lp->value.cptr->flags |= FLAGS_MAP;
      cnt++;
    }
  for (lp = server->serv->down; lp; lp = lp->next)
  {
    if ((lp->value.cptr->flags & FLAGS_MAP) == 0)
      continue;
    if (--cnt == 0)
      *p = '`';
    dump_map(cptr, lp->value.cptr, mask, prompt_length + 2);
  }
  if (prompt_length > 0)
    p[-1] = '-';
}

#if 0
/*
 * m_map  -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = server mask
 */
int m_map(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    parv[1] = "*";

  dump_map(sptr, &me, parv[1], 0);
  sendto_one(sptr, rpl_str(RPL_MAPEND), me.name, parv[0]);

  return 0;
}
#endif /* 0 */

