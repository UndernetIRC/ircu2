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
 */

#include "sys.h"
#include "h.h"
#include "struct.h"
#include "numeric.h"
#include "send.h"
#include "match.h"
#include "list.h"
#include "s_err.h"
#include "ircd.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "map.h"

RCSTAG_CC("$Id$");

static void dump_map(aClient *cptr, aClient *server, char *mask,
    int prompt_length)
{
  static char prompt[64];
  register Dlink *lp;
  register char *p = &prompt[prompt_length];
  register int cnt = 0;

  *p = '\0';
  if (prompt_length > 60)
    sendto_one(cptr, rpl_str(RPL_MAPMORE), me.name, cptr->name,
	prompt, server->name);
  else
    sendto_one(cptr, rpl_str(RPL_MAP), me.name, cptr->name,
	prompt, server->name);
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

/*
 * m_map  -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = server mask
 */
int m_map(aClient *UNUSED(cptr), aClient *sptr, int parc, char *parv[])
{
  if (parc < 2)
    parv[1] = "*";

  dump_map(sptr, &me, parv[1], 0);
  sendto_one(sptr, rpl_str(RPL_MAPEND), me.name, parv[0]);

  return 0;
}
