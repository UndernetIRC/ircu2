/*
 * IRC - Internet Relay Chat, ircd/map.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2002 Joseph Bongaarts <foxxe@wtfs.net>
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
#include "ircd_defs.h"
#include "ircd_policy.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_alloc.h"
#include "hash.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "s_user.h"
#include "s_serv.h"
#include "send.h"
#include "querycmds.h"
#include "map.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef HEAD_IN_SAND_MAP

static struct Map *MapList = 0;

/* Add a server to the map list. */
static void map_add(struct Client *server)
{
/*  assert(server != 0);
  assert(!IsHub(server));
  assert(!IsService(server));
*/
  struct Map *map = (struct Map *)MyMalloc(sizeof(struct Map));

  map->lasttime = TStime();
  strcpy(map->name, cli_name(server));
  map->maxclients = cli_serv(server)->clients;

  map->prev = 0;
  map->next = MapList;

  if(MapList)
    MapList->prev = map;
  
  MapList = map;
}

/* Remove a server from the map list */
static void map_remove(struct Map *cptr)
{
  /*  assert(cptr != 0);*/
  
  if(cptr->next)
    cptr->next->prev = cptr->prev;
  
  if(cptr->prev)
    cptr->prev->next = cptr->next;
  
  if(MapList == cptr)
    MapList = cptr->next;

  MyFree(cptr);

}

/* Update a server in the list. Called when a server connects
 * splits, or we haven't checked in more than a week. */
void map_update(struct Client *cptr)
{
  /*  assert(IsServer(cptr)); */

  struct Map *map = 0;
  
  /* Find the server in the list and update it */ 
  for(map = MapList; map; map = map->next)
  {
    /* Show max clients not current, otherwise a split can be detected. */
    if(!ircd_strcmp(cli_name(cptr), map->name)) 
    { 
      map->lasttime = TStime();
      if(map->maxclients < cli_serv(cptr)->clients) 
	map->maxclients = cli_serv(cptr)->clients;  
      break;
    }
  }

  /* We do this check after finding a matching map because
   * a client server can become a hub or service (such as 
   * santaclara)
   */
  if(IsHub(cptr) || IsService(cptr))
  {
    if(map)
      map_remove(map);
    return;
  }

  /* If we haven't seen it before, add it to the list. */
  if(!map)
    map_add(cptr);
}

void map_dump_head_in_sand(struct Client *cptr)
{
  struct Map *map = 0;
  struct Map *smap = 0;
  struct Client *acptr = 0;

  /* Send me first */
  send_reply(cptr, RPL_MAP, "", "", cli_name(&me), "", UserStats.local_clients);

  for(map = MapList; map; map = smap)
  {
    smap = map->next;

    /* Don't show servers we haven't seen in more than a week */
    if(map->lasttime < TStime() - 604800)
    {
      acptr = FindServer(map->name);
      if(!acptr)
      {
	map_remove(map);
	continue;
      }
      else
	map_update(acptr);
    }
    send_reply(cptr, RPL_MAP, "", "|-", map->name, "", map->maxclients);
  }
}

#endif /* HEAD_IN_SAND_MAP */ 
  
void map_dump(struct Client *cptr, struct Client *server, char *mask, int prompt_length)
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
      cli_flags(lp->value.cptr) &= ~FLAGS_MAP;
    else
    {
      cli_flags(lp->value.cptr) |= FLAGS_MAP;
      cnt++;
    }
  for (lp = cli_serv(server)->down; lp; lp = lp->next)
  {
    if ((cli_flags(lp->value.cptr) & FLAGS_MAP) == 0)
      continue;
    if (--cnt == 0)
      *p = '`';
    map_dump(cptr, lp->value.cptr, mask, prompt_length + 2);
  }
  if (prompt_length > 0)
    p[-1] = '-';
}


