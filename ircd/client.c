/*
 * IRC - Internet Relay Chat, ircd/client.c
 * Copyright (C) 1990 Darren Reed
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
#include "client.h"
#include "class.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "list.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

#include <assert.h>

#define BAD_PING                ((unsigned int)-2)

/*
 * client_get_ping
 * returns shortest ping time in attached server or client conf
 * classes or PINGFREQUENCY
 */
unsigned int client_get_ping(const struct Client* acptr)
{
  unsigned int     ping = 0;
  unsigned int     tmp;
  struct ConfItem* aconf;
  struct SLink*    link;

  for (link = acptr->confs; link; link = link->next) {
    aconf = link->value.aconf;
    if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
      tmp = get_conf_ping(aconf);
      if ((tmp != BAD_PING) && ((ping > tmp) || !ping))
        ping = tmp;
    }
  }
  if (0 == ping)
    ping = PINGFREQUENCY;

  Debug((DEBUG_DEBUG, "Client %s Ping %d", acptr->name, ping));
  return (ping);
}

#if 0
#define BAD_CONF_CLASS          ((unsigned int)-1)
#define BAD_CLIENT_CLASS        ((unsigned int)-3)

unsigned int get_client_class(struct Client *acptr)
{
  struct SLink *tmp;
  struct ConnectionClass *cl;
  unsigned int retc = BAD_CLIENT_CLASS;

  if (acptr && !IsMe(acptr) && (acptr->confs))
    for (tmp = acptr->confs; tmp; tmp = tmp->next)
    {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->confClass))
        continue;
      if (ConClass(cl) > retc || retc == BAD_CLIENT_CLASS)
        retc = ConClass(cl);
    }

  Debug((DEBUG_DEBUG, "Returning Class %d For %s", retc, acptr->name));

  return (retc);
}

unsigned int get_sendq(struct Client *cptr)
{
  assert(0 != cptr);
  assert(0 != cptr->local);

  if (cptr->max_sendq)
    return cptr->max_sendq;

  else if (cptr->confs) {
    struct SLink*     tmp;
    struct ConnectionClass* cl;

    for (tmp = cptr->confs; tmp; tmp = tmp->next) {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->confClass))
        continue;
      if (ConClass(cl) != BAD_CLIENT_CLASS) {
        cptr->max_sendq = MaxSendq(cl);
        return cptr->max_sendq;
      }
    }
  }
  return DEFAULTMAXSENDQLENGTH;
}
#endif
