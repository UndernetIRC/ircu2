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
int client_get_ping(const struct Client* acptr)
{
  int     ping = 0;
  struct ConfItem* aconf;
  struct SLink*    link;

  for (link = con_confs(acptr); link; link = link->next) {
    aconf = link->value.aconf;
    if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
      int tmp = get_conf_ping(aconf);
      if (0 < tmp && (ping > tmp || !ping))
        ping = tmp;
    }
  }
  if (0 == ping)
    ping = PINGFREQUENCY;

  Debug((DEBUG_DEBUG, "Client %s Ping %d", cli_name(acptr), ping));
  return ping;
}
