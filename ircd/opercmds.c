/*
 * IRC - Internet Relay Chat, ircd/opercmds.c (formerly ircd/s_serv.c)
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
#include "opercmds.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "listener.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "send.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

/*
 * m_stats/stats_conf
 *
 * Report N/C-configuration lines from this server. This could
 * report other configuration lines too, but converting the
 * status back to "char" is a bit akward--not worth the code
 * it needs...
 *
 * Note: The info is reported in the order the server uses
 *       it--not reversed as in ircd.conf!
 */

static unsigned int report_array[17][3] = {
  {CONF_SERVER, RPL_STATSCLINE, 'C'},
  {CONF_CLIENT, RPL_STATSILINE, 'I'},
  {CONF_KILL, RPL_STATSKLINE, 'K'},
  {CONF_IPKILL, RPL_STATSKLINE, 'k'},
  {CONF_LEAF, RPL_STATSLLINE, 'L'},
  {CONF_OPERATOR, RPL_STATSOLINE, 'O'},
  {CONF_HUB, RPL_STATSHLINE, 'H'},
  {CONF_LOCOP, RPL_STATSOLINE, 'o'},
  {CONF_CRULEALL, RPL_STATSDLINE, 'D'},
  {CONF_CRULEAUTO, RPL_STATSDLINE, 'd'},
  {CONF_UWORLD, RPL_STATSULINE, 'U'},
  {CONF_TLINES, RPL_STATSTLINE, 'T'},
  {0, 0}
};

void report_configured_links(struct Client *sptr, int mask)
{
  static char null[] = "<NULL>";
  struct ConfItem *tmp;
  unsigned int *p;
  unsigned short int port;
  char c, *host, *pass, *name;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if ((tmp->status & mask))
    {
      for (p = &report_array[0][0]; *p; p += 3)
        if (*p == tmp->status)
          break;
      if (!*p)
        continue;
      c = (char)*(p + 2);
      host = BadPtr(tmp->host) ? null : tmp->host;
      pass = BadPtr(tmp->passwd) ? null : tmp->passwd;
      name = BadPtr(tmp->name) ? null : tmp->name;
      port = tmp->port;
      /*
       * On K line the passwd contents can be
       * displayed on STATS reply.    -Vesa
       */
      /* Special-case 'k' or 'K' lines as appropriate... -Kev */
      if ((tmp->status & CONF_KLINE))
        sendto_one(sptr, rpl_str(p[1]), me.name,
            sptr->name, c, host, pass, name, port, get_conf_class(tmp));
      /*
       * connect rules are classless
       */
      else if ((tmp->status & CONF_CRULE))
        sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, host, name);
      else if ((tmp->status & CONF_TLINES))
        sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, host, pass);
      else if ((tmp->status & CONF_UWORLD))
        sendto_one(sptr, rpl_str(p[1]),
            me.name, sptr->name, c, host, pass, name, port,
            get_conf_class(tmp));
      else if ((tmp->status & (CONF_SERVER | CONF_HUB)))
        sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, "*", name,
            port, get_conf_class(tmp));
      else
        sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, host, name,
            port, get_conf_class(tmp));
    }
  }
}

char *militime(char* sec, char* usec)
{
  struct timeval tv;
  static char timebuf[18];

  gettimeofday(&tv, NULL);
  if (sec && usec)
    sprintf(timebuf, "%ld",
        (tv.tv_sec - atoi(sec)) * 1000 + (tv.tv_usec - atoi(usec)) / 1000);
  else
    sprintf(timebuf, "%ld %ld", tv.tv_sec, tv.tv_usec);
  return timebuf;
}

