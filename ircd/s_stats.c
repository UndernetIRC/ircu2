/*
 * IRC - Internet Relay Chat, ircd/s_stats.c
 * Copyright (C) 2000 Joseph Bongaarts
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

#include "s_stats.h"
#include "class.h"
#include "client.h"
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
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>


/*
 * m_stats/s_stats
 *
 * Report configuration lines and other statistics from this
 * server. 
 *
 * Note: The info is reported in the order the server uses
 *       it--not reversed as in ircd.conf!
 */

/*
 *  Help info displayed when user provides no stats parameter. --Gte
 */
const char *statsinfo[] = {
    "The following statistics are available:",
    "U - Service server & nick jupes information.",
    "u - Current uptime & highest connection count.",
    "p - Listening ports.",
    "i - Connection authorisation lines.",
    "y - Connection classes.",
    "c - Remote server connection lines.",
    "h - Hubs information.",
    "d - Dynamic routing configuration.", 
    "l - Current connections information.",
    "g - Global bans (G-lines).",
    "k - Local bans (K-Lines).",
    "o - Operator information.", 
    "m - Message usage information.",
    "t - Local connection statistics (Total SND/RCV, etc).", 
    "w - Userload statistics.",
    "v - Connection class information.",
    "M - Memory allocation & leak monitoring.", 
    "z - Memory/Structure allocation information.",
    "r - System resource usage (Debug only).", 
    "x - List usage information (Debug only).",
    0,
};

static unsigned int report_array[17][3] = {
  {CONF_SERVER, RPL_STATSCLINE, 'C'},
  {CONF_CLIENT, RPL_STATSILINE, 'I'},
  {CONF_LEAF, RPL_STATSLLINE, 'L'},
  {CONF_OPERATOR, RPL_STATSOLINE, 'O'},
  {CONF_HUB, RPL_STATSHLINE, 'H'},
  {CONF_LOCOP, RPL_STATSOLINE, 'o'},
  {CONF_UWORLD, RPL_STATSULINE, 'U'},
  {0, 0}
};

void report_configured_links(struct Client *sptr, int mask)
{
  static char null[] = "<NULL>";
  struct ConfItem *tmp;
  unsigned int *p;
  unsigned short int port;
  char c, *host, *pass, *name;
  

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) 
  {
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
      if ((tmp->status & CONF_UWORLD))
	send_reply(sptr, p[1], c, host, pass, name, port, get_conf_class(tmp));
      else if ((tmp->status & (CONF_SERVER | CONF_HUB)))
	send_reply(sptr, p[1], c, "*", name, port, get_conf_class(tmp));
      else
	send_reply(sptr, p[1], c, host, name, port, get_conf_class(tmp));
    }
  }
}

/*
 *  {CONF_TLINES, RPL_STATSTLINE, 'T'},
 */
void report_motd_list(struct Client* to)
{
  const struct MotdConf* conf = conf_get_motd_list();
  for ( ; conf; conf = conf->next)
    send_reply(to, RPL_STATSTLINE, 'T', conf->hostmask, conf->path);
}

/*
 * {CONF_CRULEALL, RPL_STATSDLINE, 'D'},
 * {CONF_CRULEAUTO, RPL_STATSDLINE, 'd'},
 */
void report_crule_list(struct Client* to, int mask)
{
  const struct CRuleConf* p = conf_get_crule_list();
  for ( ; p; p = p->next) {
    if (0 != (p->type & mask))
      send_reply(to, RPL_STATSDLINE, (CRULE_ALL == p->type) ? 'D' : 'd', p->hostmask, p->rule);
  }
}

/*
 * {CONF_KILL, RPL_STATSKLINE, 'K'},
 * {CONF_IPKILL, RPL_STATSKLINE, 'k'},
 */
void report_deny_list(struct Client* to)
{
  const struct DenyConf* p = conf_get_deny_list();
  for ( ; p; p = p->next)
    send_reply(to, RPL_STATSKLINE, (p->ip_kill) ? 'k' : 'K',
               p->hostmask, p->message, p->usermask);
}

/* m_stats is so obnoxiously full of special cases that the different
 * hunt_server() possiblites were becoming very messy. It now uses a
 * switch() so as to be easier to read and update as params change. 
 * -Ghostwolf 
 */
int hunt_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[], char stat)
{
  switch (stat)
  {
      /* open to all, standard # of params */
    case 'U':
    case 'u':
      return hunt_server_cmd(sptr, CMD_STATS, cptr, 0, "%s :%C", 2, parc,
			     parv);

    /* open to all, varying # of params */
    case 'k':
    case 'K':
    case 'i':
    case 'I':
    case 'p':
    case 'P':
    {
      if (parc > 3)
	return hunt_server_cmd(sptr, CMD_STATS, cptr, 0, "%s %C :%s", 2, parc, parv);
      else
	return hunt_server_cmd(sptr, CMD_STATS, cptr, 0, "%s :%C", 2, parc, parv);
    }

      /* oper only, varying # of params */
    case 'l':
    case 'L':
    case 'M':
    {
      if (parc == 4)
	return hunt_server_cmd(sptr, CMD_STATS, cptr, 1, "%s %C :%s", 2, parc, parv);
      else if (parc > 4)
	return hunt_server_cmd(sptr, CMD_STATS, cptr, 1, "%s %C %s :%s", 2, parc, parv);
      else 
	return hunt_server_cmd(sptr, CMD_STATS, cptr, 1, "%s :%C", 2, parc, parv);
    }

      /* oper only, standard # of params */
    default:
      return hunt_server_cmd(sptr, CMD_STATS, cptr, 1, "%s :%C", 2, parc, parv);
  }
}

