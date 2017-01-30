/*
 * IRC - Internet Relay Chat, ircd/m_whowas.c
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
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "s_misc.h"
#include "send.h"
#include "whowas.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>

/** Handle a WHOWAS message from some connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the nickname to look for
 * \li \a parv[2] (optional) is the maximum number of results to show
 * \li \a parv[3] (optional; opers only) is the name of a server to
 * ask, or numnick if the message comes from a server
 *
 * For local queries, the default result limit is unlimited.  For
 * remote queries, the default result limit is 20.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_whowas(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Whowas *temp;
  int cur = 0;
  int max = -1, found = 0;
  char *p, *nick, *s;

  if (parc < 2)
  {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }
  if (parc > 2)
    max = atoi(parv[2]);
  if (parc > 3)
    if (hunt_server_cmd(sptr, CMD_WHOWAS, cptr, 1, "%s %s :%C", 3, parc, parv))
      return 0;

  parv[1] = canonize(parv[1]);
  if (!MyConnect(sptr) && (max > 20))
    max = 20;                   /* Set max replies at 20 */
  for (s = parv[1]; (nick = ircd_strtok(&p, s, ",")); s = 0)
  {
    /* Search through bucket, finding all nicknames that match */
    found = 0;
    for (temp = whowashash[hash_whowas_name(nick)]; temp; temp = temp->hnext)
    {
      if (0 == ircd_strcmp(nick, temp->name))
      {
	send_reply(sptr, RPL_WHOWASUSER, temp->name, temp->username,
		   temp->hostname, temp->realname);
        if (IsAnOper(sptr) && temp->realhost)
          send_reply(sptr, RPL_WHOISACTUALLY, temp->name, temp->username, temp->realhost, "<untracked>");
        send_reply(sptr, RPL_WHOISSERVER, temp->name,
                   (feature_bool(FEAT_HIS_WHOIS_SERVERNAME) && !IsOper(sptr)) ?
                     feature_str(FEAT_HIS_SERVERNAME) :
                     temp->servername,
		   myctime(temp->logoff));
        if (temp->away)
	  send_reply(sptr, RPL_AWAY, temp->name, temp->away);
        cur++;
        found++;
      }
      if (max >= 0 && cur >= max)
        break;
    }
    if (!found)
      send_reply(sptr, ERR_WASNOSUCHNICK, nick);
    /* To keep parv[1] intact for ENDOFWHOWAS */
    if (p)
      p[-1] = ',';
  }
  send_reply(sptr, RPL_ENDOFWHOWAS, parv[1]);
  return 0;
}
