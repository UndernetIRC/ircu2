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
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "s_misc.h"
#include "send.h"
#include "whowas.h"

#include <assert.h>
#include <stdlib.h>

/*
 * m_whowas - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname queried
 * parv[2] = maximum returned items (optional, default is unlimitted)
 * parv[3] = remote server target (Opers only, max returned items 20)
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
		   (IsAnOper(sptr) && temp->realhost) ? temp->realhost :
		   temp->hostname, temp->realname);
	  send_reply(sptr, RPL_WHOISSERVER, temp->name,
		     feature_bool(FEAT_HIS_WHOIS_SERVERNAME) && !IsOper(sptr) ?
		     feature_str(FEAT_HIS_SERVERNAME) : temp->servername,
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
