/*
 * IRC - Internet Relay Chat, ircd/m_asll.c
 * Copyright (C) 2002 Alex Badea <vampire@p16.pub.ro>
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
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "match.h"
#include "msg.h"
#include "send.h"
#include "s_bsd.h"
#include "s_user.h"

#include <assert.h>
#include <stdlib.h>

static int send_asll_reply(struct Client *from, struct Client *to, char *server,
			   int rtt, int up, int down)
{
  sendcmdto_one(from, CMD_NOTICE, to,
    (up || down) ? "%C :AsLL for %s -- RTT: %ims Upstream: %ims Downstream: %ims" :
    rtt ? "%C :AsLL for %s -- RTT: %ims [no asymm info]" :
    "%C :AsLL for %s -- [unknown]",
    to, server, rtt, up, down);
  return 0;
}

/*
 * ms_asll - server message handler
 */
int ms_asll(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *mask;
  struct Client *acptr;
  int i;

  if (parc < 2)
    return need_more_params(sptr, "ASLL");

  if (parc > 5) {
    if (!(acptr = findNUser(parv[1])))
      return 0;
    if (MyUser(acptr))
      send_asll_reply(sptr, acptr, parv[2], atoi(parv[3]), atoi(parv[4]), atoi(parv[5]));
    else
      sendcmdto_prio_one(sptr, CMD_ASLL, acptr, "%C %s %s %s %s",
        acptr, parv[2], parv[3], parv[4], parv[5]);
    return 0;
  }

  if (hunt_server_prio_cmd(sptr, CMD_ASLL, cptr, 1, "%s %C", 2, parc, parv) != HUNTED_ISME)
    return 0;
  mask = parv[1];

  for (i = 0; i <= HighestFd; i++) {
    acptr = LocalClientArray[i];
    if (!acptr || !IsServer(acptr) || !MyConnect(acptr) || match(mask, cli_name(acptr)))
      continue;
    sendcmdto_prio_one(&me, CMD_ASLL, sptr, "%C %s %i %i %i", sptr,
      cli_name(acptr), cli_serv(acptr)->asll_rtt,
      cli_serv(acptr)->asll_to, cli_serv(acptr)->asll_from);
  }
  return 0;
}

/*
 * mo_asll - oper message handler
 */
int mo_asll(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *mask;
  struct Client *acptr;
  int i;

  if (parc < 2)
    return need_more_params(sptr, "ASLL");

  if (parc == 2 && MyUser(sptr))
    parv[parc++] = cli_name(&me);

  if (hunt_server_prio_cmd(sptr, CMD_ASLL, cptr, 1, "%s %C", 2, parc, parv) != HUNTED_ISME)
    return 0;
  mask = parv[1];

  for (i = 0; i <= HighestFd; i++) {
    acptr = LocalClientArray[i];
    if (!acptr || !IsServer(acptr) || !MyConnect(acptr) || match(mask, cli_name(acptr)))
      continue;
    send_asll_reply(&me, sptr, cli_name(acptr), cli_serv(acptr)->asll_rtt,
      cli_serv(acptr)->asll_to, cli_serv(acptr)->asll_from);
  }
  return 0;
}
