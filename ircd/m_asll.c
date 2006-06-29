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

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "match.h"
#include "msg.h"
#include "send.h"
#include "s_bsd.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>

/** Send an AsLL report to \a to.
 * @param[in] from Client that originated the report.
 * @param[in] to Client receiving the report.
 * @param[in] server Server on other end of link being reported.
 * @param[in] rtt Round-trip time from \a from to \a server in milliseconds.
 * @param[in] up Estimated latency from \a from to \a server in milliseconds.
 * @param[in] down Estimated latency from \a server to \a from in milliseconds.
 * @return Zero.
 */
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

/** Handle an ASLL message from a server.
 *
 * In the "outbound" direction, \a parv has the following elements:
 * \li \a parv[1] is the mask of server(s) to report on.
 * \li \a parv[2] (optional) is the server to interrogate.
 *
 * In the "return" direction, \a parv has the following elements:
 * \li \a parv[1] is the user requesting the report.
 * \li \a parv[2] is the name of the server on the other end of the link.
 * \li \a parv[3] is round trip time.
 * \li \a parv[4] is estimated latency from \a cptr to \a parv[2].
 * \li \a parv[5] is estimated latency from \a parv[2] to \a cptr.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
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

/** Handle an ASLL message from an oper.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the mask of server(s) to report on.
 * \li \a parv[2] (optional) is the server to interrogate.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
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
