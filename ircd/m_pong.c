/*
 * IRC - Internet Relay Chat, ircd/m_pong.c
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

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_auth.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdlib.h>

/** Handle a PONG message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the PONG responder
 * \li \a parv[2] is the PONG target (the PING originator)
 *
 * For AsLL pongs, the first two arguments are ignored and the
 * following arguments are used:
 * \li \a parv[3] is the original AsLL PING send timestamp
 * \li \a parv[4] is the "outbound" time for the PING to arrive
 * \li \a parv[5] is the AsLL PONG send timestamp
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_pong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*          origin;
  char*          destination;
  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if (parc < 2 || EmptyString(parv[1])) {
    return protocol_violation(sptr,"No Origin on PONG");
  }
  origin      = parv[1];
  destination = parv[2];
  ClearPingSent(cptr);
  ClearPingSent(sptr);
  cli_lasttime(cptr) = CurrentTime;

  if (parc > 5)
  {
    /* AsLL pong */
    cli_serv(cptr)->asll_rtt = atoi(militime_float(parv[3]));
    cli_serv(cptr)->asll_to = atoi(parv[4]);
    cli_serv(cptr)->asll_from = atoi(militime_float(parv[5]));
    cli_serv(cptr)->asll_last = CurrentTime;
    return 0;
  }
  
  if (EmptyString(destination))
    return 0;
  
  if (*destination == '!')
  {
    /* AsLL ping reply from a non-AsLL server */
    cli_serv(cptr)->asll_rtt = atoi(militime_float(destination + 1));
  }
  else if (0 != ircd_strcmp(destination, cli_name(&me)))
  {
    struct Client* acptr;
    if ((acptr = FindClient(destination)))
      sendcmdto_prio_one(sptr, CMD_PONG, acptr, "%s %s", origin, destination);
  }
  return 0;
}

/** Handle a PONG message from an unregistered connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the PING "cookie" used to deter TCP spoofing
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mr_pong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  assert(!IsRegistered(sptr));

  ClearPingSent(cptr);
  return (parc > 1) ? auth_set_pong(cli_auth(sptr), strtoul(parv[parc - 1], NULL, 10)) : 0;
}

/** Handle a PONG message from a normal connection.
 *
 * \a parv is ignored.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_pong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  ClearPingSent(cptr);
  cli_lasttime(cptr) = CurrentTime;
  return 0;
}
