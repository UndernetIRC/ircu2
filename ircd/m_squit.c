/*
 * IRC - Internet Relay Chat, ircd/m_squit.c
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
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "match.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Handle a SQUIT message from a server.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server's numnick
 * \li \a parv[2] is the server's link timestamp (or zero to force)
 * \li \a parv[\a parc - 1] is the squit message
 *
 * No longer supports wildcards from servers.
 * No longer squits a server that gave us an malformed squit message.
 *    - Isomer 1999-12-18
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_squit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char* server = parv[1];
  struct Client *acptr;
  time_t timestamp = 0;
  char *comment = 0;
  
  if (parc < 2) 
    return need_more_params(sptr, "SQUIT");

  comment = parv[parc-1];
  
  if (BadPtr(parv[parc - 1]))
  	comment = cli_name(sptr);
  	
  acptr = FindServer(server);

  if (!acptr)
    acptr = FindNServer(server);

  if (!acptr) {
    Debug((DEBUG_NOTICE, "Ignoring SQUIT to an unknown server"));
    return 0;
  }
  
  /* If they are squitting me, we reverse it */
  if (IsMe(acptr))
    acptr = cptr; /* Bugfix by Prefect */

  if (parc > 2)
    timestamp = atoi(parv[2]);
  else
    protocol_violation(cptr, "SQUIT with no timestamp/reason");

  /* If atoi(parv[2]) == 0 we must indeed squit !
   * It will be our neighbour.
   */
  if ( timestamp != 0 && timestamp != cli_serv(acptr)->timestamp)
  {
    Debug((DEBUG_NOTICE, "Ignoring SQUIT with the wrong timestamp"));
    return 0;
  }
  
  return exit_client(cptr, acptr, sptr, comment);
}

/** Handle a SQUIT message from an operator.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server's name (or wildcard mask)
 * \li \a parv[\a parc - 1] is the squit message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_squit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char* server;
  struct Client *acptr;
  struct Client *acptr2;
  char *comment;
      
  if (parc < 2) 
    return need_more_params(sptr, "SQUIT");

  if (parc < 3 || BadPtr(parv[2]))
    comment = cli_name(sptr);
  else
    comment = parv[2];

  server = parv[1];
  /*
   * The following allows wild cards in SQUIT. Only useful
   * when the command is issued by an oper.
   */
  for (acptr = GlobalClientList; (acptr = next_client(acptr, server));
      acptr = cli_next(acptr)) {
    if (IsServer(acptr) || IsMe(acptr))
      break;
  }
  
  /* Not found? Bugger. */
  if (!acptr || IsMe(acptr))
    return send_reply(sptr, ERR_NOSUCHSERVER, server);

  /*
   * Look for a matching server that is closer,
   * that way we won't accidentally squit two close
   * servers like davis.* and davis-r.* when typing
   * /SQUIT davis*
   */
  for (acptr2 = cli_serv(acptr)->up; acptr2 != &me;
      acptr2 = cli_serv(acptr2)->up)
    if (!match(server, cli_name(acptr2)))
      acptr = acptr2;
  
  /* Disallow local opers to squit remote servers */
  if (IsLocOp(sptr) && !MyConnect(acptr))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  return exit_client(cptr, acptr, sptr, comment);
}
