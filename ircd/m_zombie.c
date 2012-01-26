/*
 * IRC - Internet Relay Chat, ircd/m_zombie.c
 * Copyright (C) 2011 Jan Krueger <jk@jk.gs>
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
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>
#include <string.h>

/** Handle a ZOMBIE message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the numnick of the client to act on
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_zombie(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  struct Client *acptr;

  if (parc < 2)
    return need_more_params(sptr, "ZOMBIE");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "ZOMBIE from non-server %s",
			      cli_name(sptr));

  if (!(acptr = findNUser(parv[1])))
    return 0; /* Ignore for a user that QUIT; probably crossed (however unlikely) */

  if (!IsAccount(acptr))
    return protocol_violation(cptr, "ZOMBIE for user without account (%s)",
			      cli_name(acptr));

  zombie_client(cptr, sptr, acptr);
  return 0;
}
