/*
 * IRC - Internet Relay Chat, ircd/m_unzombie.c
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

/** Handle an UNZOMBIE message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the numnick of the client attaching to the zombie
 * \li \a parv[2] is the numnick of the zombie
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_unzombie(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  struct Client *acptr;
  struct Client *victim;

  if (parc < 3)
    return need_more_params(sptr, "UNZOMBIE");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "UNZOMBIE from non-server %s",
			      cli_name(sptr));

  if (!(acptr = findNUser(parv[1])))
    return 0; /* If this is colliding with a QUIT, let the QUIT win */

  if (!(victim = findNUser(parv[2])))
    /* TODO send error */
    ;

  if (!IsNotConn(victim))
    return protocol_violation(cptr, "UNZOMBIE trying to attach to non-zombie %s",
			      cli_name(victim));
  assert(IsAccount(victim));

  unzombie_client(cptr, sptr, acptr, victim);
  return 0;
}
