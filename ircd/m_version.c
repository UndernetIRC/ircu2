/*
 * IRC - Internet Relay Chat, ircd/m_version.c
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
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "version.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a VERSION message from a normal client.
 *
 * \a parv has the following elements:
 * \li \a parc[1] is the server to query (must be me)
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_version(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_VERSION, cptr, feature_int(FEAT_HIS_REMOTE),
                                                           ":%C", 1,
                                                           parc, parv)
                      == HUNTED_ISME)
  {
    send_reply(sptr, RPL_VERSION, version, debugmode, cli_name(&me),
	       debug_serveropts());
    if (MyUser(sptr))
      send_supported(sptr);
  }

  return 0;
}
