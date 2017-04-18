/*
 * IRC - Internet Relay Chat, ircd/m_stats.c
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
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Handle a STATS message from some connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the statistics selector
 * \li \a parv[2] (optional) is server to query
 * \li \a parv[3] (optional) is a mask to filter the results
 *
 * If \a parv[1] is "l" (or "links"), \a parv[3] is a mask of servers.
 * If \a parv[1] is "p" (or "P" or "ports"), \a parv[3] is a mask of
 * ports.  If \a parv[1] is "k" (or "K" or "klines" or "i" or "I" or
 * "access"), \a parv[3] is a hostname with optional username@ prefix
 * (for opers, hostmasks are allowed).
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int
m_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const struct StatDesc *sd;
  char *param;

  /* If we didn't find a descriptor, send them help */
  if ((parc < 2) || !(sd = stats_find(parv[1])))
      parv[1] = "*", sd = stats_find("*");

  assert(sd != 0);

  /* Check whether the client can issue this command.  If source is
   * not privileged (server or an operator), then the STAT_FLAG_OPERONLY
   * flag must not be set, and if the STAT_FLAG_OPERFEAT flag is set,
   * then the feature given by sd->sd_control must be off.
   *
   * This checks cptr rather than sptr so that a local oper may send
   * /stats queries to other servers.
   */
  if (!IsPrivileged(cptr) &&
      ((sd->sd_flags & STAT_FLAG_OPERONLY) ||
       ((sd->sd_flags & STAT_FLAG_OPERFEAT) && *sd->sd_control)))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  /* Check for extra parameter */
  if ((sd->sd_flags & STAT_FLAG_VARPARAM) && parc > 3 && !EmptyString(parv[3]))
    param = parv[3];
  else
    param = NULL;

  /* Ok, track down who's supposed to get this... */
  if (hunt_server_cmd(sptr, CMD_STATS, cptr, feature_int(FEAT_HIS_REMOTE),
		      param ? "%s %C :%s" : "%s :%C", 2, parc, parv) !=
      HUNTED_ISME)
    return 0; /* Someone else--cool :) */

  /* Check if they are a local user */
  if ((sd->sd_flags & STAT_FLAG_LOCONLY) && !MyUser(sptr))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  assert(sd->sd_func != 0);

  /* Ok, dispatch the stats function */
  (*sd->sd_func)(sptr, sd, param);

  /* Done sending them the stats */
  return send_reply(sptr, RPL_ENDOFSTATS, parv[1]);
}
