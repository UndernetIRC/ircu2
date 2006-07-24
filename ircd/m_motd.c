/*
 * IRC - Internet Relay Chat, ircd/m_motd.c
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
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "class.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>
/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a MOTD message from a local connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the server to query
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * Now using the motd_* family of functions defined in motd.c
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_motd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_MOTD, cptr, feature_int(FEAT_HIS_REMOTE), "%C", 1,
		      parc, parv) != HUNTED_ISME)
    return 0;

  return motd_send(sptr);
}

/** Handle a MOTD message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the server to query
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * Now using the motd_* family of functions defined in motd.c
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_motd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_MOTD, cptr, 0, "%C", 1, parc, parv) !=
      HUNTED_ISME)
    return 0;

  return motd_send(sptr);
}
