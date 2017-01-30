/*
 * IRC - Internet Relay Chat, ircd/m_admin.c
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
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Send local administrative information to \a sptr.
 * @param[in] sptr Client who wants admin information.
 * @return Zero.
 */
static int send_admin_info(struct Client* sptr)
{
  const struct LocalConf* admin = conf_get_local();
  assert(0 != sptr);

  send_reply(sptr, RPL_ADMINME,    cli_name(&me));
  send_reply(sptr, RPL_ADMINLOC1,  admin->location1);
  send_reply(sptr, RPL_ADMINLOC2,  admin->location2);
  send_reply(sptr, RPL_ADMINEMAIL, admin->contact);
  return 0;
}


/** Handle an ADMIN message from a local client connection.
 * This version will only work on the local server.
 *
 * \a parv has the following elements:
 * \li \a parv[1] (optional) is the server name being interrogated.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_admin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc > 1  && match(parv[1], cli_name(&me)))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  return send_admin_info(sptr);
}

/** Handle an ADMIN message from an oper's connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] (optional) is the server name being interrogated.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_admin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (hunt_server_cmd(sptr, CMD_ADMIN, cptr, feature_int(FEAT_HIS_REMOTE), 
                      ":%C", 1, parc, parv) != HUNTED_ISME)
    return 0;
  return send_admin_info(sptr);
}

/** Handle an ADMIN message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the server name being interrogated.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_admin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(0 != sptr);

  if (parc < 2)
    return 0;

  if (hunt_server_cmd(sptr, CMD_ADMIN, cptr, 0, ":%C", 1, parc, parv) != HUNTED_ISME)
    return 0;

  return send_admin_info(sptr);
}

