/*
 * IRC - Internet Relay Chat, ircd/m_create.c
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
#include "ircd_reply.h"
#include "ircd_string.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_misc.h"

#include <string.h>

/** Handles WEBIRC from a pre-registration client on a WebIRC port.
 *
 * \a parv has the following elements:
 * \li parv[1] password
 * \li parv[2] ident
 * \li parv[3] hostname
 * \li parv[4] ip
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_webirc(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const struct wline *wline;
  const char *passwd;
  const char *hostname;
  const char *ip;

  if (!IsWebircPort(cptr))
    return exit_client(cptr, cptr, &me, "Use a different port");

  if (parc < 5)
    return need_more_params(sptr, "WEBIRC");

  passwd = parv[1];
  hostname = parv[3];
  ip = parv[4];

  if (EmptyString(ip))
    return exit_client(cptr, cptr, &me, "WEBIRC needs IP address");

  if (!(wline = find_webirc(&cli_ip(sptr), passwd)))
    return exit_client_msg(cptr, cptr, &me, "WEBIRC not authorized");
  cli_wline(sptr) = wline;

  /* Treat client as a normally connecting user from now on. */
  cli_status(sptr) = STAT_UNKNOWN_USER;

  int res = auth_spoof_user(cli_auth(cptr), NULL, hostname, ip);
  if (res > 0)
    return exit_client(cptr, cptr, &me, "WEBIRC invalid spoof");
  return res;
}
