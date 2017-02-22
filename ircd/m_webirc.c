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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
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

/*
 * m_webirc
 *
 * parv[0] = sender prefix
 * parv[1] = password
 * parv[2] = ident
 * parv[3] = hostname
 * parv[4] = ip
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
