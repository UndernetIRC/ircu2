/*
 * IRC - Internet Relay Chat, ircd/m_pseudo.c
 * Copyright (C) 2002 - 2003 Zoot <zoot@gamesurge.net>
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
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Hanel a pseudo-message (e.g. /X or /CHANSERV) from a connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is secretly a struct s_map *, passed as char *
 *   because there is no per-command-handler private data
 * \li \a parv[\a parc - 1] is the message to the service
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_pseudo(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *text, buffer[BUFSIZE];
  struct s_map *map;
  struct nick_host *nh;

  assert(0 != cptr);
  assert(cptr == sptr);
  assert(0 != cli_user(sptr));

  /* By default, relay the message straight through. */
  text = parv[parc - 1];

  if (parc < 3 || EmptyString(text))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  /* HACK! HACK! HACK! HACK! Yes. It's icky, but
   * it's the only way. */
  map = (struct s_map *)parv[1];
  assert(0 != map);

  if (map->prepend) {
    ircd_snprintf(0, buffer, sizeof(buffer) - 1, "%s%s", map->prepend, text);
    buffer[sizeof(buffer) - 1] = 0;
    text = buffer;
  }

  for (nh = map->services; nh; nh = nh->next) {
    struct Client *target, *server;

    if (NULL == (server = FindServer(nh->nick + nh->nicklen + 1)))
      continue;
    nh->nick[nh->nicklen] = '\0';
    if ((NULL == (target = FindUser(nh->nick)))
        || (server != cli_user(target)->server))
      continue;
    nh->nick[nh->nicklen] = '@';
    relay_directed_message(sptr, nh->nick, nh->nick + nh->nicklen, text);
    return 0;
  }

  return send_reply(sptr, ERR_SERVICESDOWN, map->name);
}
