/*
 * IRC - Internet Relay Chat, ircd/m_privs.c
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
/** @file
 * @brief Report operators' privileges to others
 * @version $Id$
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/** Handle a local operator's privilege query.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int mo_privs(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *name;
  char *p = 0;
  int i;

  if (parc < 2)
    return client_report_privs(sptr, sptr);

  for (i = 1; i < parc; i++) {
    for (name = ircd_strtok(&p, parv[i], " "); name;
	 name = ircd_strtok(&p, 0, " ")) {
      if (!(acptr = FindUser(name)))
        send_reply(sptr, ERR_NOSUCHNICK, name);
      else if (MyUser(acptr))
	client_report_privs(sptr, acptr);
      else
        sendcmdto_one(cptr, CMD_PRIVS, acptr, "%s%s", NumNick(acptr));
    }
  }

  return 0;
}

/** Handle a remote user's privilege query.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int ms_privs(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *numnick, *p = 0;
  int i;

  if (parc < 2)
    return protocol_violation(cptr, "PRIVS with no arguments");

  for (i = 1; i < parc; i++) {
    for (numnick = ircd_strtok(&p, parv[i], " "); numnick;
	 numnick = ircd_strtok(&p, 0, " ")) {
      if (!(acptr = findNUser(numnick)))
        continue;
      else if (MyUser(acptr))
	client_report_privs(sptr, acptr);
      else
        sendcmdto_one(sptr, CMD_PRIVS, acptr, "%s%s", NumNick(acptr));
    }
  }

  return 0;
}
