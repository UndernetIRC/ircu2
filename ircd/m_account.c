/*
 * IRC - Internet Relay Chat, ircd/m_account.c
 * Copyright (C) 2002 Kevin L. Mitchell <klmitch@mit.edu>
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
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Handle an ACCOUNT message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the numnick of the client to act on
 * \li \a parv[2] is the account name
 * \li \a parv[3] (optional) is the account timestamp
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_account(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  struct Client *acptr;

  if (parc < 3)
    return need_more_params(sptr, "ACCOUNT");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "ACCOUNT from non-server %s",
			      cli_name(sptr));

  if (!(acptr = findNUser(parv[1])))
    return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

  if (IsAccount(acptr))
    return protocol_violation(cptr, "ACCOUNT for already registered user %s "
			      "(%s -> %s)", cli_name(acptr),
			      cli_user(acptr)->account, parv[2]);

  assert(0 == cli_user(acptr)->account[0]);

  if (strlen(parv[2]) > ACCOUNTLEN)
    return protocol_violation(cptr,
                              "Received account (%s) longer than %d for %s; "
                              "ignoring.",
                              parv[2], ACCOUNTLEN, cli_name(acptr));

  if (parc > 3) {
    cli_user(acptr)->acc_create = atoi(parv[3]);
    Debug((DEBUG_DEBUG, "Received timestamped account: account \"%s\", "
           "timestamp %Tu", parv[2], cli_user(acptr)->acc_create));
  }

  ircd_strncpy(cli_user(acptr)->account, parv[2], ACCOUNTLEN);
  hide_hostmask(acptr, FLAG_ACCOUNT);

  sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr,
                        cli_user(acptr)->acc_create ? "%C %s %Tu" : "%C %s",
                        acptr, cli_user(acptr)->account,
                        cli_user(acptr)->acc_create);

  return 0;
}
