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
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * ms_account - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = numeric of client to act on
 * parv[2] = message sub-type
 *
 * for parv[2] == 'R' (remote auth):
 * parv[3] = account name (12 characters or less)
 * parv[4] = account TS (optional)
 *
 * for parv[2] == 'C' (auth check):
 * parv[3] = request id (transparent, uninterpreted string)
 * parv[4] = username
 * parv[parc-1] = password
 *
 * for parv[2] == 'A' (auth ok) or
 * for parv[2] == 'D' (auth denied):
 * parv[3] = request id (transparent, uninterpreted string)
 */
int ms_account(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  struct Client *acptr;
  char type;

  if (parc < 3)
    return need_more_params(sptr, "ACCOUNT");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "ACCOUNT from non-server %s",
			      cli_name(sptr));

#if 1
  /* XXX HACK -- remove when all servers understand the new syntax */
  if (parc < 4) {
    /* old-school message, remap it to 'R' */
    parv[4] = NULL;
    parv[3] = parv[2];
    parv[2] = "R";
    parc = 4;
  } else if (parc == 4 && atoi(parv[3])) {
    /* old-school message with timestamp, remap it to 'R' */
    parv[5] = NULL;
    parv[4] = parv[3];
    parv[3] = parv[2];
    parv[2] = "R";
    parc = 5;
  }
#endif

  type = parv[2][0];
  if (type == 'R') {
    if (!(acptr = findNUser(parv[1])))
      return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

    if (IsAccount(acptr))
      return protocol_violation(cptr, "ACCOUNT for already registered user %s "
			        "(%s -> %s)", cli_name(acptr),
			        cli_user(acptr)->account, parv[3]);

    assert(0 == cli_user(acptr)->account[0]);

    if (strlen(parv[3]) > ACCOUNTLEN) {
      return protocol_violation(cptr, "Received account (%s) longer than %d for %s; ignoring.", parv[3], ACCOUNTLEN, cli_name(acptr));
    }

    if (parc > 4) {
      cli_user(acptr)->acc_create = atoi(parv[4]);
      Debug((DEBUG_DEBUG, "Received timestamped account: account \"%s\", "
	     "timestamp %Tu", parv[3], cli_user(acptr)->acc_create));
    }

    ircd_strncpy(cli_user(acptr)->account, parv[3], ACCOUNTLEN);
    hide_hostmask(acptr, FLAG_ACCOUNT);

#if 1
  /* remove when all servers understand the new syntax */
    sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr,
			  cli_user(acptr)->acc_create ? "%C %s %Tu" : "%C %s",
			  acptr, cli_user(acptr)->account,
			  cli_user(acptr)->acc_create);
#else
    sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr,
			  cli_user(acptr)->acc_create ? "%C R %s %Tu" : "%C R %s",
			  acptr, cli_user(acptr)->account,
			  cli_user(acptr)->acc_create);
#endif
  } else {
    if (type == 'C' && parc < 6)
      return need_more_params(sptr, "ACCOUNT");

    if (!(acptr = findNUser(parv[1])) && !(acptr = FindNServer(parv[1])))
      return 0; /* target not online, ignore */
    
    if (!IsMe(acptr)) {
      /* in-transit message, forward it */
      sendcmdto_one(sptr, CMD_ACCOUNT, acptr,
                   type == 'C' ? "%C %s %s %s :%s" : "%C %s %s",
                   acptr, parv[2], parv[3], parv[4], parv[parc-1]);
      return 0;
    }
    
    /* the message is for &me, process it */
    return protocol_violation(cptr, "ACCOUNT sub-type '%s' not implemented.", parv[2]);
  }

  return 0;
}
