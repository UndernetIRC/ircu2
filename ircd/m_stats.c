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

#include "s_stats.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * m_stats - generic message handler
 *
 *    parv[0] = sender prefix
 *    parv[1] = statistics selector
 *    parv[2] = target server (current server defaulted, if omitted)
 * And 'stats l' and 'stats' L:
 *    parv[3] = server mask ("*" default, if omitted)
 * Or for stats p,P:
 *    parv[3] = port mask (returns p-lines when its port is matched by this)
 * Or for stats k,K,i and I:
 *    parv[3] = [user@]host.name (returns which K/I-lines match this)
 *           or [user@]host.mask (returns which K/I-lines are mmatched by this)
 *              (defaults to old reply if omitted, when local or Oper)
 *              A remote mask (something containing wildcards) is only
 *              allowed for IRC Operators.
 */
int
m_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  unsigned char stat = parc > 1 ? parv[1][0] : '\0';
  struct StatDesc *sd;
  char *param = 0;

  /* If we didn't find a descriptor and this is my client, send them help */
  if (!(sd = statsmap[(int)stat])) {
    stat = '*';
    sd = statsmap[(int)stat];
  }

  assert(sd != 0);

  /* Check whether the client can issue this command.  If source is
   * not privileged (server or an operator), then the STAT_FLAG_OPERONLY
   * flag must not be set, and if the STAT_FLAG_OPERFEAT flag is set,
   * then the feature given by sd->sd_control must be off.
   */
  if (!IsPrivileged(cptr) &&
      ((sd->sd_flags & STAT_FLAG_OPERONLY) ||
       ((sd->sd_flags & STAT_FLAG_OPERFEAT) && feature_bool(sd->sd_control))))
    return send_reply(cptr, ERR_NOPRIVILEGES);

  /* Check for extra parameter */
  if ((sd->sd_flags & STAT_FLAG_VARPARAM) && parc > 3 && !EmptyString(parv[3]))
    param = parv[3];

  /* Ok, track down who's supposed to get this... */
  if (hunt_server_cmd(sptr, CMD_STATS, cptr, feature_int(FEAT_HIS_REMOTE),
		      param ? "%s %C :%s" : "%s :%C", 2, parc, parv) !=
      HUNTED_ISME)
    return 0; /* Someone else--cool :) */

  assert(sd->sd_func != 0);

  /* Ok, dispatch the stats function */
  (*sd->sd_func)(sptr, sd, stat, param);

  /* Done sending them the stats */
  return send_reply(sptr, RPL_ENDOFSTATS, stat);
}
