/*
 * IRC - Internet Relay Chat, ircd/m_jupe.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
#include "jupe.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * ms_jupe - server message handler
 *
 * parv[0] = Send prefix
 *
 * From server:
 *
 * parv[1] = Target: server numeric or *
 * parv[2] = (+|-)<server name>
 * parv[3] = Expiration offset
 * parv[4] = Last modification time
 * parv[5] = Comment
 *
 */
int ms_jupe(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr = 0;
  struct Jupe *ajupe;
  unsigned int flags = 0;
  time_t expire_off, lastmod;
  char *server = parv[2], *target = parv[1], *reason = parv[5];

  if (parc < 6)
    return need_more_params(sptr, "JUPE");

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!(acptr = FindNServer(target)))
      return 0; /* no such server */

    if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
      sendcmdto_one(sptr, CMD_JUPE, acptr, "%s %s %s %s :%s", target, server,
		    parv[3], parv[4], reason);
      return 0;
    }

    flags |= JUPE_LOCAL;
  }

  if (*server == '-')
    server++;
  else if (*server == '+') {
    flags |= JUPE_ACTIVE;
    server++;
  }

  expire_off = atoi(parv[3]);
  lastmod = atoi(parv[4]);

  ajupe = jupe_find(server);

  if (ajupe) {
    if (JupeIsLocal(ajupe) && !(flags & JUPE_LOCAL)) /* global over local */
      jupe_free(ajupe);
    else if (JupeLastMod(ajupe) < lastmod) { /* new modification */
      if (flags & JUPE_ACTIVE)
	return jupe_activate(cptr, sptr, ajupe, lastmod, flags);
      else
	return jupe_deactivate(cptr, sptr, ajupe, lastmod, flags);
    } else if (JupeLastMod(ajupe) == lastmod || IsBurstOrBurstAck(cptr))
      return 0;
    else
      return jupe_resend(cptr, ajupe); /* other server desynched WRT jupes */
  }

  return jupe_add(cptr, sptr, server, reason, expire_off, lastmod, flags);
}

/*
 * mo_jupe - oper message handler
 *
 * parv[0] = Send prefix
 * parv[1] = [[+|-]<server name>]
 *
 * Local (to me) style:
 *
 * parv[2] = [Expiration offset]
 * parv[3] = [Comment]
 *
 * Global (or remote local) style:
 *
 * parv[2] = [target]
 * parv[3] = [Expiration offset]
 * parv[4] = [Comment]
 *
 */
int mo_jupe(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr = 0;
  struct Jupe *ajupe;
  unsigned int flags = 0;
  time_t expire_off;
  char *server = parv[1], *target = 0, *reason;

  if (parc < 2)
    return jupe_list(sptr, 0);

  if (*server == '+') {
    flags |= JUPE_ACTIVE;
    server++;
  } else if (*server == '-')
    server++;
  else
    return jupe_list(sptr, server);

  if (!feature_bool(FEAT_CONFIG_OPERCMDS))
    return send_reply(sptr, ERR_DISABLED, "JUPE");

  if (parc == 4) {
    expire_off = atoi(parv[2]);
    reason = parv[3];
    flags |= JUPE_LOCAL;
  } else if (parc > 4) {
    target = parv[2];
    expire_off = atoi(parv[3]);
    reason = parv[4];
  } else
    return need_more_params(sptr, "JUPE");

  if (target) {
    if (!(target[0] == '*' && target[1] == '\0')) {
      if (!(acptr = find_match_server(target)))
	return send_reply(sptr, ERR_NOSUCHSERVER, target);

      if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
	if (!HasPriv(sptr, PRIV_GLINE))
	  return send_reply(sptr, ERR_NOPRIVILEGES);

	sendcmdto_one(sptr, CMD_JUPE, acptr, "%C %c%s %s %Tu :%s", acptr,
		      flags & JUPE_ACTIVE ? '+' : '-', server, parv[3],
		      TStime(), reason);
	return 0;
      } else if (!HasPriv(sptr, PRIV_LOCAL_GLINE))
	return send_reply(sptr, ERR_NOPRIVILEGES);

      flags |= JUPE_LOCAL;
    } else if (!HasPriv(sptr, PRIV_GLINE))
      return send_reply(sptr, ERR_NOPRIVILEGES);
  }

  ajupe = jupe_find(server);

  if (ajupe) {
    if (JupeIsLocal(ajupe) && !(flags & JUPE_LOCAL)) /* global over local */
      jupe_free(ajupe);
    else {
      if (flags & JUPE_ACTIVE)
	return jupe_activate(cptr, sptr, ajupe, TStime(), flags);
      else
	return jupe_deactivate(cptr, sptr, ajupe, TStime(), flags);
    }
  }

  return jupe_add(cptr, sptr, server, reason, expire_off, TStime(), flags);
}

/*
 * m_jupe - user message handler
 *
 * parv[0] = Send prefix
 *
 * From user:
 *
 * parv[1] = [<server name>]
 *
 */
int m_jupe(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (parc < 2)
    return jupe_list(sptr, 0);

  return jupe_list(sptr, parv[1]);
}
