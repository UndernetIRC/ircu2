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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "jupe.h"
#include "hash.h"
#include "ircd.h"
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
  int local = 0, active = 1;
  time_t expire_off, lastmod;
  char *server = parv[2], *target = parv[1], *reason = parv[5];

  if (parc < 6)
    return need_more_params(sptr, "JUPE");

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!(acptr = FindNServer(target)))
      return 0; /* no such server */

    if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
      if (IsServer(sptr))
	sendto_one(acptr, "%s " TOK_JUPE " %s %s %s %s :%s", NumServ(sptr),
		   target, server, parv[3], parv[4], reason);
      else
	sendto_one(acptr, "%s%s " TOK_JUPE " %s %s %s %s :%s", NumNick(sptr),
		   target, server, parv[3], parv[4], reason);

      return 0;
    }

    local = 1;
  }

  if (*server == '-') {
    active = 0;
    server++;
  } else if (*server == '+') {
    active = 1;
    server++;
  }

  expire_off = atoi(parv[3]);
  lastmod = atoi(parv[4]);

  ajupe = jupe_find(server);

  if (ajupe) {
    if (JupeIsLocal(ajupe) && !local) /* global jupes override local ones */
      jupe_free(ajupe);
    else if (JupeLastMod(ajupe) < lastmod) { /* new modification */
      if (active)
	return jupe_activate(cptr, sptr, ajupe, lastmod);
      else
	return jupe_deactivate(cptr, sptr, ajupe, lastmod);
    } else if (JupeLastMod(ajupe) == lastmod) /* no changes */
      return 0;
    else
      return jupe_resend(cptr, ajupe); /* other server desynched WRT jupes */
  }

  return jupe_add(cptr, sptr, server, reason, expire_off, lastmod, local,
		  active);
}

/*
 * mo_jupe - oper message handler
 *
 * parv[0] = Send prefix
 *
 * From oper:
 *
 * parv[1] = [[+|-]<server name>]
 * parv[2] = [target]
 * parv[3] = [Expiration offset]
 * parv[4] = [Comment]
 *
 */
int mo_jupe(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr = 0;
  struct Jupe *ajupe;
  int local = 0, active = 1;
  time_t expire_off;
  char *server = parv[1], *target = parv[2], *reason = parv[4];

  if (parc < 2)
    return jupe_list(sptr, 0);

  if (*server == '+') {
    active = 1;
    server++;
  } else if (*server == '-') {
    active = 0;
    server++;
  } else
    return jupe_list(sptr, server);

  if (parc < 5)
    return need_more_params(sptr, "JUPE");

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!(acptr = find_match_server(target))) {
      sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], target);
      return 0;
    }

    if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
      if (!IsOper(sptr)) {
	sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
	return 0;
      }

      sendto_one(acptr, "%s%s " TOK_JUPE " %s %c%s %s " TIME_T_FMT " :%s",
		 NumNick(sptr), NumServ(acptr), active ? '+' : '-', server,
		 parv[3], TStime(), reason);
      return 0;
    }

    local = 1;
  } else if (!IsOper(sptr)) {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }

  expire_off = atoi(parv[3]);

  ajupe = jupe_find(server);

  if (ajupe) {
    if (JupeIsLocal(ajupe) && !local) /* global jupes override local ones */
      jupe_free(ajupe);
    else {
      if (active)
	return jupe_activate(cptr, sptr, ajupe, TStime());
      else
	return jupe_deactivate(cptr, sptr, ajupe, TStime());
    }
  }

  return jupe_add(cptr, sptr, server, reason, expire_off, TStime(), local,
		  active);
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
