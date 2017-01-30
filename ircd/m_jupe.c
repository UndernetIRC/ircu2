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
 */

#include "config.h"

#include "client.h"
#include "jupe.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Handle a JUPE message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server's numnick (or "*" for all servers)
 * \li \a parv[2] is the server name to jupe, optionally with '+' or '-' prefix
 * \li \a parv[3] is the jupe's duration in seconds
 * \li \a parv[4] is the last modification time of the jupe
 * \li \a parv[\a parc - 1] is the comment or explanation of the jupe
 *
 * The default is to deactivate the jupe; activating or adding a jupe
 * requires the '+' prefix to \a parv[2].
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_jupe(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr = 0;
  struct Jupe *ajupe;
  unsigned int flags = 0;
  time_t expire_off, lastmod;
  char *server = parv[2], *target = parv[1], *reason = parv[parc - 1];

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

/** Handle a JUP message from an operator.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server's numnick (or "*" for all servers)
 * \li \a parv[2] (optional) is the server name to jupe with '+' or '-' prefix
 * \li \a parv[N+1] is the jupe's duration in seconds
 * \li \a parv[N+2] is the last modification time of the jupe
 * \li \a parv[\a parc - 1] is the comment or explanation of the jupe
 *
 * Unlike GLINE and server-to-server JUPE, the '+' or '-' prefix
 * before the target is REQUIRED.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
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
    flags |= JUPE_LOCAL;
  } else if (parc > 4) {
    target = parv[2];
    expire_off = atoi(parv[3]);
  } else
    return need_more_params(sptr, "JUPE");

  reason = parv[parc - 1];

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

