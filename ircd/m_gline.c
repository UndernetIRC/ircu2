/*
 * IRC - Internet Relay Chat, ircd/m_gline.c
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

#include "config.h"

#include "client.h"
#include "gline.h"
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

/** Handle a GLINE message from a server.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server numnick or "*" for all servers
 * \li \a parv[2] is the G-line mask (preceded by modifier flags)
 * \li \a parv[3] is the G-line lifetime in seconds
 * \li \a parv[4] (optional) is the G-line's last modification time
 * \li \a parv[\a parc - 1] is the G-line comment
 *
 * If the issuer is a server or there is no timestamp, the issuer must
 * be flagged as a UWorld server.  In this case, if the '-' modifier
 * flag is used, the G-line lifetime and all following arguments may
 * be omitted.
 *
 * Three modifier flags are recognized, and must be present in this
 * order:
 * \li '!' Indicates an G-line that an oper forcibly applied.
 * \li '-' Indicates that the following G-line should be removed.
 * \li '+' (exclusive of '-') indicates that the G-line should be
 *   activated.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int
ms_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Gline *agline;
  unsigned int flags = 0;
  time_t expire_off, lastmod = 0;
  char *mask = parv[2], *target = parv[1], *reason = "No reason";

  if (*mask == '!')
  {
    mask++;
    flags |= GLINE_OPERFORCE; /* assume oper had WIDE_GLINE */
  }

  if ((parc == 3 && *mask == '-') || parc == 5)
  {
    if (!cli_uworld(sptr))
      return need_more_params(sptr, "GLINE");

    flags |= GLINE_FORCE;
  }
  else if (parc > 5)
    lastmod = atoi(parv[4]);
  else
    return need_more_params(sptr, "GLINE");

  if (parc > 4)
    reason = parv[parc - 1];

  if (IsServer(sptr))
    flags |= GLINE_FORCE;

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!(acptr = FindNServer(target)))
      return 0; /* no such server */

    if (!IsMe(acptr)) { /* manually propagate */
      if (!lastmod)
	sendcmdto_one(sptr, CMD_GLINE, acptr,
		      (parc == 3) ? "%C %s" : "%C %s %s :%s", acptr, mask,
		      parv[3], reason);
      else
	sendcmdto_one(sptr, CMD_GLINE, acptr, "%C %s%s %s %s :%s", acptr,
		      flags & GLINE_OPERFORCE ? "!" : "", mask, parv[3],
		      parv[4], reason);

      return 0;
    }

    flags |= GLINE_LOCAL;
  }

  if (*mask == '-')
    mask++;
  else if (*mask == '+') {
    flags |= GLINE_ACTIVE;
    mask++;
  } else
    flags |= GLINE_ACTIVE;

  expire_off = parc < 5 ? 0 : atoi(parv[3]);

  agline = gline_find(mask, GLINE_ANY | GLINE_EXACT);

  if (agline) {
    if (GlineIsLocal(agline) && !(flags & GLINE_LOCAL)) /* global over local */
      gline_free(agline);
    else if (!lastmod && ((flags & GLINE_ACTIVE) == GlineIsRemActive(agline)))
      return gline_propagate(cptr, sptr, agline);
    else if (!lastmod || GlineLastMod(agline) < lastmod) { /* new mod */
      if (flags & GLINE_ACTIVE)
	return gline_activate(cptr, sptr, agline, lastmod, flags);
      else
	return gline_deactivate(cptr, sptr, agline, lastmod, flags);
    } else if (GlineLastMod(agline) == lastmod || IsBurstOrBurstAck(cptr))
      return 0;
    else
      return gline_resend(cptr, agline); /* other server desynched WRT gline */
  } else if (parc == 3 && !(flags & GLINE_ACTIVE)) {
    /* U-lined server removing a G-line we don't have; propagate the removal
     * anyway.
     */
    if (!(flags & GLINE_LOCAL))
      sendcmdto_serv(sptr, CMD_GLINE, cptr, "* -%s", mask);
    return 0;
  } else if (parc < 5)
    return need_more_params(sptr, "GLINE");

  return gline_add(cptr, sptr, mask, reason, expire_off, lastmod, flags);
}

/** Handle a GLINE message from an operator.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the G-line mask (preceded by modifier flags)
 * \li \a parv[2] (optional) is the target server numnick or '*'
 * \li \a parv[N+1] is the G-line lifetime in seconds
 * \li \a parv[\a parc - 1] is the G-line comment
 *
 * Three modifier flags are recognized, and must be present in this
 * order:
 * \li '!' Indicates an G-line that an oper forcibly applied.
 * \li '-' Indicates that the following G-line should be removed.
 * \li '+' (exclusive of '-') indicates that the G-line should be
 *   activated.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int
mo_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Gline *agline;
  unsigned int flags = 0;
  time_t expire_off;
  char *mask = parv[1], *target = 0, *reason;

  if (parc < 2)
    return gline_list(sptr, 0);

  if (*mask == '!') {
    mask++;

    if (HasPriv(sptr, PRIV_WIDE_GLINE))
      flags |= GLINE_OPERFORCE;
  }

  if (*mask == '+') {
    flags |= GLINE_ACTIVE;
    mask++;
  } else if (*mask == '-')
    mask++;
  else
    return gline_list(sptr, mask);

  if (parc == 4) {
    expire_off = atoi(parv[2]);
    flags |= GLINE_LOCAL;
  } else if (parc > 4) {
    target = parv[2];
    expire_off = atoi(parv[3]);
  } else
    return need_more_params(sptr, "GLINE");

  reason = parv[parc - 1];

  if (target)
  {
    if (!(target[0] == '*' && target[1] == '\0'))
    {
      if (!(acptr = find_match_server(target)))
	return send_reply(sptr, ERR_NOSUCHSERVER, target);

      /* manually propagate, since we don't set it */
      if (!IsMe(acptr))
      {
	if (!feature_bool(FEAT_CONFIG_OPERCMDS))
	  return send_reply(sptr, ERR_DISABLED, "GLINE");

	if (!HasPriv(sptr, PRIV_GLINE))
	  return send_reply(sptr, ERR_NOPRIVILEGES);

	sendcmdto_one(sptr, CMD_GLINE, acptr, "%C %s%c%s %s %Tu :%s", acptr,
		      flags & GLINE_OPERFORCE ? "!" : "",
		      flags & GLINE_ACTIVE ? '+' : '-', mask, parv[3],
		      TStime(), reason);
	return 0;
      }
      flags |= GLINE_LOCAL;
    }
  }

  if (!(flags & GLINE_LOCAL) && !feature_bool(FEAT_CONFIG_OPERCMDS))
    return send_reply(sptr, ERR_DISABLED, "GLINE");

  if (!HasPriv(sptr, (flags & GLINE_LOCAL ? PRIV_LOCAL_GLINE : PRIV_GLINE)))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  agline = gline_find(mask, GLINE_ANY | GLINE_EXACT);

  if (agline) {
    if (GlineIsLocal(agline) && !(flags & GLINE_LOCAL)) /* global over local */
      gline_free(agline);
    else {
      if (!GlineLastMod(agline)) /* force mods to Uworld-set G-lines local */
	flags |= GLINE_LOCAL;

      if (flags & GLINE_ACTIVE)
	return gline_activate(cptr, sptr, agline,
			      GlineLastMod(agline) ? TStime() : 0, flags);
      else
	return gline_deactivate(cptr, sptr, agline,
				GlineLastMod(agline) ? TStime() : 0, flags);
    }
  }

  return gline_add(cptr, sptr, mask, reason, expire_off, TStime(), flags);
}

/** Handle a GLINE message from a normal client.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target for which to show G-lines.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int
m_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return send_reply(sptr, ERR_NOSUCHGLINE, "");

  if (!feature_bool(FEAT_USER_GLIST))
    return send_reply(sptr, ERR_DISABLED, "GLINE");

  return gline_list(sptr, parv[1]);
}
