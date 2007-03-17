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

/*
 * ms_gline - server message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = Target: server numeric
 * parv[2] = (+|-)<G-line mask>
 * parv[3] = G-line lifetime
 *
 * From Uworld:
 *
 * parv[4] = Comment
 *
 * From somewhere else:
 *
 * parv[4] = Last modification time
 * parv[5] = Comment
 *
 */
int
ms_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Gline *agline = 0;
  unsigned int flags = 0;
  enum GlineAction action = GLINE_MODIFY;
  time_t expire_off = 0, lastmod = 0, lifetime = 0;
  char *mask = parv[2], *target = parv[1], *reason = "No reason", *tmp = 0;

  if (parc < 3)
    return need_more_params(sptr, "GLINE");

  if (*mask == '!') {
    mask++;
    flags |= GLINE_OPERFORCE; /* assume oper had WIDE_GLINE */
  } else if (IsServer(sptr))
    flags |= GLINE_FORCE;

  switch (*mask) { /* handle +, -, <, and > */
  case '+': /* activate the G-line */
    action = GLINE_ACTIVATE;
    mask++;
    break;

  case '-': /* deactivate the G-line */
    action = GLINE_DEACTIVATE;
    mask++;
    break;

  case '>': /* locally activate the G-line */
    action = GLINE_LOCAL_ACTIVATE;
    mask++;
    break;

  case '<': /* locally deactivate the G-line */
    action = GLINE_LOCAL_DEACTIVATE;
    mask++;
    break;
  }

  /* Now, let's figure out if it's a local or global G-line */
  if (action == GLINE_LOCAL_ACTIVATE || action == GLINE_LOCAL_DEACTIVATE ||
      (target[0] == '*' && target[1] == '\0'))
    flags |= GLINE_GLOBAL;
  else {
    if (!(acptr = FindNServer(target)))
      return 0; /* no such server, jump out */

    flags |= GLINE_LOCAL;
  }

  /* Next, try to find the G-line... */
  if ((flags & GLINE_GLOBAL) || IsMe(acptr)) /* don't bother if it's not me! */
    agline = gline_find(mask, flags | GLINE_ANY | GLINE_EXACT);

  /* We now have all the pieces to tell us what we've got; let's
   * put it all together and convert the rest of the arguments.
   */

  /* Handle the local G-lines first... */
  if (flags & GLINE_LOCAL) {
    assert(acptr);

    /* normalize the action, first */
    if (action == GLINE_LOCAL_ACTIVATE || action == GLINE_MODIFY)
      action = GLINE_ACTIVATE;
    else if (action == GLINE_LOCAL_DEACTIVATE)
      action = GLINE_DEACTIVATE;

    if (action == GLINE_ACTIVATE) { /* get expiration and reason */
      if (parc < 5) /* check parameter count... */
	return need_more_params(sptr, "GLINE");

      expire_off = atoi(parv[3]); /* get expiration... */
      reason = parv[parc - 1]; /* and reason */

      if (IsMe(acptr)) {
	/* XXX and create the local G-line */
	sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
				"I would create a local G-line here; target "
				"%s, mask %s, operforce %s, action %s, "
				"expire %Tu, reason: %s", target, mask,
				flags & GLINE_OPERFORCE ? "YES" : "NO",
				action == GLINE_ACTIVATE ? "+" : "-",
				expire_off, reason);
      }
    } else if (IsMe(acptr)) { /* destroying a local G-line */
      /* XXX destroy the G-line */;
      sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
			      "I would destroy a local G-line here; target "
			      "%s, mask %s, operforce %s, action %s", target,
			      mask, flags & GLINE_OPERFORCE ? "YES" : "NO",
			      action == GLINE_ACTIVATE ? "+" : "-");
    }

    /* OK, we've converted arguments; if it's not for us, forward */
    /* UPDATE NOTE: Once all servers are updated to u2.10.12.11, the
     * format string in this sendcmdto_one() may be updated to omit
     * <lastmod> for GLINE_ACTIVATE and to omit <expire>, <lastmod>,
     * and <reason> for GLINE_DEACTIVATE.
     */
    if (!IsMe(acptr)) {
      sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
			      "I am forwarding a local G-line to a remote "
			      "server; target %s, mask %s, operforce %s, "
			      "action %s, expire %Tu, lastmod %Tu, reason: %s",
			      target, mask,
			      flags & GLINE_OPERFORCE ? "YES" : "NO",
			      action == GLINE_ACTIVATE ? "+" :  "-",
			      expire_off, CurrentTime, reason);
      sendcmdto_one(sptr, CMD_GLINE, acptr, "%C %s%c%s %Tu %Tu :%s",
		    acptr, flags & GLINE_OPERFORCE ? "!" : "",
		    action == GLINE_ACTIVATE ? '+' : '-', mask, expire_off,
		    CurrentTime, reason);
    }

    return 0; /* all done */
  }

  /* can't modify a G-line that doesn't exist, so remap to activate */
  if (!agline && action == GLINE_MODIFY)
    action = GLINE_ACTIVATE;

  /* OK, let's figure out what other parameters we may have... */
  switch (action) {
  case GLINE_LOCAL_ACTIVATE: /* locally activating a G-line */
  case GLINE_LOCAL_DEACTIVATE: /* locally deactivating a G-line */
    break; /* no additional parameters to manipulate */

  case GLINE_ACTIVATE: /* activating a G-line */
  case GLINE_DEACTIVATE: /* deactivating a G-line */
    /* in either of these cases, we have at least a lastmod parameter */
    if (parc < 4)
      return need_more_params(sptr, "GLINE");
    else if (parc == 4) /* lastmod only form... */
      lastmod = atoi(parv[3]);
    /*FALLTHROUGH*/
  case GLINE_MODIFY: /* modifying a G-line */
    /* convert expire and lastmod, look for lifetime and reason */
    if (parc > 4) { /* protect against fall-through from 4-param form */
      if (parc < 5)
	return need_more_params(sptr, "GLINE");

      expire_off = atoi(parv[3]); /* convert expiration and lastmod */
      lastmod = atoi(parv[4]);

      if (parc > 6) { /* no question, have a lifetime and reason */
	lifetime = atoi(parv[5]);
	reason = parv[parc - 1];
      } else if (parc == 6) { /* either a lifetime or a reason */
	if (!agline || /* gline creation, has to be the reason */
	    /* trial-convert as lifetime, and if it doesn't fully convert,
	     * it must be the reason */
	    ((lifetime = strtoul(parv[5], &tmp, 10)) && !*tmp)) {
	  lifetime = 0;
	  reason = parv[5];
	}
      }
    }
  }

  sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
			  "I have a global G-line I would act upon now; "
			  "target %s, mask %s, operforce %s, action %s, "
			  "expire %Tu, lastmod %Tu, lifetime %Tu, "
			  "reason: %s; gline %s!",
			  target, mask, flags & GLINE_OPERFORCE ? "YES" : "NO",
			  action == GLINE_ACTIVATE ? "+" :
			  (action == GLINE_DEACTIVATE ? "-" :
			   (action == GLINE_LOCAL_ACTIVATE ? ">" :
			    (action == GLINE_LOCAL_DEACTIVATE ? "<" :
			     "(MODIFY)"))), expire_off, lastmod, lifetime,
			  reason, agline ? "EXISTS" : "does not exist");

  /* OK, at this point, we have converted all available parameters.
   * Let's actually do the action!
   */
  if (agline)
    /* XXX modify the G-line */;

  /* XXX create the G-line */return 0;





/*   if ((parc == 3 && *mask == '-') || parc == 5) */
/*   { */
/*     if (!find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD)) */
/*       return need_more_params(sptr, "GLINE"); */

/*     flags |= GLINE_FORCE; */
/*   } */
/*   else if (parc > 5) */
/*     lastmod = atoi(parv[4]); */
/*   else */
/*     return need_more_params(sptr, "GLINE"); */

/*   if (parc > 4) */
/*     reason = parv[parc - 1]; */

/*   if (IsServer(sptr)) */
/*     flags |= GLINE_FORCE; */

/*   if (!(target[0] == '*' && target[1] == '\0')) { */
/*     if (!(acptr = FindNServer(target))) */
/*       return 0; /\* no such server *\/ */

/*     if (!IsMe(acptr)) { /\* manually propagate *\/ */
/*       if (!lastmod) */
/* 	sendcmdto_one(sptr, CMD_GLINE, acptr, */
/* 		      (parc == 3) ? "%C %s" : "%C %s %s :%s", acptr, mask, */
/* 		      parv[3], reason); */
/*       else */
/* 	sendcmdto_one(sptr, CMD_GLINE, acptr, "%C %s%s %s %s :%s", acptr, */
/* 		      flags & GLINE_OPERFORCE ? "!" : "", mask, parv[3], */
/* 		      parv[4], reason); */

/*       return 0; */
/*     } */

/*     flags |= GLINE_LOCAL; */
/*   } */

/*   if (*mask == '-') */
/*     mask++; */
/*   else if (*mask == '+') { */
/*     flags |= GLINE_ACTIVE; */
/*     mask++; */
/*   } else */
/*     flags |= GLINE_ACTIVE; */

/*   expire_off = parc < 5 ? 0 : atoi(parv[3]); */

/*   agline = gline_find(mask, GLINE_ANY | GLINE_EXACT); */

/*   if (agline) { */
/*     if (GlineIsLocal(agline) && !(flags & GLINE_LOCAL)) /\* global over local *\/ */
/*       gline_free(agline); */
/*     else if (!lastmod && ((flags & GLINE_ACTIVE) == GlineIsRemActive(agline))) */
/*       return gline_propagate(cptr, sptr, agline); */
/*     else if (!lastmod || GlineLastMod(agline) < lastmod) { /\* new mod *\/ */
/*       if (flags & GLINE_ACTIVE) */
/* 	return gline_activate(cptr, sptr, agline, lastmod, flags); */
/*       else */
/* 	return gline_deactivate(cptr, sptr, agline, lastmod, flags); */
/*     } else if (GlineLastMod(agline) == lastmod || IsBurstOrBurstAck(cptr)) */
/*       return 0; */
/*     else */
/*       return gline_resend(cptr, agline); /\* other server desynched WRT gline *\/ */
/*   } else if (parc == 3 && !(flags & GLINE_ACTIVE)) { */
/*     /\* U-lined server removing a G-line we don't have; propagate the removal */
/*      * anyway. */
/*      *\/ */
/*     if (!(flags & GLINE_LOCAL)) */
/*       sendcmdto_serv_butone(sptr, CMD_GLINE, cptr, "* -%s", mask); */
/*     return 0; */
/*   } else if (parc < 5) */
/*     return need_more_params(sptr, "GLINE"); */

/*   return gline_add(cptr, sptr, mask, reason, expire_off, lastmod, flags); */
}

/*
 * mo_gline - oper message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [[+|-]<G-line mask>]
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
    reason = parv[3];
    flags |= GLINE_LOCAL;
  } else if (parc > 4) {
    target = parv[2];
    expire_off = atoi(parv[3]);
    reason = parv[4];
  } else
    return need_more_params(sptr, "GLINE");

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

/*
 * m_gline - user message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [<server name>]
 *
 */
int
m_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return send_reply(sptr, ERR_NOSUCHGLINE, "");

  return gline_list(sptr, parv[1]);
}
