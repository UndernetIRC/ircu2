/*
 * IRC - Internet Relay Chat, ircd/m_settime.c
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
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <assert.h>
#include <stdlib.h>

/*
 * ms_settime - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = new time
 * parv[2] = server name (only used when sptr is an oper)
 */
int ms_settime(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  time_t t;
  long dt;
  static char tbuf[11];
  struct DLink *lp;

  if (parc < 2) /* verify argument count */
    return need_more_params(sptr, "SETTIME");

  t = atoi(parv[1]); /* convert time and compute delta */
  dt = TStime() - t;

  /* verify value */
  if (t < OLDEST_TS || dt < -9000000) {
    if (IsServer(sptr)) /* protocol violation if it's from a server */
      protocol_violation(sptr, "SETTIME: Bad value (%Tu, delta %l)", t, dt);
    else
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :SETTIME: Bad value (%Tu, "
		    "delta %l)", sptr, t, dt);
    return 0;
  }

  if (feature_bool(FEAT_RELIABLE_CLOCK)) { /* reset time */
    ircd_snprintf(0, tbuf, sizeof(tbuf), "%Tu", TStime());
    parv[1] = tbuf;
  }

  if (BadPtr(parv[2])) { /* spam the network */
    for (lp = cli_serv(&me)->down; lp; lp = lp->next)
      if (cptr != lp->value.cptr)
	sendcmdto_prio_one(sptr, CMD_SETTIME, lp->value.cptr, "%s", parv[1]);
  } else {
    if (hunt_server_prio_cmd(sptr, CMD_SETTIME, cptr, 1, "%s %C", 2, parc,
			     parv) != HUNTED_ISME) {
      /* If the destination was *not* me, but I'm RELIABLE_CLOCK and the
       * delta is more than 30 seconds off, bounce back a corrected
       * SETTIME
       */
      if (feature_bool(FEAT_RELIABLE_CLOCK) && (dt > 30 || dt < -30))
	sendcmdto_prio_one(&me, CMD_SETTIME, cptr, "%s %C", parv[1], cptr);
      return 0;
    }
  }

  if (feature_bool(FEAT_RELIABLE_CLOCK)) { /* don't apply settime--reliable */
    if (dt > 600 || dt < -600) /* If it was off more than 5 min, complain */
      sendcmdto_serv_butone(&me, CMD_DESYNCH, 0, ":Bad SETTIME from %s: %Tu "
			    "(delta %l)", cli_name(sptr), t, dt);
    if (IsUser(sptr)) /* Let user know we're ignoring him */
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is not set %ld seconds "
		    "%s: RELIABLE_CLOCK is defined", sptr, (dt < 0) ? -dt : dt,
		    (dt < 0) ? "forward" : "backward");
  } else { /* tell opers about time change */
    sendto_opmask_butone(0, SNO_OLDSNO, "SETTIME from %s, clock is set %ld "
			 "seconds %s", cli_name(sptr), (dt < 0) ? -dt : dt,
			 (dt < 0) ? "forward" : "backward");
    TSoffset -= dt; /* apply time change */
    if (IsUser(sptr)) /* let user know what we did */
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is set %ld seconds %s",
		    sptr, (dt < 0) ? -dt : dt,
		    (dt < 0) ? "forward" : "backward");
  }

  return 0;
}

/*
 * mo_settime - oper message handler
 *
 * parv[0] = sender prefix
 * parv[1] = new time
 * parv[2] = server name (only used when sptr is an oper)
 */
int mo_settime(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  time_t t;
  long dt = 0;
  static char tbuf[11];

  if (!IsOper(sptr)) /* Must be a global oper */
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 2) /* verify argument count */
    return need_more_params(sptr, "SETTIME");

  if (parc == 2 && MyUser(sptr)) /* default to me */
    parv[parc++] = cli_name(&me);

  t = atoi(parv[1]); /* convert the time */

  /* If we're reliable_clock or if the oper specified a 0 time, use current */
  if (!t || feature_bool(FEAT_RELIABLE_CLOCK)) {
    t = TStime();
    ircd_snprintf(0, tbuf, sizeof(tbuf), "%Tu", TStime());
    parv[1] = tbuf;
  }

  dt = TStime() - t; /* calculate the delta */

  /* verify value */
  if (t < OLDEST_TS || dt < -9000000) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :SETTIME: Bad value (%Tu, "
		  "delta %l)", sptr, t, dt);
    return 0;
  }

  /* OK, send the message off to its destination */
  if (hunt_server_prio_cmd(sptr, CMD_SETTIME, cptr, 1, "%s %C", 2, parc,
			   parv) != HUNTED_ISME)
    return 0;

  if (feature_bool(FEAT_RELIABLE_CLOCK)) { /* don't apply settime--reliable */
    if (dt > 600 || dt < -600) /* If it was off more than 5 min, complain */
      sendcmdto_serv_butone(&me, CMD_DESYNCH, 0, ":Bad SETTIME from %s: %Tu "
			    "(delta %l)", cli_name(sptr), t, dt);
    if (IsUser(sptr)) /* Let user know we're ignoring him */
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is not set %ld seconds "
		    "%s: RELIABLE_CLOCK is defined", sptr, (dt < 0) ? -dt : dt,
		    (dt < 0) ? "forward" : "backward");
  } else { /* tell opers about time change */
    sendto_opmask_butone(0, SNO_OLDSNO, "SETTIME from %s, clock is set %ld "
			 "seconds %s", cli_name(sptr), (dt < 0) ? -dt : dt,
			 (dt < 0) ? "forward" : "backward");
    TSoffset -= dt; /* apply time change */
    if (IsUser(sptr)) /* let user know what we did */
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is set %ld seconds %s",
		    sptr, (dt < 0) ? -dt : dt,
		    (dt < 0) ? "forward" : "backward");
  }

  return 0;
}
