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

#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
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
 * parv[2] = servername (Only used when sptr is an Oper).
 */
int ms_settime(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  time_t t;
  long int dt;
  static char tbuf[11];
  struct DLink *lp;

  if (!IsPrivileged(sptr))
    return 0;

  if (parc < 2)
    return need_more_params(sptr, "SETTIME");

  if (parc == 2 && MyUser(sptr))
    parv[parc++] = cli_name(&me);

  t = atoi(parv[1]);
  dt = TStime() - t;

  if (t < OLDEST_TS || dt < -9000000)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :SETTIME: Bad value", sptr);
    return 0;
  }

  if (IsServer(sptr))           /* send to unlagged servers */
  {
    if (feature_bool(FEAT_RELIABLE_CLOCK)) {
      ircd_snprintf(0, tbuf, sizeof(tbuf), "%Tu", TStime());
      parv[1] = tbuf;
    }

    for (lp = cli_serv(&me)->down; lp; lp = lp->next)
      if (cptr != lp->value.cptr && MsgQLength(&(cli_sendQ(lp->value.cptr))) < 8000)
	sendcmdto_one(sptr, CMD_NOTICE, lp->value.cptr, "%s", parv[1]);
  }
  else
  {
    ircd_snprintf(0, tbuf, sizeof(tbuf), "%Tu", TStime());
    parv[1] = tbuf;
    if (hunt_server_cmd(sptr, CMD_SETTIME, cptr, 1, "%s %C", 2, parc, parv) !=
        HUNTED_ISME)
      return 0;
  }

  if (feature_bool(FEAT_RELIABLE_CLOCK)) {
    if ((dt > 600) || (dt < -600))
      sendcmdto_serv_butone(&me, CMD_WALLOPS, 0, ":Bad SETTIME from %s: %Tu",
			    cli_name(sptr), t);
    if (IsUser(sptr)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is not set %ld "
		    "seconds %s : RELIABLE_CLOCK is defined", sptr,
		    (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
    }
  } else {
    sendto_opmask_butone(0, SNO_OLDSNO, "SETTIME from %s, clock is set %ld "
			 "seconds %s", cli_name(sptr), (dt < 0) ? -dt : dt,
			 (dt < 0) ? "forwards" : "backwards");
    TSoffset -= dt;
    if (IsUser(sptr)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is set %ld seconds %s",
		    sptr, (dt < 0) ? -dt : dt,
		    (dt < 0) ? "forwards" : "backwards");
    }
  }

  return 0;
}

/*
 * mo_settime - oper message handler
 *
 * parv[0] = sender prefix
 * parv[1] = new time
 * parv[2] = servername (Only used when sptr is an Oper).
 */
int mo_settime(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  time_t t;
  long int dt;
  static char tbuf[11];
  struct DLink *lp;

  if (!IsPrivileged(sptr))
    return 0;

  if (parc < 2)
    return need_more_params(sptr, "SETTIME");

  if (parc == 2 && MyUser(sptr))
    parv[parc++] = cli_name(&me);

  t = atoi(parv[1]);
  dt = TStime() - t;

  if (t < OLDEST_TS || dt < -9000000)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :SETTIME: Bad value", sptr);
    return 0;
  }

  if (IsServer(sptr))           /* send to unlagged servers */
  {
    if (feature_bool(FEAT_RELIABLE_CLOCK)) {
      ircd_snprintf(0, tbuf, sizeof(tbuf), "%Tu", TStime());
      parv[1] = tbuf;
    }

    for (lp = cli_serv(&me)->down; lp; lp = lp->next)
      if (cptr != lp->value.cptr && MsgQLength(&(cli_sendQ(lp->value.cptr))) < 8000)
	sendcmdto_one(sptr, CMD_SETTIME, lp->value.cptr, "%s", parv[1]);
  }
  else
  {
    ircd_snprintf(0, tbuf, sizeof(tbuf), "%Tu", TStime());
    parv[1] = tbuf;
    if (hunt_server_cmd(sptr, CMD_SETTIME, cptr, 1, "%s %C", 2, parc, parv) !=
        HUNTED_ISME)
      return 0;
  }

  if (feature_bool(FEAT_RELIABLE_CLOCK)) {
    if ((dt > 600) || (dt < -600))
      sendcmdto_serv_butone(&me, CMD_WALLOPS, 0, ":Bad SETTIME from %s: %Tu",
			    cli_name(sptr), t);
    if (IsUser(sptr)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is not set %ld "
		    "seconds %s : RELIABLE_CLOCK is defined", sptr,
		    (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
    }
  } else {
    sendto_opmask_butone(0, SNO_OLDSNO, "SETTIME from %s, clock is set %ld "
			 "seconds %s", cli_name(sptr), (dt < 0) ? -dt : dt,
			 (dt < 0) ? "forwards" : "backwards");
    TSoffset -= dt;
    if (IsUser(sptr)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :clock is set %ld seconds %s",
		    sptr, (dt < 0) ? -dt : dt,
		    (dt < 0) ? "forwards" : "backwards");
    }
  }

  return 0;
}

  
#if 0
/*
 * m_settime
 *
 * parv[0] = sender prefix
 * parv[1] = new time
 * parv[2] = servername (Only used when sptr is an Oper).
 */
int m_settime(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  time_t t;
  long int dt;
  static char tbuf[11];
  struct DLink *lp;

  if (!IsPrivileged(sptr))
    return 0;

  if (parc < 2)
    return need_more_params(sptr, "SETTIME");

  if (parc == 2 && MyUser(sptr))
    parv[parc++] = me.name;

  t = atoi(parv[1]);
  dt = TStime() - t;

  if (t < OLDEST_TS || dt < -9000000)
  {
    sendto_one(sptr, ":%s NOTICE %s :SETTIME: Bad value", me.name, parv[0]); /* XXX DEAD */
    return 0;
  }

  if (IsServer(sptr))           /* send to unlagged servers */
  {
#ifdef RELIABLE_CLOCK
    sprintf_irc(tbuf, TIME_T_FMT, TStime());
    parv[1] = tbuf;
#endif
    for (lp = me.serv->down; lp; lp = lp->next)
      if (cptr != lp->value.cptr && DBufLength(&lp->value.cptr->sendQ) < 8000) /* XXX DEAD */
        sendto_one(lp->value.cptr, ":%s SETTIME %s", parv[0], parv[1]); /* XXX DEAD */
  }
  else
  {
    sprintf_irc(tbuf, TIME_T_FMT, TStime());
    parv[1] = tbuf;
    if (hunt_server(1, cptr, sptr, "%s%s " TOK_SETTIME " %s %s", 2, parc, parv) != /* XXX DEAD */
        HUNTED_ISME)
      return 0;
  }

#ifdef RELIABLE_CLOCK
  if ((dt > 600) || (dt < -600))
    sendto_serv_butone(0, ":%s " TOK_WALLOPS " :Bad SETTIME from %s: " TIME_T_FMT, /* XXX DEAD */
                       me.name, sptr->name, t);
  if (IsUser(sptr))
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :clock is not set %ld seconds %s : " /* XXX DEAD */
                 "RELIABLE_CLOCK is defined", me.name, parv[0],
                 (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
    else
      sendto_one(sptr, "%s NOTICE %s%s :clock is not set %ld seconds %s : " /* XXX DEAD */
                 "RELIABLE_CLOCK is defined", NumServ(&me), NumNick(sptr),
                 (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
  }
#else
  sendto_ops("SETTIME from %s, clock is set %ld seconds %s", /* XXX DEAD */
             sptr->name, (dt < 0) ? -dt : dt,
             (dt < 0) ? "forwards" : "backwards");
  TSoffset -= dt;
  if (IsUser(sptr))
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :clock is set %ld seconds %s", me.name, /* XXX DEAD */
                 parv[0], (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
    else
      sendto_one(sptr, "%s NOTICE %s%s :clock is set %ld seconds %s", /* XXX DEAD */
                 NumServ(&me), NumNick(sptr),
                 (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
  }
#endif
  return 0;
}
#endif /* 0 */
