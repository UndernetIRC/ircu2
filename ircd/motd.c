/*
 * IRC - Internet Relay Chat, ircd/motd.c
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
#include "motd.h"
#include "client.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "class.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>
#include <assert.h>

/* This routine returns the TRecord structure for a user, or 0 if there
 * is no matching T-line--in which case, we should use the standard
 * MOTD.
 */
struct TRecord *
motd_find(struct Client* cptr)
{
  struct TRecord *ptr;
  int class = -1;

  assert(0 != cptr);

  if (MyUser(cptr))
    class = get_client_class(cptr);

  for (ptr = tdata; ptr; ptr = ptr->next) {
    if (class >= 0 && IsDigit(*ptr->hostmask)) {
      if (atoi(ptr->hostmask) == class)
	return ptr;
    } else if (!match(ptr->hostmask, cptr->sockhost))
      return ptr;
  }

  return 0;
}

/* This routine is used to send the MOTD off to a user. */
int
motd_send(struct Client* cptr, struct TRecord* trec)
{
  struct MotdItem *t_motd;
  struct tm *t_tm;
  int count;

  assert(0 != cptr);

  if (!MyUser(cptr)) { /* not our user, send the remote MOTD */
    t_motd = rmotd;
    t_tm = 0;
  } else if (trec) { /* We were given a TRecord */
    t_motd = trec->tmotd;
    t_tm = &trec->tmotd_tm;
  } else { /* use the basic MOTD */
    t_motd = motd;
    t_tm = &motd_tm;
  }

  if (!t_motd) /* No motd to send */
    return send_reply(cptr, ERR_NOMOTD);

  /* this is a change; we now always send the start numeric */
  send_reply(cptr, RPL_MOTDSTART, me.name);

  if (t_tm) { /* We should probably go for ISO dates here: yyyy-mm-dd. */
    send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":- %d/%d/%d %d:%02d",
	       t_tm->tm_mday, t_tm->tm_mon + 1, 1900 + t_tm->tm_year,
	       t_tm->tm_hour, t_tm->tm_min);
    count = 100;
  } else
    count = 3;

  for (; t_motd; t_motd = t_motd->next) { /* send along the MOTD */
    send_reply(cptr, RPL_MOTD, t_motd->line);
    if (!--count)
      break;
  }

  send_reply(cptr, RPL_ENDOFMOTD); /* end */

  return 0; /* Convenience return */
}

/* This routine sends the MOTD or something to newly-registered users. */
void
motd_signon(struct Client* cptr)
{
  struct TRecord *trec;
  struct tm *t_tm = &motd_tm;

  if ((trec = motd_find(cptr)))
    t_tm = &trec->tmotd_tm;

#ifdef NODEFAULTMOTD
  send_reply(cptr, RPL_MOTDSTART, me.name);
  send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":\002Type /MOTD to read the AUP "
	     "before continuing using this service.\002");
  /* Perhaps we should switch to an ISO date here? */
  send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":The message of the day was last "
	     "changed: %d/%d/%d", t_tm->tm_mday, t_tm->tm_mon + 1,
	     1900 + t_tm->tm_year);
  send_reply(cptr, RPL_ENDOFMOTD);
#else
  motd_send(cptr, trec);
#endif
}
