/*
 * IRC - Internet Relay Chat, ircd/m_motd.c
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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
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

/*
 * m_motd - generic message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * When NODEFAULTMOTD is defined, then it is possible that
 * sptr == NULL, which means that this function is called from
 * register_user.
 */
int m_motd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct tm *tm = &motd_tm;     /* Default: Most general case */
  struct TRecord *ptr;
  int count;
  struct MotdItem *temp;
  int class = get_client_class(sptr);

#ifdef NODEFAULTMOTD
  int no_motd;

  if (sptr)
  {
    no_motd = 0;
#endif
    if (hunt_server_cmd(sptr, CMD_MOTD, cptr, 0, "%C", 1, parc, parv) !=
	HUNTED_ISME)
      return 0;
#ifdef NODEFAULTMOTD
  }
  else
  {
    sptr = cptr;
    no_motd = 1;
  }
#endif
  /* 2.10.11: Allow per Class T:'s
   *    -- Isomer 2000-11-19
   */
  for (ptr = tdata; ptr; ptr = ptr->next)
  {
    if (IsDigit(*ptr->hostmask)) {
      if (atoi(ptr->hostmask)==class)
        break;
    }
    else if (!match(ptr->hostmask, cptr->sockhost))
      break;
  }
  if (ptr)
  {
    temp = ptr->tmotd;
    tm = &ptr->tmotd_tm;
  }
  else
    temp = motd;
  if (temp == 0)
  {
    send_reply(sptr, ERR_NOMOTD);
    return 0;
  }
#ifdef NODEFAULTMOTD
  if (!no_motd)
  {
#endif
    if (tm)                     /* Not remote? */
    {
      send_reply(sptr, RPL_MOTDSTART, me.name);
      send_reply(sptr, SND_EXPLICIT | RPL_MOTD, ":- %d/%d/%d %d:%02d",
		 tm->tm_mday, tm->tm_mon + 1, 1900 + tm->tm_year, tm->tm_hour,
		 tm->tm_min);
      count = 100;
    }
    else
      count = 3;
    for (; temp; temp = temp->next)
    {
      send_reply(sptr, RPL_MOTD, temp->line);
      if (--count == 0)
        break;
    }
#ifdef NODEFAULTMOTD
  }
  else
  {
    send_reply(sptr, RPL_MOTDSTART, me.name);
    send_reply(sptr, SND_EXPLICIT | RPL_MOTD, ":Type /MOTD to read the "
	       "AUP before continuing using this service.");
    send_reply(sptr, SND_EXPLICIT | RPL_MOTD, ":The message of the day was "
	       "last changed: %d/%d/%d", tm->tm_mday, tm->tm_mon + 1,
	       1900 + tm->tm_year);
  }
#endif
  send_reply(sptr, RPL_ENDOFMOTD);
  return 0;
}

/*
 * ms_motd - server message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * When NODEFAULTMOTD is defined, then it is possible that
 * sptr == NULL, which means that this function is called from
 * register_user.
 */
int ms_motd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct tm *tm = &motd_tm;     /* Default: Most general case */
  struct TRecord *ptr;
  int count;
  struct MotdItem *temp;

#ifdef NODEFAULTMOTD
  int no_motd;

  if (sptr)
  {
    no_motd = 0;
#endif
    if (hunt_server_cmd(sptr, CMD_MOTD, cptr, 0, "%C", 1, parc, parv) !=
	HUNTED_ISME)
      return 0;
#ifdef NODEFAULTMOTD
  }
  else
  {
    sptr = cptr;
    no_motd = 1;
  }
#endif

  /*
   * Find out if this is a remote query or if we have a T line for our hostname
   */
  if (IsServer(cptr))
  {
    tm = 0;                  /* Remote MOTD */
    temp = rmotd;
  }
  else
  {
    for (ptr = tdata; ptr; ptr = ptr->next)
    {
      if (!match(ptr->hostmask, cptr->sockhost))
        break;
    }
    if (ptr)
    {
      temp = ptr->tmotd;
      tm = &ptr->tmotd_tm;
    }
    else
      temp = motd;
  }
  if (temp == 0)
  {
    send_reply(sptr, ERR_NOMOTD);
    return 0;
  }
#ifdef NODEFAULTMOTD
  if (!no_motd)
  {
#endif
    if (tm)                     /* Not remote? */
    {
      send_reply(sptr, RPL_MOTDSTART, me.name);
      send_reply(sptr, SND_EXPLICIT | RPL_MOTD, ":- %d/%d/%d %d:%02d",
		 tm->tm_mday, tm->tm_mon + 1, 1900 + tm->tm_year, tm->tm_hour,
		 tm->tm_min);
      count = 100;
    }
    else
      count = 3;
    for (; temp; temp = temp->next)
    {
      send_reply(sptr, RPL_MOTD, temp->line);
      if (--count == 0)
        break;
    }
#ifdef NODEFAULTMOTD
  }
  else
  {
    send_reply(sptr, RPL_MOTDSTART, me.name);
    send_reply(sptr, SND_EXPLICIT | RPL_MOTD, ":Type /MOTD to read the "
	       "AUP before continuing using this service.");
    send_reply(sptr, SND_EXPLICIT | RPL_MOTD, ":The message of the day was "
	       "last changed: %d/%d/%d", tm->tm_mday, tm->tm_mon + 1,
	       1900 + tm->tm_year);
  }
#endif
  send_reply(sptr, RPL_ENDOFMOTD);
  return 0;
}

#if 0
/*
 * m_motd
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * When NODEFAULTMOTD is defined, then it is possible that
 * sptr == NULL, which means that this function is called from
 * register_user.
 */
int m_motd(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct tm *tm = &motd_tm;     /* Default: Most general case */
  struct TRecord *ptr;
  int count;
  struct MotdItem *temp;

#ifdef NODEFAULTMOTD
  int no_motd;

  if (sptr)
  {
    no_motd = 0;
#endif
    if (hunt_server(0, cptr, sptr, "%s%s " TOK_MOTD " %s", 1, parc, /* XXX DEAD */
        parv) != HUNTED_ISME)
      return 0;
#ifdef NODEFAULTMOTD
  }
  else
  {
    sptr = cptr;
    no_motd = 1;
  }
#endif

  /*
   * Find out if this is a remote query or if we have a T line for our hostname
   */
  if (IsServer(cptr))
  {
    tm = 0;                  /* Remote MOTD */
    temp = rmotd;
  }
  else
  {
    for (ptr = tdata; ptr; ptr = ptr->next)
    {
      if (!match(ptr->hostmask, cptr->sockhost))
        break;
    }
    if (ptr)
    {
      temp = ptr->tmotd;
      tm = &ptr->tmotd_tm;
    }
    else
      temp = motd;
  }
  if (temp == 0)
  {
    sendto_one(sptr, err_str(ERR_NOMOTD), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }
#ifdef NODEFAULTMOTD
  if (!no_motd)
  {
#endif
    if (tm)                     /* Not remote? */
    {
      sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, parv[0], me.name); /* XXX DEAD */
      sendto_one(sptr, ":%s %d %s :- %d/%d/%d %d:%02d", me.name, RPL_MOTD, /* XXX DEAD */
          parv[0], tm->tm_mday, tm->tm_mon + 1, 1900 + tm->tm_year,
          tm->tm_hour, tm->tm_min);
      count = 100;
    }
    else
      count = 3;
    for (; temp; temp = temp->next)
    {
      sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0], temp->line); /* XXX DEAD */
      if (--count == 0)
        break;
    }
#ifdef NODEFAULTMOTD
  }
  else
  {
    sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, parv[0], me.name); /* XXX DEAD */
    sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_MOTD, parv[0], /* XXX DEAD */
        "Type /MOTD to read the AUP before continuing using this service.");
    sendto_one(sptr, /* XXX DEAD */
        ":%s %d %s :The message of the day was last changed: %d/%d/%d", me.name,
        RPL_MOTD, parv[0], tm->tm_mday, tm->tm_mon + 1, 1900 + tm->tm_year);
  }
#endif
  sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, parv[0]); /* XXX DEAD */
  return 0;
}
#endif /* 0 */

