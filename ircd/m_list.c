/*
 * IRC - Internet Relay Chat, ircd/m_list.c
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

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define LPARAM_ERROR	-1
#define LPARAM_SUCCESS	 0
#define LPARAM_CHANNEL	 1

static struct ListingArgs la_init = {
  2147483647,                 /* max_time */
  0,                          /* min_time */
  4294967295U,                /* max_users */
  0,                          /* min_users */
  0,                          /* topic_limits */
  2147483647,                 /* max_topic_time */
  0,                          /* min_topic_time */
  0                           /* chptr */
};

static struct ListingArgs la_default = {
  2147483647,                 /* max_time */
  0,                          /* min_time */
  4294967295U,                /* max_users */
  0,                          /* min_users */
  0,                          /* topic_limits */
  2147483647,                 /* max_topic_time */
  0,                          /* min_topic_time */
  0                           /* chptr */
};

static int
show_usage(struct Client *sptr)
{
  if (!sptr) { /* configuration file error... */
    log_write(LS_CONFIG, L_ERROR, 0, "Invalid default list parameter");
    return LPARAM_ERROR;
  }

  send_reply(sptr, RPL_LISTUSAGE,
	     "Usage: \002/QUOTE LIST\002 \037parameters\037");
  send_reply(sptr, RPL_LISTUSAGE,
	     "Where \037parameters\037 is a space or comma seperated "
	     "list of one or more of:");
  send_reply(sptr, RPL_LISTUSAGE,
	     " \002<\002\037max_users\037    ; Show all channels with less "
	     "than \037max_users\037.");
  send_reply(sptr, RPL_LISTUSAGE,
	     " \002>\002\037min_users\037    ; Show all channels with more "
	     "than \037min_users\037.");
  send_reply(sptr, RPL_LISTUSAGE,
	     " \002C<\002\037max_minutes\037 ; Channels that exist less "
	     "than \037max_minutes\037.");
  send_reply(sptr, RPL_LISTUSAGE,
	     " \002C>\002\037min_minutes\037 ; Channels that exist more "
	     "than \037min_minutes\037.");
  send_reply(sptr, RPL_LISTUSAGE,
	     " \002T<\002\037max_minutes\037 ; Channels with a topic last "
	     "set less than \037max_minutes\037 ago.");
  send_reply(sptr, RPL_LISTUSAGE,
	     " \002T>\002\037min_minutes\037 ; Channels with a topic last "
	     "set more than \037min_minutes\037 ago.");
  send_reply(sptr, RPL_LISTUSAGE,
	     "Example: LIST <3,>1,C<10,T>0  ; 2 users, younger than 10 "
	     "min., topic set.");

  return LPARAM_ERROR; /* return error condition */
}

static int
param_parse(struct Client *sptr, const char *param, struct ListingArgs *args,
	    int permit_chan)
{
  int is_time = 0;
  char dir;
  unsigned int val;

  assert(0 != args);

  if (!param) /* NULL param == default--no list param */
    return LPARAM_SUCCESS;

  while (1) {
    switch (*param) {
    case 'T':
    case 't':
      is_time++;
      args->topic_limits = 1;
      /*FALLTHROUGH*/

    case 'C':
    case 'c':
      is_time++;
      param++;
      if (*param != '<' && *param != '>')
	return show_usage(sptr);
      /*FALLTHROUGH*/

    case '<':
    case '>':
      dir = *(param++);

      if (!IsDigit(*param)) /* must start with a digit */
	return show_usage(sptr);

      val = strtol(param, (char **)&param, 10); /* convert it... */

      if (*param != ',' && *param != ' ' && *param != '\0') /* check syntax */
	return show_usage(sptr);

      if (is_time && val < 80000000) /* Toggle UTC/offset */
	val = TStime() - val * 60;
      
      switch (is_time) {
      case 0: /* number of users on channel */
	if (dir == '<')
	  args->max_users = val;
	else
	  args->min_users = val;
	break;

      case 1: /* channel topic */
	if (dir == '<')
	  args->min_topic_time = val;
	else
	  args->max_topic_time = val;
	break;

      case 2: /* channel creation time */
	if (dir == '<')
	  args->min_time = val;
	else
	  args->max_time = val;
	break;
      }
      break;

    default: /* channel name? */
      if (!permit_chan || !IsChannelName(param))
	return show_usage(sptr);

      return LPARAM_CHANNEL;
      break;
    }

    if (!*param) /* hit end of string? */
      break;

    param++;
  }

  return LPARAM_SUCCESS;
}

void
list_set_default(void)
{
  la_default = la_init; /* start off with a clean slate... */

  if (param_parse(0, feature_str(FEAT_DEFAULT_LIST_PARAM), &la_default, 0) !=
      LPARAM_SUCCESS)
    la_default = la_init; /* recover from error by switching to default */
}

/*
 * m_list - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel list or user/time limit
 * parv[2...] = more user/time limits
 */
int m_list(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char *name, *p = 0;
  int show_channels = 0, param;
  struct ListingArgs args;

  if (cli_listing(sptr))            /* Already listing ? */
  {
    cli_listing(sptr)->chptr->mode.mode &= ~MODE_LISTED;
    MyFree(cli_listing(sptr));
    cli_listing(sptr) = 0;
    send_reply(sptr, RPL_LISTEND);
    update_write(sptr);
    if (parc < 2 || 0 == ircd_strcmp("STOP", parv[1]))
      return 0;                 /* Let LIST or LIST STOP abort a listing. */
  }

  if (parc < 2)                 /* No arguments given to /LIST ? */
    args = la_default;
  else {
    args = la_init; /* initialize argument to blank slate */

    for (param = 1; parv[param]; param++) { /* process each parameter */
      switch (param_parse(sptr, parv[param], &args, parc == 2)) {
      case LPARAM_ERROR: /* error encountered, usage already sent, return */
	return 0;
	break;

      case LPARAM_CHANNEL: /* show channel instead */
	show_channels++;
	break;

      case LPARAM_SUCCESS: /* parse succeeded */
	break;
      }
    }
  }

  send_reply(sptr, RPL_LISTSTART);

  if (!show_channels)
  {
    if (args.max_users > args.min_users + 1 && args.max_time > args.min_time &&
        args.max_topic_time > args.min_topic_time)      /* Sanity check */
    {
      cli_listing(sptr) = (struct ListingArgs*) MyMalloc(sizeof(struct ListingArgs));
      assert(0 != cli_listing(sptr));
      memcpy(cli_listing(sptr), &args, sizeof(struct ListingArgs));
      if ((cli_listing(sptr)->chptr = GlobalChannelList)) {
        int m = GlobalChannelList->mode.mode & MODE_LISTED;
        list_next_channels(sptr, 64);
        GlobalChannelList->mode.mode |= m;
        return 0;
      }
      MyFree(cli_listing(sptr));
      cli_listing(sptr) = 0;
    }
    send_reply(sptr, RPL_LISTEND);
    return 0;
  }

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = FindChannel(name);
    if (chptr && ShowChannel(sptr, chptr) && cli_user(sptr))
      send_reply(sptr, RPL_LIST, chptr->chname,
		 chptr->users - number_of_zombies(chptr), chptr->topic);
  }

  send_reply(sptr, RPL_LISTEND);
  return 0;
}
