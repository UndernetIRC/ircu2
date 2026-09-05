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
#include "label.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
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
  0,                          /* flags */
  2147483647,                 /* max_topic_time */
  0,                          /* min_topic_time */
  0,                          /* bucket */
  {0},                        /* wildcard */
  {0}                         /* label_ref */
};

static struct ListingArgs la_default = {
  2147483647,                 /* max_time */
  0,                          /* min_time */
  4294967295U,                /* max_users */
  0,                          /* min_users */
  0,                          /* flags */
  2147483647,                 /* max_topic_time */
  0,                          /* min_topic_time */
  0,                          /* bucket */
  {0},                        /* wildcard */
  {0}                         /* label_ref */
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
	     "Where \037parameters\037 is a space or comma separated "
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
	     " \037pattern\037       ; Channels with names matching "
             "\037pattern\037. ");
  send_reply(sptr, RPL_LISTUSAGE,
	     " !\037pattern\037      ; Channels with names not "
             "matching \037pattern\037. ");
  send_reply(sptr, RPL_LISTUSAGE, "Note: Patterns may contain * and ?. "
             "You may only give one pattern match constraint.");
  if (IsAnOper(sptr)) {
    send_reply(sptr, RPL_LISTUSAGE,
               " \002S\002             ; Show secret channels.");
    send_reply(sptr, RPL_LISTUSAGE,
               " \002M\002             ; Show channel modes.");
  }
  send_reply(sptr, RPL_LISTUSAGE,
	     "Example: LIST <3,>1,C<10,T>0,#a*  ; 2 users, younger than 10 "
	     "min., topic set., starts with #a");

  return LPARAM_ERROR; /* return error condition */
}

static int
param_parse(struct Client *sptr, const char *param, struct ListingArgs *args,
	    int permit_chan)
{
  int is_time = 0;
  char dir;
  unsigned int val;
  char *tmp1, *tmp2;

  assert(0 != args);

  if (!param) /* NULL param == default--no list param */
    return LPARAM_SUCCESS;

  while (1) {
    switch (*param) {
    case 'T':
    case 't':
      is_time++;
      args->flags |= LISTARG_TOPICLIMITS;
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

      if (is_time && val < 80000000) {
        /* Convert age to timestamp and reverse direction */
        val = TStime() - val * 60;
        dir = (dir == '>') ? '<' : '>';
      }
      
      switch (is_time) {
      case 0: /* number of users on channel */
	if (dir == '<')
	  args->max_users = val;
	else
	  args->min_users = val;
	break;

      case 1: /* channel creation time */
	if (dir == '<')
	  args->max_time = val;
	else
	  args->min_time = val;
	break;

      case 2: /* channel topic */
	if (dir == '<')
	  args->max_topic_time = val;
	else
	  args->min_topic_time = val;
	break;
      }
      break;

    case 'S':
    case 's':
      if (!IsAnOper(sptr) || !HasPriv(sptr, PRIV_LIST_CHAN))
        return show_usage(sptr);

      args->flags |= LISTARG_SHOWSECRET;
      param++;

      if (*param != ',' && *param != ' ' && *param != '\0') /* check syntax */
        return show_usage(sptr);
      break;

    case 'M':
    case 'm':
      if (!IsAnOper(sptr) || !HasPriv(sptr, PRIV_LIST_CHAN))
        return show_usage(sptr);

      args->flags |= LISTARG_SHOWMODES;
      param++;

      if (*param != ',' && *param != ' ' && *param != '\0') /* check syntax */
        return show_usage(sptr);
      break;

    default:
      /* It might be a wildcard... */
      if (strchr(param, '*') ||
          strchr(param, '?'))
      {
        if (param[0] == '!')
        {
          param++;
          args->flags |= LISTARG_NEGATEWILDCARD;
        }

        /* Only one wildcard allowed... */
        if (args->wildcard[0] != 0)
          return show_usage(sptr);

        /* If its not going to match anything, don't bother. */
        if (param[0] != '*' &&
            param[0] != '?' &&
            param[0] != '#' &&
            param[0] != '&')
          return show_usage(sptr);

        tmp1 = strchr(param, ',');
        tmp2 = strchr(param, ' ');
        if (tmp2 && (!tmp1 || (tmp2 < tmp1)))
          tmp1 = tmp2;
        
        if (tmp1)
          *tmp1++ = 0;

        ircd_strncpy(args->wildcard, param, CHANNELLEN-1);
        args->wildcard[CHANNELLEN-1] = 0;

        if (tmp1 == NULL)
          return LPARAM_SUCCESS;

        param = tmp1;
        continue;
      }

      /* channel name? */
      if (!permit_chan || !IsChannelName(param))
	return show_usage(sptr);

      return LPARAM_CHANNEL;
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
    char old_label_ref[sizeof(cli_listing(sptr)->label_ref)];

    ircd_strncpy(old_label_ref, cli_listing(sptr)->label_ref,
                 sizeof(old_label_ref) - 1);
    old_label_ref[sizeof(old_label_ref) - 1] = '\0';

    if (cli_listing(sptr))
    MyFree(cli_listing(sptr));
    cli_listing(sptr) = 0;

    if (*old_label_ref) {
      /* Being superseded doesn't make the old listing's response
       * dishonest: RPL_LISTEND terminates it the same way a natural
       * completion would, just with fewer channels than a full run
       * would have produced -- LIST never promised completeness beyond
       * "you get 322s, then 323 ends it". So finish it labeled (fold
       * this RPL_LISTEND into its own capture, then close that capture
       * out as its own BATCH/ACK/single-line via reopen()+finish(), not
       * abort()) the same as any other early-but-clean completion,
       * rather than dumping whatever it had captured unlabeled. A
       * *different* capture may be active right now for sptr (e.g. if
       * this LIST/STOP command is itself labeled); save/restore it
       * around the old one so this doesn't steal its output.
       *
       * This fires against a genuinely live capture in practice, not
       * just defensively: label_capture_stream_active() (label.c) makes
       * a labeled LIST's output go out through the *real*
       * send_buffer()/cli_sendQ() path as it's produced, so list_next_
       * channels()'s own sendQ-based pause check sees it and can leave
       * cli_listing() (and this capture) parked across ticks exactly
       * like an unlabeled LIST always could -- see
       * label_capture_append()'s streaming branch in label.c. */
      struct Client *saved_active_client;
      struct LabelCapture *saved_active_node;

      label_capture_save_active(&saved_active_client, &saved_active_node);

      if (label_capture_reopen(sptr, old_label_ref)) {
        send_reply(sptr, RPL_LISTEND);
        label_capture_close_window();
        label_capture_finish(sptr, old_label_ref);
      } else {
        /* old_label_ref doesn't resolve to anything: reopen() no-ops
         * silently, which -- left unchecked -- would leave RPL_LISTEND
         * landing in whatever capture happens to be active right now
         * (e.g. this very LIST/STOP command's own, if it's itself
         * labeled) instead of nowhere. Close the window explicitly
         * first so it goes out plain; nothing to finish() either. */
        label_capture_close_window();
        send_reply(sptr, RPL_LISTEND);
      }

      label_capture_restore_active(saved_active_client, saved_active_node);
    } else {
      send_reply(sptr, RPL_LISTEND);
    }

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

      {
        /* If this LIST is labeled, commit to a streaming BATCH right now
         * rather than deferring the ACK/single-line/BATCH decision to
         * parse.c's normal end-of-dispatch finish(): a paginated listing
         * is unconditionally multi-line (at minimum RPL_LISTEND) and may
         * span many event-loop ticks, so there is nothing to decide and
         * nothing worth buffering in memory until some eventual finish().
         * See label_capture_stream_active() in label.c. */
        const char *ref = label_capture_stream_active(sptr);

        if (ref)
          ircd_strncpy(cli_listing(sptr)->label_ref, ref,
                       sizeof(cli_listing(sptr)->label_ref) - 1);
      }

      list_next_channels(sptr);
      return 0;
    }
    send_reply(sptr, RPL_LISTEND);
    return 0;
  }

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = FindChannel(name);
    if (!chptr)
        continue;
    if (ShowChannel(sptr, chptr)
        || (IsAnOper(sptr) && HasPriv(sptr, PRIV_LIST_CHAN)))
      send_reply(sptr, RPL_LIST, chptr->chname,
		 chptr->users - number_of_zombies(chptr), chptr->topic);
  }

  send_reply(sptr, RPL_LISTEND);
  return 0;
}
