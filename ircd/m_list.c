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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

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
  int show_usage = 0, show_channels = 0, param;
  struct ListingArgs args = {
    2147483647,                 /* max_time */
    0,                          /* min_time */
    4294967295U,                /* max_users */
    0,                          /* min_users */
    0,                          /* topic_limits */
    2147483647,                 /* max_topic_time */
    0,                          /* min_topic_time */
    0                        /* chptr */
  };

  if (cli_listing(sptr))            /* Already listing ? */
  {
    cli_listing(sptr)->chptr->mode.mode &= ~MODE_LISTED;
    MyFree(cli_listing(sptr));
    cli_listing(sptr) = 0;
    send_reply(sptr, RPL_LISTEND);
    if (parc < 2)
      return 0;                 /* Let LIST abort a listing. */
  }

  if (parc < 2)                 /* No arguments given to /LIST ? */
  {
#ifdef DEFAULT_LIST_PARAM
    static char *defparv[MAXPARA + 1];
    static int defparc = 0;
    static char lp[] = DEFAULT_LIST_PARAM;
    int i;

    /*
     * XXX - strtok used
     */
    if (!defparc)
    {
      char *s = lp, *t;

      defparc = 1;
      defparv[defparc++] = t = strtok(s, " ");
      while (t && defparc < MAXPARA)
      {
        if ((t = strtok(0, " ")))
          defparv[defparc++] = t;
      }
    }
    for (i = 1; i < defparc; i++)
      parv[i] = defparv[i];
    parv[i] = 0;
    parc = defparc;
#endif /* DEFAULT_LIST_PARAM */
  }

  /* Decode command */
  for (param = 1; !show_usage && parv[param]; param++)
  {
    char *p = parv[param];
    do
    {
      int is_time = 0;
      switch (*p)
      {
        case 'T':
        case 't':
          is_time++;
          args.topic_limits = 1;
          /* Fall through */
        case 'C':
        case 'c':
          is_time++;
          p++;
          if (*p != '<' && *p != '>')
          {
            show_usage = 1;
            break;
          }
          /* Fall through */
        case '<':
        case '>':
        {
          p++;
          if (!IsDigit(*p))
            show_usage = 1;
          else
          {
            if (is_time)
            {
              time_t val = atoi(p);
              if (p[-1] == '<')
              {
                if (val < 80000000)     /* Toggle UTC/offset */
                {
                  /*
                   * Demands that
                   * 'TStime() - chptr->creationtime < val * 60'
                   * Which equals
                   * 'chptr->creationtime > TStime() - val * 60'
                   */
                  if (is_time == 1)
                    args.min_time = TStime() - val * 60;
                  else
                    args.min_topic_time = TStime() - val * 60;
                }
                else if (is_time == 1)  /* Creation time in UTC was entered */
                  args.max_time = val;
                else            /* Topic time in UTC was entered */
                  args.max_topic_time = val;
              }
              else if (val < 80000000)
              {
                if (is_time == 1)
                  args.max_time = TStime() - val * 60;
                else
                  args.max_topic_time = TStime() - val * 60;
              }
              else if (is_time == 1)
                args.min_time = val;
              else
                args.min_topic_time = val;
            }
            else if (p[-1] == '<')
              args.max_users = atoi(p);
            else
              args.min_users = atoi(p);
            if ((p = strchr(p, ',')))
              p++;
          }
          break;
        }
        default:
          if (!IsChannelName(p))
          {
            show_usage = 1;
            break;
          }
          if (parc != 2)        /* Don't allow a mixture of channels with <,> */
            show_usage = 1;
          show_channels = 1;
          p = 0;
          break;
      }
    }
    while (!show_usage && p);   /* p points after comma, or is NULL */
  }

  if (show_usage)
  {
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
    return 0;
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


#if 0
/*
 * m_list
 *
 * parv[0] = sender prefix
 * parv[1] = channel list or user/time limit
 * parv[2...] = more user/time limits
 */
int m_list(struct Client* cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  char *name, *p = 0;
  int show_usage = 0, show_channels = 0, param;
  struct ListingArgs args = {
    2147483647,                 /* max_time */
    0,                          /* min_time */
    4294967295U,                /* max_users */
    0,                          /* min_users */
    0,                          /* topic_limits */
    2147483647,                 /* max_topic_time */
    0,                          /* min_topic_time */
    0                        /* chptr */
  };

  if (sptr->listing)            /* Already listing ? */
  {
    sptr->listing->chptr->mode.mode &= ~MODE_LISTED;
    MyFree(sptr->listing);
    sptr->listing = 0;
    sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, sptr->name); /* XXX DEAD */
    if (parc < 2)
      return 0;                 /* Let LIST abort a listing. */
  }

  if (parc < 2)                 /* No arguments given to /LIST ? */
  {
#ifdef DEFAULT_LIST_PARAM
    static char *defparv[MAXPARA + 1];
    static int defparc = 0;
    static char lp[] = DEFAULT_LIST_PARAM;
    int i;

    if (!defparc)
    {
      char *s = lp, *t;

      defparc = 1;
      defparv[defparc++] = t = strtok(s, " ");
      while (t && defparc < MAXPARA)
      {
        if ((t = strtok(0, " ")))
          defparv[defparc++] = t;
      }
    }
    for (i = 1; i < defparc; i++)
      parv[i] = defparv[i];
    parv[i] = 0;
    parc = defparc;
#endif /* DEFAULT_LIST_PARAM */
  }

  /* Decode command */
  for (param = 1; !show_usage && parv[param]; param++)
  {
    char *p = parv[param];
    do
    {
      int is_time = 0;
      switch (*p)
      {
        case 'T':
        case 't':
          is_time++;
          args.topic_limits = 1;
          /* Fall through */
        case 'C':
        case 'c':
          is_time++;
          p++;
          if (*p != '<' && *p != '>')
          {
            show_usage = 1;
            break;
          }
          /* Fall through */
        case '<':
        case '>':
        {
          p++;
          if (!IsDigit(*p))
            show_usage = 1;
          else
          {
            if (is_time)
            {
              time_t val = atoi(p);
              if (p[-1] == '<')
              {
                if (val < 80000000)     /* Toggle UTC/offset */
                {
                  /*
                   * Demands that
                   * 'TStime() - chptr->creationtime < val * 60'
                   * Which equals
                   * 'chptr->creationtime > TStime() - val * 60'
                   */
                  if (is_time == 1)
                    args.min_time = TStime() - val * 60;
                  else
                    args.min_topic_time = TStime() - val * 60;
                }
                else if (is_time == 1)  /* Creation time in UTC was entered */
                  args.max_time = val;
                else            /* Topic time in UTC was entered */
                  args.max_topic_time = val;
              }
              else if (val < 80000000)
              {
                if (is_time == 1)
                  args.max_time = TStime() - val * 60;
                else
                  args.max_topic_time = TStime() - val * 60;
              }
              else if (is_time == 1)
                args.min_time = val;
              else
                args.min_topic_time = val;
            }
            else if (p[-1] == '<')
              args.max_users = atoi(p);
            else
              args.min_users = atoi(p);
            if ((p = strchr(p, ',')))
              p++;
          }
          break;
        }
        default:
          if (!IsChannelName(p))
          {
            show_usage = 1;
            break;
          }
          if (parc != 2)        /* Don't allow a mixture of channels with <,> */
            show_usage = 1;
          show_channels = 1;
          p = 0;
          break;
      }
    }
    while (!show_usage && p);   /* p points after comma, or is NULL */
  }

  if (show_usage)
  {
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        "Usage: \002/QUOTE LIST\002 \037parameters\037");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        "Where \037parameters\037 is a space or comma seperated "
        "list of one or more of:");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        " \002<\002\037max_users\037    ; Show all channels with less "
        "than \037max_users\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        " \002>\002\037min_users\037    ; Show all channels with more "
        "than \037min_users\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        " \002C<\002\037max_minutes\037 ; Channels that exist less "
        "than \037max_minutes\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        " \002C>\002\037min_minutes\037 ; Channels that exist more "
        "than \037min_minutes\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        " \002T<\002\037max_minutes\037 ; Channels with a topic last "
        "set less than \037max_minutes\037 ago.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        " \002T>\002\037min_minutes\037 ; Channels with a topic last "
        "set more than \037min_minutes\037 ago.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0], /* XXX DEAD */
        "Example: LIST <3,>1,C<10,T>0  ; 2 users, younger than 10 min., "
        "topic set.");
    return 0;
  }

  sendto_one(sptr, rpl_str(RPL_LISTSTART), me.name, parv[0]); /* XXX DEAD */

  if (!show_channels)
  {
    if (args.max_users > args.min_users + 1 && args.max_time > args.min_time &&
        args.max_topic_time > args.min_topic_time)      /* Sanity check */
    {
      sptr->listing = (struct ListingArgs*) MyMalloc(sizeof(struct ListingArgs));
      assert(0 != sptr->listing);
      memcpy(sptr->listing, &args, sizeof(struct ListingArgs));
      if ((sptr->listing->chptr = GlobalChannelList)) {
        int m = GlobalChannelList->mode.mode & MODE_LISTED;
        list_next_channels(sptr, 64);
        GlobalChannelList->mode.mode |= m;
        return 0;
      }
      MyFree(sptr->listing);
      sptr->listing = 0;
    }
    sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = FindChannel(name);
    if (chptr && ShowChannel(sptr, chptr) && sptr->user)
      sendto_one(sptr, rpl_str(RPL_LIST), me.name, parv[0], /* XXX DEAD */
          ShowChannel(sptr, chptr) ? chptr->chname : "*",
          chptr->users - number_of_zombies(chptr), chptr->topic);
  }

  sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]); /* XXX DEAD */
  return 0;
}
#endif /* 0 */

