/*
 * IRC - Internet Relay Chat, ircd/destruct_event.c
 * Copyright (C) 2002 Carlo Wood <carlo@alinoe.com>
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
/** @file
 * @brief Implementation of timed channel destruction events.
 * @version $Id$
 */
#include "config.h"

#include "channel.h"	/* destruct_channel */
#include "s_debug.h"
#include "ircd_alloc.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "send.h"
#include "msg.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>

/** Structure describing a destruction event. */
struct DestructEvent {
  struct DestructEvent* next_event; /**< Next event in the queue. */
  struct DestructEvent* prev_event; /**< Previous event in the queue. */
  time_t expires;                   /**< When the destruction should happen. */
  struct Channel* chptr;            /**< Channel to destroy. */
};

/** Head of short-delay destruction events.  */
static struct DestructEvent* minute_list_top;
/** Tail of short-delay destruction events. */
static struct DestructEvent* minute_list_bottom;
/** Head of long-delay destruction events. */
static struct DestructEvent* days_list_top;
/** Tail of long-delay destruction events. */
static struct DestructEvent* days_list_bottom;

/** Schedule a short-delay destruction event for \a chptr.
 * @param[in] chptr Channel to destroy.
 */
void schedule_destruct_event_1m(struct Channel* chptr)
{
  struct DestructEvent* new_event;

  /* Ignore request when we already have a destruct request */
  if (chptr->destruct_event)
    return;

  /* Create a new destruct event and add it at the top of the list. */
  new_event = (struct DestructEvent*)MyMalloc(sizeof(struct DestructEvent));
  new_event->expires = TStime() + 60;	/* 1 minute from now */
  new_event->next_event = NULL;
  new_event->prev_event = minute_list_top;
  new_event->chptr = chptr;

  if (minute_list_top)
    minute_list_top->next_event = new_event;
  minute_list_top = new_event;
  if (!minute_list_bottom)
    minute_list_bottom = new_event;

  chptr->destruct_event = new_event;
}

/** Schedule a long-delay destruction event for \a chptr.
 * @param[in] chptr Channel to destroy.
 */
void schedule_destruct_event_48h(struct Channel* chptr)
{
  struct DestructEvent* new_event;

  /* Ignore request when we already have a destruct request */
  if (chptr->destruct_event)
    return;

  /* Create a new destruct event and add it at the top of the list. */
  new_event = (struct DestructEvent*)MyMalloc(sizeof(struct DestructEvent));
  new_event->expires = TStime() + 172800;	/* 48 hours from now */
  new_event->next_event = NULL;
  new_event->prev_event = days_list_top;
  new_event->chptr = chptr;

  if (days_list_top)
    days_list_top->next_event = new_event;
  days_list_top = new_event;
  if (!days_list_bottom)
    days_list_bottom = new_event;

  chptr->destruct_event = new_event;
}

/** Unlink a destruction event for a channel.
 * @param[in] chptr Channel that is being destroyed early.
 */
void remove_destruct_event(struct Channel* chptr)
{
  struct DestructEvent* event = chptr->destruct_event;

  assert(event != NULL);

  /* unlink event */
  if (event->prev_event)
    event->prev_event->next_event = event->next_event;
  if (event->next_event)
    event->next_event->prev_event = event->prev_event;

  /* correct top and bottom pointers */
  if (days_list_top == event)
    days_list_top = event->prev_event;
  if (minute_list_top == event)
    minute_list_top = event->prev_event;
  if (days_list_bottom == event)
    days_list_bottom = event->next_event;
  if (minute_list_bottom == event)
    minute_list_bottom = event->next_event;

  /* Free memory */
  MyFree(event);

  chptr->destruct_event = NULL;
}

/** Execute expired channel destruction events.
 * @param[in] ev Expired timer event (ignored).
 */
void exec_expired_destruct_events(struct Event* ev)
{
  int i = 0;
  struct DestructEvent** list_bottom;
  for(list_bottom = &minute_list_bottom; i < 2; ++i, list_bottom = &days_list_bottom)
  {
    while (*list_bottom && TStime() >= (*list_bottom)->expires)
    {
      struct Channel* chptr = (*list_bottom)->chptr;
      /* Send DESTRUCT message */
      sendcmdto_serv_butone(&me, CMD_DESTRUCT, 0, "%s %Tu", chptr->chname, chptr->creationtime);
      remove_destruct_event(chptr);
      destruct_channel(chptr);
    }
  }
}

