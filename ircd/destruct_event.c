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
 *
 * $Id$
 */
#include "config.h"

#include "channel.h"	/* destruct_channel */
#include "s_debug.h"
#include "ircd_alloc.h"
#include "ircd.h"
#include "ircd_events.h"

#include <assert.h>
#include <stdlib.h>

struct DestructEvent {
  struct DestructEvent* next_event;
  struct DestructEvent* prev_event;
  time_t expires;
  struct Channel* chptr;
};

static struct DestructEvent* minute_list_top;
static struct DestructEvent* minute_list_bottom;
static struct DestructEvent* days_list_top;
static struct DestructEvent* days_list_bottom;

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

void exec_expired_destruct_events(struct Event* ev)
{
  int i = 0;
  struct DestructEvent** list_bottom;
  for(list_bottom = &minute_list_bottom; i < 2; ++i, list_bottom = &days_list_bottom)
  {
    while (*list_bottom && TStime() >= (*list_bottom)->expires)
    {
      struct Channel* chptr = (*list_bottom)->chptr;
      remove_destruct_event(chptr);
      destruct_channel(chptr);
    }
  }
}

