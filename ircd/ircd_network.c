/*
 * IRC - Internet Relay Chat, ircd/gline.c
 * Copyright (C) 2001 Kevin L. Mitchell <klmitch@mit.edu>
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
#include "ircd_network.h"

#include "ircd_alloc.h"

static struct {
  struct Socket* sockets_head;
  unsigned int	 sockets_count;

  struct Timer*	 timers_head;
  unsigned int	 timers_count;

  struct Signal* signals_head;
  unsigned int	 signals_count;

  struct Event*	 events_head;
  struct Event*	 events_tail;
  unsigned int	 events_count;

  struct Event*	 events_free;
  unsigned int	 events_alloc;
} netInfo = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/* Execute an event; optimizations should inline this */
static void
event_execute(struct Event* event)
{
  assert(0 == event->ev_prev_p); /* must be off queue first */

  (*event->ev_callback)(event); /* execute the event */

  event->ev_type = ET_ERROR; /* clear event data */
  event->ev_callback = 0;
  event->ev_gen.gen_socket = 0;

  event->ev_next = netInfo.events_free; /* add to free list */
  netInfo.events_free = event;
}

#ifndef IRCD_THREADED
/* we synchronously execute the event when not threaded */
#define event_add(event)	event_execute(event)

#else
/* add an event to the work queue */
static void
event_add(struct Event* event)
{
  /* This is just a placeholder; don't expect ircd to be threaded soon */
  event->ev_next = 0; /* add event to end of event queue */
  if (netInfo.events_head) {
    assert(0 != netInfo.events_tail);

    event->ev_prev_p = &netInfo.events_tail->ev_next;
    netInfo.events_tail->ev_next = event;
    netInfo.events_tail = event;
  } else { /* queue was empty... */
    assert(0 == netInfo.events_tail);

    event->ev_prev_p = &netInfo.events_head;
    netInfo.events_head = event;
    netInfo.events_tail = event;
  }

  netInfo.events_count++; /* update count of pending events */

  /* We'd also have to signal the work crew here */
}
#endif /* IRCD_THREADED */

/* Generate an event and add it to the queue (or execute it) */
void
event_generate(enum EventType type, void* gen)
{
  struct Event* ptr;

  assert(0 != gen);

  if ((ptr = netInfo.events_free))
    netInfo.events_free = ptr->next; /* pop one off the freelist */
  else { /* allocate another structure */
    ptr = (struct Event*) MyMalloc(sizeof(struct Event));
    netInfo.events_alloc++; /* count of allocated events */
  }

  ptr->ev_type = type; /* Record event type */

  switch (type) { /* link to generator properly */
  case ET_READ: case ET_WRITE: case ET_ACCEPT: case ET_EOF: case ET_ERROR:
    /* event is for a socket */
    ptr->ev_gen.gen_socket = (struct Socket*) gen;
    ptr->ev_callback = ptr->ev_gen.gen_socket->s_callback;
    break;

  case ET_SIGNAL: /* event is for a signal */
    ptr->ev_gen.gen_signal = (struct Signal*) gen;
    ptr->ev_callback = ptr->ev_gen.gen_signal->sig_callback;
    break;

  case ET_TIMER: /* event is for a timer */
    ptr->ev_gen.gen_timer = (struct Timer*) gen;
    ptr->ev_callback = ptr->ev_gen.gen_timer->t_callback;
    break;
  }

  event_add(ptr); /* add event to queue */
}
