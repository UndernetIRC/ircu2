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
#include "ircd_events.h"

#include "ircd.h"
#include "ircd_alloc.h"

#include <signal.h>

static int sig_fd = -1;

static struct {
  struct Generators gens;

  struct Event*	 events_head;
  struct Event*	 events_tail;
  unsigned int	 events_count;

  struct Event*	 events_free;
  unsigned int	 events_alloc;

  struct Engine* engine;
} netInfo = { { 0, 0, 0, 0, 0, 0 }, 0, 0, 0, 0, 0, 0 };

/* Remove something from its queue */
static void
gen_dequeue(void *arg)
{
  struct GenHeader* gen = (struct GenHeader*) arg;

  if (gen->gh_next) /* clip it out of the list */
    gen->gh_next->gh_prev_p = gen->gh_prev_p;
  *gen->gh_prev_p = gen->gh_next;

  gen->gh_next = 0; /* mark that it's not in the list anymore */
  gen->gh_prev_p = 0;
}

/* Execute an event; optimizations should inline this */
static void
event_execute(struct Event* event)
{
  assert(0 == event->ev_prev_p); /* must be off queue first */

  (*event->ev_gen.gen_header->gh_call)(event); /* execute the event */

  /* The logic here is very careful; if the event was an ET_DESTROY,
   * then we must assume the generator is now invalid; fortunately, we
   * don't need to do anything to it if so.  Otherwise, we decrement
   * the reference count; if reference count goes to zero, AND we need
   * to destroy the generator, THEN we generate a DESTROY event.
   */
  if (event->ev_type != ET_DESTROY &&
      !--event->ev_gen.gen_header->gh_ref &&
      (event->ev_gen.gen_header->gh_flags & GEN_DESTROY)) {
    gen_dequeue(event->ev_gen.gen_header);
    event_generate(ET_DESTROY, event->ev_gen.gen_header);
  }

  event->ev_callback = 0; /* clear event data */
  event->ev_gen.gen_header = 0;
  event->ev_type = ET_DESTROY;

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

  ptr->ev_gen.gen_header = (struct GenHeader*) gen;
  ptr->ev_gen.gen_header->gh_ref++;

  event_add(ptr); /* add event to queue */
}

/* Place a timer in the correct spot on the queue */
static void
timer_enqueue(struct Timer* timer)
{
  struct Timer** ptr_p;

  assert(0 != timer);
  assert(0 == timer->t_header.gh_prev_p); /* not already on queue */

  /* Calculate expire time */
  switch (timer->t_type) {
  case TT_ABSOLUTE: /* no need to consider it relative */
    timer->t_expire = timer->t_value;
    break;

  case TT_RELATIVE: case TT_PERIODIC: /* relative timer */
    timer->t_expire = timer->t_value + CurrentTime;
    break;
  }

  /* Find a slot to insert timer */
  for (ptr_p = &netInfo.gens.g_timer; ; ptr_p = &(*ptr_p)->t_header.gh_next)
    if (!*ptr_p || timer->t_expire < (*ptr_p)->t_expire)
      break;

  timer->t_header.gh_next = *ptr_p; /* link it in the right place */
  timer->t_header.gh_prev_p = ptr_p;
  if (*ptr_p)
    (*ptr_p)->t_header.gh_prev_p = &timer->t_header.gh_next;
  *ptr_p = timer;

  netInfo.timers_count++;
}

/* Add a timer to be processed */
void
timer_add(struct Timer* timer, EventCallBack call, void* data,
	  enum TimerType type, time_t value)
{
  assert(0 != timer);
  assert(0 != call);
  assert(0 != value);

  timer->t_header.gh_next = 0; /* initialize a timer... */
  timer->t_header.gh_prev_p = 0;
  timer->t_header.gh_flags = 0;
  timer->t_header.gh_ref = 0;
  timer->t_header.gh_call = call;
  timer->t_header.gh_data = data;
  timer->t_type = type;
  timer->t_value = value;
  timer->t_expire = 0;

  timer_enqueue(timer); /* and enqueue it */
}

/* Remove a timer from the processing queue */
void
timer_del(struct Timer* timer)
{
  assert(0 != timer);

  if (timer->t_header.gh_ref) /* in use; mark for destruction */
    timer->t_header.gh_flags |= GEN_DESTROY;
  else { /* not in use; destroy right now */
    gen_dequeue(timer);
    event_generate(ET_DESTROY, timer);
  }
}

/* Return 0 if no pending timers, else return next expire time (absolute) */
time_t
timer_next(void)
{
  return netInfo.gens.g_timer ? netInfo.gens.g_timer->t_expire : 0;
}

/* Execute all expired timers */
void
timer_run(void)
{
  struct Timer* ptr;
  struct Timer* next;

  /* go through queue... */
  for (ptr = netInfo.gens.g_timer; ptr; ptr = next) {
    next = ptr->next;
    if (CurrentTime < ptr->t_expire)
      break; /* processed all pending timers */

    gen_dequeue(ptr); /* must dequeue timer here */
    event_generate(ET_EXPIRE, ptr); /* generate expire event */

    switch (ptr->t_type) {
    case TT_ABSOLUTE: case TT_RELATIVE:
      timer_del(ptr); /* delete inactive timer */
      break;

    case TT_PERIODIC:
      timer_enqueue(ptr); /* re-queue periodic timer */
      break;
    }
  }
}

static void
signal_signal(struct Signal* signal)
{
  assert(0 != signal);

  signal->sig_count++; /* count number of signals */
  event_generate(ET_SIGNAL, signal); /* generate signal event */
}

static void
signal_event(int sig)
{
  unsigned char c;

  assert(sig_fd >= 0);

  c = (unsigned char) sig; /* only write 1 byte to identify sig */

  write(sig_fd, &c, 1);
}

static void
signal_socket_callback(struct Event* event)
{
  unsigned char c = 0;
  int sig;
  struct Signal* ptr;

  read(event->ev_gen.gen_socket->s_fd, &c, 1); /* which signal? */
  sig = (int) c;

  for (ptr = netInfo.gens.g_signal; ptr; ptr = ptr->sig_header.gh_next)
    if (ptr->sig_signal) /* find its descriptor... */
      break;

  signal_signal(ptr); /* signal event */
}

void
signal_add(struct Signal* signal, EventCallBack call, void* data, int sig)
{
  struct sigaction act;

  assert(0 != signal);
  assert(0 != call);
  assert(0 != netInfo.engine);

  signal->sig_header.gh_next = netInfo.gens.g_signal; /* set up struct */
  signal->sig_header.gh_prev_p = &netInfo.gens.g_signal;
  signal->sig_header.gh_flags = 0;
  signal->sig_header.gh_ref = 0;
  signal->sig_header.gh_call = call;
  signal->sig_header.gh_data = data;
  signal->sig_signal = sig;
  signal->sig_count = 0;

  if (netInfo.gens.g_signal) /* link into list */
    netInfo.gens.g_signal->sig_header.gh_prev_p = &signal->sig_header.gh_next;
  netInfo.gens.g_signal = signal;

  if (netInfo.engine->eng_flags & ENG_FLAGS_DIRECTSIGS)
    (*netInfo.engine->eng_signal)(netInfo.engine, signal); /* tell engine */
  else {
    act.sa_handler = signal_event; /* set up signal handler */
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(sig, &act, 0);
  }
}
