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

#define SIGS_PER_SOCK	10	/* number of signals to process per socket
				   readable event */

#ifdef HAVE_KQUEUE
extern struct Engine engine_kqueue;
#define ENGINE_KQUEUE	&engine_kqueue,
#else
#define ENGINE_KQUEUE
#endif /* HAVE_KQUEUE */

#ifdef HAVE_DEVPOLL_H
extern struct Engine engine_devpoll;
#define ENGINE_DEVPOLL	&engine_devpoll,
#else
#define ENGINE_DEVPOLL
#endif /* HAVE_DEVPOLL_H */

#ifdef USE_POLL
extern struct Engine engine_poll;
#define ENGINE_FALLBACK	&engine_poll,
#else
extern struct Engine engine_select;
#define ENGINE_FALLBACK	&engine_select,
#endif /* USE_POLL */

static struct Engine *evEngines[] = {
  ENGINE_KQUEUE
  ENGINE_DEVPOLL
  ENGINE_FALLBACK
  0
};

static struct Socket sig_sock;

static int sig_fd = -1;

static struct {
  struct Generators gens;

  struct Event*	 events_head;
  struct Event*	 events_tail;
  unsigned int	 events_count;

  struct Event*	 events_free;
  unsigned int	 events_alloc;

  struct Engine* engine;
} evInfo = { { 0, 0, 0 }, 0, 0, 0, 0, 0, 0 };

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

  event->ev_next = evInfo.events_free; /* add to free list */
  evInfo.events_free = event;
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
  if (evInfo.events_head) {
    assert(0 != evInfo.events_tail);

    event->ev_prev_p = &evInfo.events_tail->ev_next;
    evInfo.events_tail->ev_next = event;
    evInfo.events_tail = event;
  } else { /* queue was empty... */
    assert(0 == evInfo.events_tail);

    event->ev_prev_p = &evInfo.events_head;
    evInfo.events_head = event;
    evInfo.events_tail = event;
  }

  evInfo.events_count++; /* update count of pending events */

  /* We'd also have to signal the work crew here */
}
#endif /* IRCD_THREADED */

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
  for (ptr_p = &evInfo.gens.g_timer; ; ptr_p = &(*ptr_p)->t_header.gh_next)
    if (!*ptr_p || timer->t_expire < (*ptr_p)->t_expire)
      break;

  timer->t_header.gh_next = *ptr_p; /* link it in the right place */
  timer->t_header.gh_prev_p = ptr_p;
  if (*ptr_p)
    (*ptr_p)->t_header.gh_prev_p = &timer->t_header.gh_next;
  *ptr_p = timer;
}

/* signal handler for writing signal notification to pipe */
static void
signal_handler(int sig)
{
  unsigned char c;

  assert(sig_fd >= 0);

  c = (unsigned char) sig; /* only write 1 byte to identify sig */

  write(sig_fd, &c, 1);
}

/* callback for signal "socket" events */
static void
signal_callback(struct Event* event)
{
  unsigned char sigstr[SIGS_PER_SOCK];
  int sig, n_sigs, i;
  struct Signal* ptr;

  assert(event->ev_type == ET_READ); /* readable events only */

  n_sigs = read(event->ev_gen.gen_socket->s_fd, sigstr, sizeof(sigstr));

  for (i = 0; i < n_sigs; i++) {
    sig = (int) sigstr[i]; /* get signal */

    for (ptr = evInfo.gens.g_signal; ptr; ptr = ptr->sig_header.gh_next)
      if (ptr->sig_signal) /* find its descriptor... */
	break;

    event_generate(ET_SIGNAL, ptr); /* generate signal event */
  }
}

/* Initializes the event system */
void
event_init(void)
{
  int i, p[2];

  for (i = 0; evEngine[i]; i++) { /* look for an engine... */
    assert(0 != evEngine[i]->eng_name);
    assert(0 != evEngine[i]->eng_init);

    if ((*evEngine[i]->eng_init)())
      break; /* Found an engine that'll work */
  }

  assert(0 != evEngine[i]);

  evInfo.engine = evEngine[i]; /* save engine */

  if (!evInfo.engine->eng_signal) { /* engine can't do signals */
    if (pipe(p)) {
      log_write(LS_SYSTEM, L_CRIT, 0, "Failed to open signal pipe");
      exit(8);
    }

    sig_fd = p[1]; /* write end of pipe */
    socket_add(&sock_sig, signal_callback, 0, SS_CONNECTED,
	       SOCK_EVENT_READABLE, p[0]); /* read end of pipe */
  }
}

/* Do the event loop */
void
event_loop(void)
{
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_loop);

  (*evInfo.engine->eng_loop)(&evInfo.gens);
}

/* Generate an event and add it to the queue (or execute it) */
void
event_generate(enum EventType type, void* gen)
{
  struct Event* ptr;

  assert(0 != gen);

  if ((ptr = evInfo.events_free))
    evInfo.events_free = ptr->next; /* pop one off the freelist */
  else { /* allocate another structure */
    ptr = (struct Event*) MyMalloc(sizeof(struct Event));
    evInfo.events_alloc++; /* count of allocated events */
  }

  ptr->ev_type = type; /* Record event type */

  ptr->ev_gen.gen_header = (struct GenHeader*) gen;
  ptr->ev_gen.gen_header->gh_ref++;

  event_add(ptr); /* add event to queue */
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
  timer->t_header.gh_engdata = 0;
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

/* Execute all expired timers */
void
timer_run(void)
{
  struct Timer* ptr;
  struct Timer* next;

  /* go through queue... */
  for (ptr = evInfo.gens.g_timer; ptr; ptr = next) {
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

/* Adds a signal to the event callback system */
void
signal_add(struct Signal* signal, EventCallBack call, void* data, int sig)
{
  struct sigaction act;

  assert(0 != signal);
  assert(0 != call);
  assert(0 != evInfo.engine);

  signal->sig_header.gh_next = evInfo.gens.g_signal; /* set up struct */
  signal->sig_header.gh_prev_p = &evInfo.gens.g_signal;
  signal->sig_header.gh_flags = 0;
  signal->sig_header.gh_ref = 0;
  signal->sig_header.gh_call = call;
  signal->sig_header.gh_data = data;
  signal->sig_header.gh_engdata = 0;
  signal->sig_signal = sig;
  signal->sig_count = 0;

  if (evInfo.gens.g_signal) /* link into list */
    evInfo.gens.g_signal->sig_header.gh_prev_p = &signal->sig_header.gh_next;
  evInfo.gens.g_signal = signal;

  if (evInfo.engine->eng_signal)
    (*evInfo.engine->eng_signal)(signal); /* tell engine */
  else {
    act.sa_handler = signal_handler; /* set up signal handler */
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(sig, &act, 0);
  }
}

/* Adds a socket to the event system */
void
socket_add(struct Socket* sock, EventCallBack call, void* data,
	   enum SocketState state, unsigned int events, int fd)
{
  assert(0 != sock);
  assert(0 != call);
  assert(fd >= 0);
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_add);

  sock->s_header.gh_next = evInfo.gens.g_socket; /* set up struct */
  sock->s_header.gh_prev_p = &evInfo.gens.g_socket;
  sock->s_header.gh_flags = 0;
  sock->s_header.gh_ref = 0;
  sock->s_header.gh_call = call;
  sock->s_header.gh_data = data;
  sock->s_header.gh_engdata = 0;
  sock->s_state = state;
  sock->s_events = events & SOCK_EVENT_MASK;
  sock->s_fd = fd;

  if (evInfo.gens.g_socket) /* link into list */
    evInfo.gens.g_socket->s_header.gh_prev_p = &sock->s_header.gh_next;
  evInfo.gens.g_socket = sock;

  (*evInfo.engine->eng_add)(sock); /* tell engine about it */
}

/* deletes (or marks for deletion) a socket */
void
socket_del(struct Socket* sock)
{
  assert(0 != timer);
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_closing);

  /* tell engine socket is going away */
  (*evInfo.engine->eng_closing)(sock);

  if (sock->s_header.gh_ref) /* in use; mark for destruction */
    sock->s_header.gh_flags |= GEN_DESTROY;
  else { /* not in use; destroy right now */
    gen_dequeue(sock);
    event_generate(ET_DESTROY, sock);
  }
}

/* Sets the socket state to something else */
void
socket_state(struct Socket* sock, enum SocketState state)
{
  assert(0 != sock);
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_state);

  /* assertions for invalid socket state transitions */
  assert(sock->s_state != state); /* not changing states ?! */
  assert(sock->s_state != SS_LISTENING); /* listening socket to...?! */
  assert(sock->s_state != SS_CONNECTED); /* connected socket to...?! */
  /* connecting socket now connected */
  assert(sock->s_state != SS_CONNECTING || state == SS_CONNECTED);
  /* unconnected datagram socket now connected */
  assert(sock->s_state != SS_DATAGRAM || state == SS_CONNECTDG);
  /* connected datagram socket now unconnected */
  assert(sock->s_state != SS_CONNECTDG || state == SS_DATAGRAM);

  /* tell engine we're changing socket state */
  (*evInfo.engine->eng_state)(sock, state);

  sock->s_state = state; /* set new state */
}

/* sets the events a socket's interested in */
void
socket_events(struct Socket* sock, unsigned int events)
{
  unsigned int new_events;

  assert(0 != sock);
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_events);

  switch (events & SOCK_ACTION_MASK) {
  case SOCK_ACTION_SET: /* set events to given set */
    new_events = events & SOCK_EVENT_MASK;
    break;

  case SOCK_ACTION_ADD: /* add some events */
    new_events = sock->s_events | (events & SOCK_EVENT_MASK);
    break;

  case SOCK_ACTION_DEL: /* remove some events */
    new_events = sock->s_events & ~(events & SOCK_EVENT_MASK);
    break;
  }

  /* tell engine about event mask change */
  (*evInfo.engine->eng_events)(sock, new_events);

  sock->s_events = new_events; /* set new events */
}

/* Returns an engine's name for informational purposes */
char*
engine_name(void)
{
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_name);

  return evInfo.engine->eng_name;
}
