/*
 * IRC - Internet Relay Chat, ircd/ircd_events.c
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
#include "config.h"

#include "ircd_events.h"

#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "s_debug.h"

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define SIGS_PER_SOCK	10	/* number of signals to process per socket
				   readable event */

#ifdef USE_KQUEUE
extern struct Engine engine_kqueue;
#define ENGINE_KQUEUE	&engine_kqueue,
#else
#define ENGINE_KQUEUE
#endif /* USE_KQUEUE */

#ifdef USE_DEVPOLL
extern struct Engine engine_devpoll;
#define ENGINE_DEVPOLL	&engine_devpoll,
#else
#define ENGINE_DEVPOLL
#endif /* USE_DEVPOLL */

#ifdef USE_POLL
extern struct Engine engine_poll;
#define ENGINE_FALLBACK	&engine_poll,
#else
extern struct Engine engine_select;
#define ENGINE_FALLBACK	&engine_select,
#endif /* USE_POLL */

/* list of engines to try */
static const struct Engine *evEngines[] = {
  ENGINE_KQUEUE
  ENGINE_DEVPOLL
  ENGINE_FALLBACK
  0
};

/* signal routines pipe data */
static struct {
  int		fd;	/* signal routine's fd */
  struct Socket	sock;	/* and its struct Socket */
} sigInfo = { -1 };

/* All the thread info */
static struct {
  struct Generators    gens;		/* List of all generators */
  struct Event*	       events_free;	/* struct Event free list */
  unsigned int	       events_alloc;	/* count of allocated struct Events */
  const struct Engine* engine;		/* core engine being used */
#ifdef IRCD_THREADED
  struct GenHeader*    genq_head;	/* head of generator event queue */
  struct GenHeader*    genq_tail;	/* tail of generator event queue */
  unsigned int	       genq_count;	/* count of generators on queue */
#endif
} evInfo = {
  { 0, 0, 0 },
  0, 0, 0
#ifdef IRCD_THREADED
  , 0, 0, 0
#endif
};

/* Initialize a struct GenHeader */
static void
gen_init(struct GenHeader* gen, EventCallBack call, void* data,
	 struct GenHeader* next, struct GenHeader** prev_p)
{
  assert(0 != gen);

  gen->gh_next = next;
  gen->gh_prev_p = prev_p;
#ifdef IRCD_THREADED
  gen->gh_qnext = 0;
  gen->gh_qprev_p = 0;
  gen->gh_head = 0;
  gen->gh_tail = 0;
#endif
  gen->gh_flags = GEN_ACTIVE;
  gen->gh_ref = 0;
  gen->gh_call = call;
  gen->gh_data = data;
  gen->gh_engdata.ed_int = 0;

  if (prev_p) { /* Going to link into list? */
    if (next) /* do so */
      next->gh_prev_p = &gen->gh_next;
    *prev_p = gen;
  }
}

/* Execute an event; optimizations should inline this */
static void
event_execute(struct Event* event)
{
  assert(0 != event);
  assert(0 == event->ev_prev_p); /* must be off queue first */
  assert(event->ev_gen.gen_header->gh_flags & GEN_ACTIVE);

  if (event->ev_type == ET_DESTROY) /* turn off active flag *before* destroy */
    event->ev_gen.gen_header->gh_flags &= ~GEN_ACTIVE;
  if (event->ev_type == ET_ERROR) /* turn on error flag before callback */
    event->ev_gen.gen_header->gh_flags |= GEN_ERROR;

  (*event->ev_gen.gen_header->gh_call)(event); /* execute the event */

  /* The logic here is very careful; if the event was an ET_DESTROY,
   * then we must assume the generator is now invalid; fortunately, we
   * don't need to do anything to it if so.  Otherwise, we decrement
   * the reference count; if reference count goes to zero, AND we need
   * to destroy the generator, THEN we generate a DESTROY event.
   */
  if (event->ev_type != ET_DESTROY)
    gen_ref_dec(event->ev_gen.gen_header);

  event->ev_gen.gen_header = 0; /* clear event data */
  event->ev_type = ET_DESTROY;

  event->ev_next = evInfo.events_free; /* add to free list */
  evInfo.events_free = event;
}

#ifndef IRCD_THREADED
/* we synchronously execute the event when not threaded */
#define event_add(event)	\
do {									      \
  struct Event* _ev = (event);						      \
  _ev->ev_next = 0;							      \
  _ev->ev_prev_p = 0;							      \
  event_execute(_ev);							      \
} while (0)

#else
/* add an event to the work queue */
/* This is just a placeholder; don't expect ircd to be threaded soon */
/* There should be locks all over the place in here */
static void
event_add(struct Event* event)
{
  struct GenHeader* gen;

  assert(0 != event);

  gen = event->ev_gen.gen_header;

  /* First, place event on generator's event queue */
  event->ev_next = 0;
  if (gen->gh_head) {
    assert(0 != gen->gh_tail);

    event->ev_prev_p = &gen->gh_tail->ev_next;
    gen->gh_tail->ev_next = event;
    gen->gh_tail = event;
  } else { /* queue was empty */
    assert(0 == gen->gh_tail);

    event->ev_prev_p = &gen->gh_head;
    gen->gh_head = event;
    gen->gh_tail = event;
  }

  /* Now, if the generator isn't on the queue yet... */
  if (!gen->gh_qprev_p) {
    gen->gh_qnext = 0;
    if (evInfo.genq_head) {
      assert(0 != evInfo.genq_tail);

      gen->gh_qprev_p = &evInfo.genq_tail->gh_qnext;
      evInfo.genq_tail->gh_qnext = gen;
      evInfo.genq_tail = gen;
    } else { /* queue was empty */
      assert(0 == evInfo.genq_tail);

      gen->gh_qprev_p = &evInfo.genq_head;
      evInfo.genq_head = gen;
      evInfo.genq_tail = gen;
    }

    /* We'd also have to signal the work crew here */
  }
}
#endif /* IRCD_THREADED */

/* Place a timer in the correct spot on the queue */
static void
timer_enqueue(struct Timer* timer)
{
  struct Timer** ptr_p;

  assert(0 != timer);
  assert(0 == timer->t_header.gh_prev_p); /* not already on queue */
  assert(timer->t_header.gh_flags & GEN_ACTIVE); /* timer is active */

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
  for (ptr_p = &evInfo.gens.g_timer; ;
       ptr_p = (struct Timer**) &(*ptr_p)->t_header.gh_next)
    if (!*ptr_p || timer->t_expire < (*ptr_p)->t_expire)
      break;

  /* link it in the right place */
  timer->t_header.gh_next = (struct GenHeader*) *ptr_p;
  timer->t_header.gh_prev_p = (struct GenHeader**) ptr_p;
  if (*ptr_p)
    (*ptr_p)->t_header.gh_prev_p = &timer->t_header.gh_next;
  *ptr_p = timer;
}

/* signal handler for writing signal notification to pipe */
static void
signal_handler(int sig)
{
  unsigned char c;

  assert(sigInfo.fd >= 0);

  c = (unsigned char) sig; /* only write 1 byte to identify sig */

  write(sigInfo.fd, &c, 1);
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

    for (ptr = evInfo.gens.g_signal; ptr;
	 ptr = (struct Signal*) ptr->sig_header.gh_next)
      if (ptr->sig_signal == sig) /* find its descriptor... */
	break;

    if (ptr)
      event_generate(ET_SIGNAL, ptr, sig); /* generate signal event */
  }
}

/* Remove something from its queue */
void
gen_dequeue(void* arg)
{
  struct GenHeader* gen = (struct GenHeader*) arg;

  if (gen->gh_next) /* clip it out of the list */
    gen->gh_next->gh_prev_p = gen->gh_prev_p;
  if (gen->gh_prev_p)
    *gen->gh_prev_p = gen->gh_next;

  gen->gh_next = 0; /* mark that it's not in the list anymore */
  gen->gh_prev_p = 0;
}

/* Initializes the event system */
void
event_init(int max_sockets)
{
  int i, p[2];

  for (i = 0; evEngines[i]; i++) { /* look for an engine... */
    assert(0 != evEngines[i]->eng_name);
    assert(0 != evEngines[i]->eng_init);

    if ((*evEngines[i]->eng_init)(max_sockets))
      break; /* Found an engine that'll work */
  }

  assert(0 != evEngines[i]);

  evInfo.engine = evEngines[i]; /* save engine */

  if (!evInfo.engine->eng_signal) { /* engine can't do signals */
    if (pipe(p)) {
      log_write(LS_SYSTEM, L_CRIT, 0, "Failed to open signal pipe");
      exit(8);
    }

    sigInfo.fd = p[1]; /* write end of pipe */
    socket_add(&sigInfo.sock, signal_callback, 0, SS_NOTSOCK,
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
event_generate(enum EventType type, void* arg, int data)
{
  struct Event* ptr;
  struct GenHeader* gen = (struct GenHeader*) arg;

  assert(0 != gen);

  /* don't create events (other than ET_DESTROY) for destroyed generators */
  if (type != ET_DESTROY && (gen->gh_flags & GEN_DESTROY))
    return;

  Debug((DEBUG_LIST, "Generating event type %s for generator %p (%s)",
	 event_to_name(type), gen, gen_flags(gen->gh_flags)));

  if ((ptr = evInfo.events_free))
    evInfo.events_free = ptr->ev_next; /* pop one off the freelist */
  else { /* allocate another structure */
    ptr = (struct Event*) MyMalloc(sizeof(struct Event));
    evInfo.events_alloc++; /* count of allocated events */
  }

  ptr->ev_type = type; /* Record event type */
  ptr->ev_data = data;

  ptr->ev_gen.gen_header = (struct GenHeader*) gen;
  ptr->ev_gen.gen_header->gh_ref++;

  event_add(ptr); /* add event to queue */
}

#if 0
/* Try to verify the timer list */
void
timer_verify(void)
{
  struct Timer* ptr;
  struct Timer** ptr_p = &evInfo.gens.g_timer;
  time_t lasttime = 0;

  for (ptr = evInfo.gens.g_timer; ptr;
       ptr = (struct Timer*) ptr->t_header.gh_next) {
    /* verify timer is supposed to be in the list */
    assert(ptr->t_header.gh_prev_p);
    /* verify timer is correctly ordered */
    assert((struct Timer**) ptr->t_header.gh_prev_p == ptr_p);
    /* verify timer is active */
    assert(ptr->t_header.gh_flags & GEN_ACTIVE);
    /* verify timer ordering is correct */
    assert(lasttime <= ptr->t_expire);

    lasttime = ptr->t_expire; /* store time for ordering check */
    ptr_p = (struct Timer**) &ptr->t_header.gh_next; /* store prev pointer */
  }
}
#endif

/* Initialize a timer structure */
struct Timer*
timer_init(struct Timer* timer)
{
  gen_init((struct GenHeader*) timer, 0, 0, 0, 0);

  timer->t_header.gh_flags = 0; /* turn off active flag */

  return timer; /* convenience return */
}

/* Add a timer to be processed */
void
timer_add(struct Timer* timer, EventCallBack call, void* data,
	  enum TimerType type, time_t value)
{
  assert(0 != timer);
  assert(0 != call);

  Debug((DEBUG_LIST, "Adding timer %p; time out %Tu (type %s)", timer, value,
	 timer_to_name(type)));

  /* initialize a timer... */
  timer->t_header.gh_flags |= GEN_ACTIVE;
  if (timer->t_header.gh_flags & GEN_MARKED)
    timer->t_header.gh_flags |= GEN_READD;

  timer->t_header.gh_ref = 0;
  timer->t_header.gh_call = call;
  timer->t_header.gh_data = data;

  timer->t_type = type;
  timer->t_value = value;
  timer->t_expire = 0;

  if (!(timer->t_header.gh_flags & GEN_MARKED))
    timer_enqueue(timer); /* and enqueue it */
}

/* Remove a timer from the processing queue */
void
timer_del(struct Timer* timer)
{
  assert(0 != timer);

  timer->t_header.gh_flags &= ~GEN_READD;

  if (timer->t_header.gh_flags & GEN_MARKED)
    return; /* timer is being used */

  Debug((DEBUG_LIST, "Deleting timer %p (type %s)", timer,
	 timer_to_name(timer->t_type)));

  gen_dequeue(timer);
  event_generate(ET_DESTROY, timer, 0);
}

/* Change the time a timer expires */
void
timer_chg(struct Timer* timer, enum TimerType type, time_t value)
{
  assert(0 != timer);
  assert(0 != value);
  assert(TT_PERIODIC != timer->t_type);
  assert(TT_PERIODIC != type);

  Debug((DEBUG_LIST, "Changing timer %p from type %s timeout %Tu to type %s "
	 "timeout %Tu", timer, timer_to_name(timer->t_type), timer->t_value,
	 timer_to_name(type), value));

  gen_dequeue(timer); /* remove the timer from the queue */

  timer->t_type = type; /* Set the new type and value */
  timer->t_value = value;
  timer->t_expire = 0;

  timer_enqueue(timer); /* re-queue the timer */
}

/* Execute all expired timers */
void
timer_run(void)
{
  struct Timer* ptr;

  /* go through queue... */
  while ((ptr = evInfo.gens.g_timer)) {
    if (CurrentTime < ptr->t_expire)
      break; /* processed all pending timers */

    gen_dequeue(ptr); /* must dequeue timer here */
    ptr->t_header.gh_flags |= (GEN_MARKED |
			       (ptr->t_type == TT_PERIODIC ? GEN_READD : 0));

    event_generate(ET_EXPIRE, ptr, 0); /* generate expire event */

    ptr->t_header.gh_flags &= ~GEN_MARKED;

    if (!(ptr->t_header.gh_flags & GEN_READD)) {
      Debug((DEBUG_LIST, "Destroying timer %p", ptr));
      event_generate(ET_DESTROY, ptr, 0);
    } else {
      Debug((DEBUG_LIST, "Re-enqueuing timer %p", ptr));
      timer_enqueue(ptr); /* re-queue timer */
      ptr->t_header.gh_flags &= ~GEN_READD;
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

  /* set up struct */
  gen_init((struct GenHeader*) signal, call, data,
	   (struct GenHeader*) evInfo.gens.g_signal,
	   (struct GenHeader**) &evInfo.gens.g_signal);

  signal->sig_signal = sig;

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
int
socket_add(struct Socket* sock, EventCallBack call, void* data,
	   enum SocketState state, unsigned int events, int fd)
{
  assert(0 != sock);
  assert(0 != call);
  assert(fd >= 0);
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_add);

  /* set up struct */
  gen_init((struct GenHeader*) sock, call, data,
	   (struct GenHeader*) evInfo.gens.g_socket,
	   (struct GenHeader**) &evInfo.gens.g_socket);

  sock->s_state = state;
  sock->s_events = events & SOCK_EVENT_MASK;
  sock->s_fd = fd;

  return (*evInfo.engine->eng_add)(sock); /* tell engine about it */
}

/* deletes (or marks for deletion) a socket */
void
socket_del(struct Socket* sock)
{
  assert(0 != sock);
  assert(!(sock->s_header.gh_flags & GEN_DESTROY));
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_closing);

  /* tell engine socket is going away */
  (*evInfo.engine->eng_closing)(sock);

  sock->s_header.gh_flags |= GEN_DESTROY;

  if (!sock->s_header.gh_ref) { /* not in use; destroy right now */
    gen_dequeue(sock);
    event_generate(ET_DESTROY, sock, 0);
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

  /* Don't continue if an error occurred or the socket got destroyed */
  if (sock->s_header.gh_flags & (GEN_DESTROY | GEN_ERROR))
    return;

  /* tell engine we're changing socket state */
  (*evInfo.engine->eng_state)(sock, state);

  sock->s_state = state; /* set new state */
}

/* sets the events a socket's interested in */
void
socket_events(struct Socket* sock, unsigned int events)
{
  unsigned int new_events = 0;

  assert(0 != sock);
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_events);

  /* Don't continue if an error occurred or the socket got destroyed */
  if (sock->s_header.gh_flags & (GEN_DESTROY | GEN_ERROR))
    return;

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

  if (sock->s_events == new_events)
    return; /* no changes have been made */

  /* tell engine about event mask change */
  (*evInfo.engine->eng_events)(sock, new_events);

  sock->s_events = new_events; /* set new events */
}

/* Returns an engine's name for informational purposes */
const char*
engine_name(void)
{
  assert(0 != evInfo.engine);
  assert(0 != evInfo.engine->eng_name);

  return evInfo.engine->eng_name;
}

#ifdef DEBUGMODE
/* These routines pretty-print names for states and types for debug printing */

#define NS(TYPE) \
struct {	\
  char *name;	\
  TYPE value;	\
}

#define NM(name)	{ #name, name }

#define NE		{ 0, 0 }

const char*
state_to_name(enum SocketState state)
{
  int i;
  NS(enum SocketState) map[] = {
    NM(SS_CONNECTING),
    NM(SS_LISTENING),
    NM(SS_CONNECTED),
    NM(SS_DATAGRAM),
    NM(SS_CONNECTDG),
    NM(SS_NOTSOCK),
    NE
  };

  for (i = 0; map[i].name; i++)
    if (map[i].value == state)
      return map[i].name;

  return "Undefined socket state";
}

const char*
timer_to_name(enum TimerType type)
{
  int i;
  NS(enum TimerType) map[] = {
    NM(TT_ABSOLUTE),
    NM(TT_RELATIVE),
    NM(TT_PERIODIC),
    NE
  };

  for (i = 0; map[i].name; i++)
    if (map[i].value == type)
      return map[i].name;

  return "Undefined timer type";
}

const char*
event_to_name(enum EventType type)
{
  int i;
  NS(enum EventType) map[] = {
    NM(ET_READ),
    NM(ET_WRITE),
    NM(ET_ACCEPT),
    NM(ET_CONNECT),
    NM(ET_EOF),
    NM(ET_ERROR),
    NM(ET_SIGNAL),
    NM(ET_EXPIRE),
    NM(ET_DESTROY),
    NE
  };

  for (i = 0; map[i].name; i++)
    if (map[i].value == type)
      return map[i].name;

  return "Undefined event type";
}

const char*
gen_flags(unsigned int flags)
{
  int i, loc = 0;
  static char buf[256];
  NS(unsigned int) map[] = {
    NM(GEN_DESTROY),
    NM(GEN_MARKED),
    NM(GEN_ACTIVE),
    NM(GEN_READD),
    NM(GEN_ERROR),
    NE
  };

  buf[0] = '\0';

  for (i = 0; map[i].name; i++)
    if (map[i].value & flags) {
      if (loc != 0)
	buf[loc++] = ' ';
      loc += ircd_snprintf(0, buf + loc, sizeof(buf) - loc, "%s", map[i].name);
      if (loc >= sizeof(buf))
	return buf; /* overflow case */
    }

  return buf;
}

const char*
sock_flags(unsigned int flags)
{
  int i, loc = 0;
  static char buf[256];
  NS(unsigned int) map[] = {
    NM(SOCK_EVENT_READABLE),
    NM(SOCK_EVENT_WRITABLE),
    NM(SOCK_ACTION_SET),
    NM(SOCK_ACTION_ADD),
    NM(SOCK_ACTION_DEL),
    NE
  };

  buf[0] = '\0';

  for (i = 0; map[i].name; i++)
    if (map[i].value & flags) {
      if (loc != 0)
	buf[loc++] = ' ';
      loc += ircd_snprintf(0, buf + loc, sizeof(buf) - loc, "%s", map[i].name);
      if (loc >= sizeof(buf))
	return buf; /* overflow case */
    }

  return buf;
}

#endif /* DEBUGMODE */
