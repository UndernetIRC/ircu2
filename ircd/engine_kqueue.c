/*
 * IRC - Internet Relay Chat, ircd/engine_kqueue.c
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
#include "ircd_features.h"
#include "ircd_log.h"
#include "s_debug.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define KQUEUE_ERROR_THRESHOLD	20	/* after 20 kqueue errors, restart */
#define ERROR_EXPIRE_TIME	3600	/* expire errors after an hour */

static struct Socket** sockList;
static int kqueue_max;
static int kqueue_id;

static int errors = 0;
static struct Timer clear_error;

/* decrements the error count once per hour */
static void
error_clear(struct Event* ev)
{
  if (!--errors) /* remove timer when error count reaches 0 */
    timer_del(ev_timer(ev));
}

/* initialize the kqueue engine */
static int
engine_init(int max_sockets)
{
  int i;

  if ((kqueue_id = kqueue()) < 0) { /* initialize... */
    log_write(LS_SYSTEM, L_WARNING, 0,
	      "kqueue() engine cannot initialize: %m");
    return 0;
  }

  /* allocate necessary memory */
  sockList = (struct Socket**) MyMalloc(sizeof(struct Socket*) * max_sockets);

  /* initialize the data */
  for (i = 0; i < max_sockets; i++)
    sockList[i] = 0;

  kqueue_max = max_sockets; /* number of sockets allocated */

  return 1; /* success! */
}

/* add a signel to be watched for */
static void
engine_signal(struct Signal* sig)
{
  struct kevent sigevent;
  struct sigaction act;

  assert(0 != signal);

  Debug((DEBUG_ENGINE, "kqueue: Adding filter for signal %d [%p]",
	 sig_signal(sig), sig));

  sigevent.ident = sig_signal(sig); /* set up the kqueue event */
  sigevent.filter = EVFILT_SIGNAL; /* looking for signals... */
  sigevent.flags = EV_ADD | EV_ENABLE; /* add and enable it */
  sigevent.fflags = 0;
  sigevent.data = 0;
  sigevent.udata = sig; /* store our user data */

  if (kevent(kqueue_id, &sigevent, 1, 0, 0, 0) < 0) { /* add event */
    log_write(LS_SYSTEM, L_WARNING, 0, "Unable to trap signal %d",
	      sig_signal(sig));
    return;
  }

  act.sa_handler = SIG_IGN; /* ignore the signal */
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaction(sig_signal(sig), &act, 0);
}

/* Figure out what events go with a given state */
static unsigned int
state_to_events(enum SocketState state, unsigned int events)
{
  switch (state) {
  case SS_CONNECTING: /* connecting socket */
    return SOCK_EVENT_WRITABLE;
    break;

  case SS_LISTENING: /* listening socket */
  case SS_NOTSOCK: /* our signal socket--just in case */
    return SOCK_EVENT_READABLE;
    break;

  case SS_CONNECTED: case SS_DATAGRAM: case SS_CONNECTDG:
    return events; /* ordinary socket */
    break;
  }

  /*NOTREACHED*/
  return 0;
}

/* Activate kqueue filters as appropriate */
static void
set_or_clear(struct Socket* sock, unsigned int clear, unsigned int set)
{
  int i = 0;
  struct kevent chglist[2];

  assert(0 != sock);
  assert(-1 < s_fd(sock));

  if ((clear ^ set) & SOCK_EVENT_READABLE) { /* readable has changed */
    chglist[i].ident = s_fd(sock); /* set up the change list */
    chglist[i].filter = EVFILT_READ; /* readable filter */
    chglist[i].flags = EV_ADD; /* adding it */
    chglist[i].fflags = 0;
    chglist[i].data = 0;
    chglist[i].udata = 0; /* I love udata, but it can't really be used here */

    if (set & SOCK_EVENT_READABLE) /* it's set */
      chglist[i].flags |= EV_ENABLE;
    else /* clear it */
      chglist[i].flags |= EV_DISABLE;

    i++; /* advance to next element */
  }

  if ((clear ^ set) & SOCK_EVENT_WRITABLE) { /* writable has changed */
    chglist[i].ident = s_fd(sock); /* set up the change list */
    chglist[i].filter = EVFILT_WRITE; /* writable filter */
    chglist[i].flags = EV_ADD; /* adding it */
    chglist[i].fflags = 0;
    chglist[i].data = 0;
    chglist[i].udata = 0;

    if (set & SOCK_EVENT_WRITABLE) /* it's set */
      chglist[i].flags |= EV_ENABLE;
    else /* clear it */
      chglist[i].flags |= EV_DISABLE;

    i++; /* advance count... */
  }

  if (kevent(kqueue_id, chglist, i, 0, 0, 0) < 0 && errno != EBADF)
    event_generate(ET_ERROR, sock, errno); /* report error */
}

/* add a socket to be listened on */
static int
engine_add(struct Socket* sock)
{
  assert(0 != sock);
  assert(0 == sockList[s_fd(sock)]);

  /* bounds-check... */
  if (sock->s_fd >= kqueue_max) {
    log_write(LS_SYSTEM, L_ERROR, 0,
	      "Attempt to add socket %d (> %d) to event engine", s_fd(sock),
	      kqueue_max);
    return 0;
  }

  sockList[s_fd(sock)] = sock; /* add to list */

  Debug((DEBUG_ENGINE, "kqueue: Adding socket %d [%p], state %s, to engine",
	 s_fd(sock), sock, state_to_name(s_state(sock))));

  /* Add socket to queue */
  set_or_clear(sock, 0, state_to_events(s_state(sock), s_events(sock)));

  return 1; /* success */
}

/* socket switching to new state */
static void
engine_state(struct Socket* sock, enum SocketState new_state)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "kqueue: Changing state for socket %p to %s", sock,
	 state_to_name(new_state)));

  /* set the correct events */
  set_or_clear(sock,
	       state_to_events(s_state(sock), s_events(sock)), /* old state */
	       state_to_events(new_state, s_events(sock))); /* new state */

}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "kqueue: Changing event mask for socket %p to [%s]",
	 sock, sock_flags(new_events)));

  /* set the correct events */
  set_or_clear(sock,
	       state_to_events(s_state(sock), s_events(sock)), /* old events */
	       state_to_events(s_state(sock), new_events)); /* new events */
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  struct kevent dellist[2];

  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "kqueue: Deleting socket %d [%p], state %s",
	 s_fd(sock), sock, state_to_name(s_state(sock))));

  dellist[0].ident = s_fd(sock); /* set up the delete list */
  dellist[0].filter = EVFILT_READ; /* readable filter */
  dellist[0].flags = EV_DELETE; /* delete it */
  dellist[0].fflags = 0;
  dellist[0].data = 0;
  dellist[0].udata = 0;

  dellist[1].ident = s_fd(sock);
  dellist[1].filter = EVFILT_WRITE; /* writable filter */
  dellist[1].flags = EV_DELETE; /* delete it */
  dellist[1].fflags = 0;
  dellist[1].data = 0;
  dellist[1].udata = 0;

  /* make it all go away */
  if (kevent(kqueue_id, dellist, 2, 0, 0, 0) < 0)
    log_write(LS_SOCKET, L_WARNING, 0,
	      "Unable to delete kevent items for socket %d", s_fd(sock));

  sockList[s_fd(sock)] = 0;
}

/* engine event loop */
static void
engine_loop(struct Generators* gen)
{
  struct kevent *events;
  int events_count;
  struct Socket* sock;
  struct timespec wait;
  int nevs;
  int i;
  int errcode;
  size_t codesize;

  if ((events_count = feature_int(FEAT_POLLS_PER_LOOP)) < 20)
    events_count = 20;
  events = (struct kevent *)MyMalloc(sizeof(struct kevent) * events_count);

  while (running) {
    if ((i = feature_int(FEAT_POLLS_PER_LOOP)) >= 20 && i != events_count) {
      events = (struct kevent *)MyRealloc(events, sizeof(struct kevent) * i);
      events_count = i;
    }

    /* set up the sleep time */
    wait.tv_sec = timer_next(gen) ? (timer_next(gen) - CurrentTime) : -1;
    wait.tv_nsec = 0;

    Debug((DEBUG_INFO, "kqueue: delay: %Tu (%Tu) %Tu", timer_next(gen),
	   CurrentTime, wait.tv_sec));

    /* check for active events */
    nevs = kevent(kqueue_id, 0, 0, events, events_count,
		  wait.tv_sec < 0 ? 0 : &wait);

    CurrentTime = time(0); /* set current time... */

    if (nevs < 0) {
      if (errno != EINTR) { /* ignore kevent interrupts */
	/* Log the kqueue error */
	log_write(LS_SOCKET, L_ERROR, 0, "kevent() error: %m");
	if (!errors++)
	  timer_add(timer_init(&clear_error), error_clear, 0, TT_PERIODIC,
		    ERROR_EXPIRE_TIME);
	else if (errors > KQUEUE_ERROR_THRESHOLD) /* too many errors... */
	  server_restart("too many kevent errors");
      }
      /* old code did a sleep(1) here; with usage these days,
       * that may be too expensive
       */
      continue;
    }

    for (i = 0; i < nevs; i++) {
      if (events[i].filter == EVFILT_SIGNAL) {
	/* it's a signal; deal appropriately */
	event_generate(ET_SIGNAL, events[i].udata, events[i].ident);
	continue; /* skip socket processing loop */
      }

      assert(events[i].filter == EVFILT_READ ||
	     events[i].filter == EVFILT_WRITE);

      sock = sockList[events[i].ident];
      if (!sock) /* slots may become empty while processing events */
	continue;

      assert(s_fd(sock) == events[i].ident);

      gen_ref_inc(sock); /* can't have it going away on us */

      Debug((DEBUG_ENGINE, "kqueue: Checking socket %p (fd %d) state %s, "
	     "events %s", sock, s_fd(sock), state_to_name(s_state(sock)),
	     sock_flags(s_events(sock))));

      if (s_state(sock) != SS_NOTSOCK) {
	errcode = 0; /* check for errors on socket */
	codesize = sizeof(errcode);
	if (getsockopt(s_fd(sock), SOL_SOCKET, SO_ERROR, &errcode,
		       &codesize) < 0)
	  errcode = errno; /* work around Solaris implementation */

	if (errcode) { /* an error occurred; generate an event */
	  Debug((DEBUG_ENGINE, "kqueue: Error %d on fd %d, socket %p", errcode,
		 s_fd(sock), sock));
	  event_generate(ET_ERROR, sock, errcode);
	  gen_ref_dec(sock); /* careful not to leak reference counts */
	  continue;
	}
      }

      switch (s_state(sock)) {
      case SS_CONNECTING:
	if (events[i].filter == EVFILT_WRITE) { /* connection completed */
	  Debug((DEBUG_ENGINE, "kqueue: Connection completed"));
	  event_generate(ET_CONNECT, sock, 0);
	}
	break;

      case SS_LISTENING:
	if (events[i].filter == EVFILT_READ) { /* connect. to be accept. */
	  Debug((DEBUG_ENGINE, "kqueue: Ready for accept"));
	  event_generate(ET_ACCEPT, sock, 0);
	}
	break;

      case SS_NOTSOCK: /* doing nothing socket-specific */
      case SS_CONNECTED:
	if (events[i].filter == EVFILT_READ) { /* data on socket */
	  Debug((DEBUG_ENGINE, "kqueue: EOF or data to be read"));
	  event_generate(events[i].flags & EV_EOF ? ET_EOF : ET_READ, sock, 0);
	}
	if (events[i].filter == EVFILT_WRITE) { /* socket writable */
	  Debug((DEBUG_ENGINE, "kqueue: Data can be written"));
	  event_generate(ET_WRITE, sock, 0);
	}
	break;

      case SS_DATAGRAM: case SS_CONNECTDG:
	if (events[i].filter == EVFILT_READ) { /* socket readable */
	  Debug((DEBUG_ENGINE, "kqueue: Datagram to be read"));
	  event_generate(ET_READ, sock, 0);
	}
	if (events[i].filter == EVFILT_WRITE) { /* socket writable */
	  Debug((DEBUG_ENGINE, "kqueue: Datagram can be written"));
	  event_generate(ET_WRITE, sock, 0);
	}
	break;
      }

      assert(s_fd(sock) == events[i].ident);

      gen_ref_dec(sock); /* we're done with it */
    }

    timer_run(); /* execute any pending timers */
  }
}

struct Engine engine_kqueue = {
  "kqueue()",		/* Engine name */
  engine_init,		/* Engine initialization function */
  engine_signal,	/* Engine signal registration function */
  engine_add,		/* Engine socket registration function */
  engine_state,		/* Engine socket state change function */
  engine_events,	/* Engine socket events mask function */
  engine_delete,	/* Engine socket deletion function */
  engine_loop		/* Core engine event loop */
};
