/*
 * IRC - Internet Relay Chat, ircd/engine_poll.c
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

#include <assert.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define POLL_ERROR_THRESHOLD	20	/* after 20 poll errors, restart */
#define ERROR_EXPIRE_TIME	3600	/* expire errors after an hour */

/* Figure out what bits to set for read */
#if defined(POLLMSG) && defined(POLLIN) && defined(POLLRDNORM)
#  define POLLREADFLAGS (POLLMSG|POLLIN|POLLRDNORM)
#elif defined(POLLIN) && defined(POLLRDNORM)
#  define POLLREADFLAGS (POLLIN|POLLRDNORM)
#elif defined(POLLIN)
#  define POLLREADFLAGS POLLIN
#elif defined(POLLRDNORM)
#  define POLLREADFLAGS POLLRDNORM
#endif

/* Figure out what bits to set for write */
#if defined(POLLOUT) && defined(POLLWRNORM)
#  define POLLWRITEFLAGS (POLLOUT|POLLWRNORM)
#elif defined(POLLOUT)
#  define POLLWRITEFLAGS POLLOUT
#elif defined(POLLWRNORM)
#  define POLLWRITEFLAGS POLLWRNORM
#endif

/* Figure out what bits indicate errors */
#ifdef POLLHUP
#  define POLLERRORS (POLLHUP|POLLERR)
#else
#  define POLLERRORS POLLERR
#endif

static struct Socket** sockList;
static struct pollfd* pollfdList;
static unsigned int poll_count;
static unsigned int poll_max;

static int errors = 0;
static struct Timer clear_error;

/* decrements the error count once per hour */
static void
error_clear(struct Event* ev)
{
  if (!--errors) /* remove timer when error count reaches 0 */
    timer_del(ev_timer(ev));
}

/* initialize the poll engine */
static int
engine_init(int max_sockets)
{
  int i;

  /* allocate necessary memory */
  sockList = (struct Socket**) MyMalloc(sizeof(struct Socket*) * max_sockets);
  pollfdList = (struct pollfd*) MyMalloc(sizeof(struct pollfd) * max_sockets);

  /* initialize the data */
  for (i = 0; i < max_sockets; i++) {
    sockList[i] = 0;
    pollfdList[i].fd = -1;
    pollfdList[i].events = 0;
    pollfdList[i].revents = 0;
  }

  poll_count = 0; /* nothing in set */
  poll_max = max_sockets; /* number of sockets allocated */

  return 1;
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
    return SOCK_EVENT_READABLE;
    break;

  case SS_CONNECTED: case SS_DATAGRAM: case SS_CONNECTDG:
    return events; /* ordinary socket */
    break;
  }

  /*NOTREACHED*/
  return 0;
}

/* Toggle bits in the pollfd structs correctly */
static void
set_or_clear(int idx, unsigned int clear, unsigned int set)
{
  if ((clear ^ set) & SOCK_EVENT_READABLE) { /* readable has changed */
    if (set & SOCK_EVENT_READABLE) /* it's set */
      pollfdList[idx].events |= POLLREADFLAGS;
    else /* clear it */
      pollfdList[idx].events &= ~POLLREADFLAGS;
  }

  if ((clear ^ set) & SOCK_EVENT_WRITABLE) { /* writable has changed */
    if (set & SOCK_EVENT_WRITABLE) /* it's set */
      pollfdList[idx].events |= POLLWRITEFLAGS;
    else /* clear it */
      pollfdList[idx].events &= ~POLLWRITEFLAGS;
  }
}

/* add a socket to be listened on */
static int
engine_add(struct Socket* sock)
{
  int i;

  assert(0 != sock);

  for (i = 0; sockList[i] && i < poll_count; i++) /* Find an empty slot */
    ;
  if (sockList[i]) { /* ok, need to allocate another off the list */
    if (poll_count >= poll_max) { /* bounds-check... */
      log_write(LS_SYSTEM, L_ERROR, 0,
		"Attempt to add socket %d (> %d) to event engine", sock->s_fd,
		poll_max);
      return 0;
    }

    i = poll_count++;
  }

  s_ed_int(sock) = i; /* set engine data */
  sockList[i] = sock; /* enter socket into data structures */
  pollfdList[i].fd = s_fd(sock);

  /* set the appropriate bits */
  set_or_clear(i, 0, state_to_events(s_state(sock), s_events(sock)));

  return 1; /* success */
}

/* socket switching to new state */
static void
engine_state(struct Socket* sock, enum SocketState new_state)
{
  assert(0 != sock);
  assert(sock == sockList[s_ed_int(sock)]);
  assert(s_fd(sock) == pollfdList[s_ed_int(sock)].fd);

  /* set the correct events */
  set_or_clear(s_ed_int(sock),
	       state_to_events(s_state(sock), s_events(sock)), /* old state */
	       state_to_events(new_state, s_events(sock))); /* new state */
}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[s_ed_int(sock)]);
  assert(s_fd(sock) == pollfdList[s_ed_int(sock)].fd);

  /* set the correct events */
  set_or_clear(s_ed_int(sock),
	       state_to_events(s_state(sock), s_events(sock)), /* old events */
	       state_to_events(s_state(sock), new_events)); /* new events */
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  assert(0 != sock);
  assert(sock == sockList[s_ed_int(sock)]);
  assert(s_fd(sock) == pollfdList[s_ed_int(sock)].fd);

  /* clear the events */
  pollfdList[s_ed_int(sock)].fd = -1;
  pollfdList[s_ed_int(sock)].events = 0;

  /* zero the socket list entry */
  sockList[s_ed_int(sock)] = 0;

  /* update poll_count */
  while (poll_count > 0 && sockList[poll_count - 1] == 0)
    poll_count--;
}

/* socket event loop */
static void
engine_loop(struct Generators* gen)
{
  unsigned int wait;
  int nfds;
  int i;
  int errcode;
  size_t codesize;

  while (running) {
    wait = timer_next(gen) * 1000; /* set up the sleep time */

    /* check for active files */
    nfds = poll(pollfdList, poll_count, wait ? wait : -1);

    CurrentTime = time(0); /* set current time... */

    if (nfds < 0) {
      if (errno != EINTR) { /* ignore poll interrupts */
	/* Log the poll error */
	log_write(LS_SOCKET, L_ERROR, 0, "poll() error: %m");
	if (!errors++)
	  timer_add(&clear_error, error_clear, 0, TT_PERIODIC,
		    ERROR_EXPIRE_TIME);
	else if (errors > POLL_ERROR_THRESHOLD) /* too many errors... */
	  server_restart("too many poll errors");
      }
      /* old code did a sleep(1) here; with usage these days,
       * that may be too expensive
       */
      continue;
    }

    for (i = 0; nfds && i < poll_count; i++) {
      if (!sockList[i]) /* skip empty socket elements */
	continue;

      assert(s_fd(sockList[i]) == pollfdList[i].fd);

      gen_ref_inc(sockList[i]); /* can't have it going away on us */

      errcode = 0; /* check for errors on socket */
      codesize = sizeof(errcode);
      if (getsockopt(s_fd(sockList[i]), SOL_SOCKET, SO_ERROR, &errcode,
		     &codesize) < 0)
	errcode = errno; /* work around Solaris implementation */

      if (errcode) { /* an error occurred; generate an event */
	event_generate(ET_ERROR, sockList[i], errcode);
	gen_ref_dec(sockList[i]); /* careful not to leak reference counts */
	continue;
      }

      switch (s_state(sockList[i])) {
      case SS_CONNECTING:
	if (pollfdList[i].revents & POLLWRITEFLAGS) /* connection completed */
	  event_generate(ET_CONNECT, sockList[i], 0);
	break;

      case SS_LISTENING:
	if (pollfdList[i].revents & POLLREADFLAGS) /* connect. to be accept. */
	  event_generate(ET_ACCEPT, sockList[i], 0);
	break;

      case SS_CONNECTED:
	if (pollfdList[i].revents & POLLREADFLAGS) { /* data on socket */
	  char c;

	  switch (recv(s_fd(sockList[i]), &c, 1, MSG_PEEK)) { /* check EOF */
	  case -1: /* error occurred?!? */
	    event_generate(ET_ERROR, sockList[i], errno);
	    break;

	  case 0: /* EOF from client */
	    event_generate(ET_EOF, sockList[i], 0);
	    break;

	  default: /* some data can be read */
	    event_generate(ET_READ, sockList[i], 0);
	    break;
	  }
	}
	if (pollfdList[i].revents & POLLWRITEFLAGS) /* socket writable */
	  event_generate(ET_WRITE, sockList[i], 0);
	break;

      case SS_DATAGRAM: case SS_CONNECTDG:
	if (pollfdList[i].revents & POLLREADFLAGS) /* socket readable */
	  event_generate(ET_READ, sockList[i], 0);
	if (pollfdList[i].revents & POLLWRITEFLAGS) /* socket writable */
	  event_generate(ET_WRITE, sockList[i], 0);
	break;
      }

      gen_ref_dec(sockList[i]); /* we're done with it */
    }

    timer_run(); /* execute any pending timers */
  }
}

struct Engine engine_poll = {
  "poll()",		/* Engine name */
  engine_init,		/* Engine initialization function */
  0,			/* Engine signal registration function */
  engine_add,		/* Engine socket registration function */
  engine_state,		/* Engine socket state change function */
  engine_events,	/* Engine socket events mask function */
  engine_delete,	/* Engine socket deletion function */
  engine_loop		/* Core engine event loop */
};
