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
#include "ircd_events.h"

#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"

#include <assert.h>
#include <sys/poll.h>
#include <time.h>
#include <unistd.h>

#define POLL_ERROR_THRESHOLD	20	/* after 20 poll errors, restart */

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
static void
engine_add(struct Socket* sock)
{
  int i;

  assert(0 != sock);

  for (i = 0; sockList[i] && i < poll_count; i++) /* Find an empty slot */
    ;
  if (sockList[i]) { /* ok, need to allocate another off the list */
    i = poll_count++;
    assert(poll_max >= poll_count);
  }

  sock->s_header.gen_engdata.ed_int = i; /* set engine data */
  sockList[i] = sock; /* enter socket into data structures */
  pollfdList[i].fd = sock->s_fd;

  /* set the appropriate bits */
  set_or_clear(i, 0, state_to_events(sock->s_state, sock->s_events));
}

/* socket switching to new state */
static void
engine_state(struct Socket* sock, enum SocketState new_state)
{
  assert(0 != sock);
  assert(sock == sockList[sock->s_header.gen_engdata.ed_int]);
  assert(sock->s_fd == pollfdList[sock->s_header.gen_engdata.ed_int]);

  /* set the correct events */
  set_or_clear(sock->s_header.gen_engdata.ed_int,
	       state_to_events(sock->s_state, sock->s_events), /* old state */
	       state_to_events(new_state, sock->s_events)); /* new state */
}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[sock->s_header.gen_engdata.ed_int]);
  assert(sock->s_fd == pollfdList[sock->s_header.gen_engdata.ed_int]);

  /* set the correct events */
  set_or_clear(sock->s_header.gen_engdata.ed_int,
	       state_to_events(sock->s_state, sock->s_events), /* old events */
	       state_to_events(sock->s_state, new_events)); /* new events */
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  assert(0 != sock);
  assert(sock == sockList[sock->s_header.gen_engdata.ed_int]);
  assert(sock->s_fd == pollfdList[sock->s_header.gen_engdata.ed_int]);

  /* clear the events */
  pollfdList[sock->s_header.gen_engdata.ed_int].fd = -1;
  pollfdList[sock->s_header.gen_engdata.ed_int].events = 0;

  /* zero the socket list entry */
  sockList[sock->s_header.gen_engdata.ed_int] = 0;

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
  int errors = 0;
  int i;

  while (running) {
    wait = time_next(gen) * 1000; /* set up the sleep time */

    /* check for active files */
    nfds = poll(pollfdList, poll_count, wait ? wait : -1);

    CurrentTime = time(0); /* set current time... */

    if (nfds < 0) {
      if (errno != EINTR) { /* ignore poll interrupts */
	/* Log the poll error */
	ircd_log(LS_SOCKET, L_ERROR, 0, "poll() error: %m");
	if (++errors > POLL_ERROR_THRESHOLD) /* too many errors, restart */
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

      gen_ref_inc(sockList[i]); /* can't have it going away on us */

      /* XXX Here's where we actually process sockets and figure out what
       * XXX events have happened, be they errors, eofs, connects, or what
       * XXX have you.  I'll fill this in sometime later.
       */

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
