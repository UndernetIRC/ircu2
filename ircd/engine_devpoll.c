/*
 * IRC - Internet Relay Chat, ircd/engine_devpoll.c
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
#include <sys/devpoll.h>
#include <sys/poll.h>
#include <unistd.h>

#define DEVPOLL_ERROR_THRESHOLD	20	/* after 20 devpoll errors, restart */
#define POLLS_PER_DEVPOLL	20	/* get 20 pollfd's per turn */

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
static int devpoll_max;
static int devpoll_fd;

/* initialize the devpoll engine */
static int
engine_init(int max_sockets)
{
  int i;

  if ((devpoll_fd = open("/dev/poll", O_RDWR)) < 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
	      "/dev/poll engine cannot open device: %m");
    return 0; /* engine cannot be initialized; defer */
  }

  /* allocate necessary memory */
  sockList = (struct Socket**) MyMalloc(sizeof(struct Socket*) * max_sockets);

  /* initialize the data */
  for (i = 0; i < max_sockets; i++)
    sockList[i] = 0;

  devpoll_max = max_sockets; /* number of sockets allocated */

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

/* Reset the desired events */
static void
set_events(struct Socket* sock, unsigned int events)
{
  struct pollfd pfd;

  pfd.fd = s_fd(sock);

  if (s_ed_int(sock)) { /* is one in /dev/poll already? */
    pfd.events = POLLREMOVE; /* First, remove old pollfd */

    if (write(devpoll_fd, &pfd, sizeof(pfd)) != sizeof(pfd)) {
      event_generate(ET_ERROR, sock, errno); /* report error */
      return;
    }

    s_ed_int(sock) = 0; /* mark that it's gone */
  }

  if (!(events & SOCK_EVENT_MASK)) /* no events, so stop here */
    return;

  pfd.events = 0; /* Now, set up new pollfd... */
  if (events & SOCK_EVENT_READABLE)
    pfd.events |= POLLREADFLAGS; /* look for readable conditions */
  if (events & SOCK_EVENT_WRITABLE)
    pfd.events |= POLLWRITEFLAGS; /* look for writable conditions */

  if (write(devpoll_fd, &pfd, sizeof(pfd)) != sizeof(pfd)) {
    event_generate(ET_ERROR, sock, errno); /* report error */
    return;
  }

  s_ed_int(sock) = 1; /* mark that we've added a pollfd */
}

/* add a socket to be listened on */
static int
engine_add(struct Socket* sock)
{
  assert(0 != sock);
  assert(0 == sockList[s_fd(sock)]);

  /* bounds-check... */
  if (s_fd(sock) >= devpoll_max) {
    log_write(LS_SYSTEM, L_ERROR, 0,
	      "Attempt to add socket %d (> %d) to event engine", s_fd(sock),
	      devpoll_max);
    return 0;
  }

  sockList[s_fd(sock)] = sock; /* add to list */

  /* set the correct events */
  set_events(sock, state_to_events(s_state(sock), s_events(sock)));

  return 1; /* success */
}

/* socket switching to new state */
static void
engine_state(struct Socket* sock, enum SocketState new_state)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  /* set the correct events */
  set_events(sock, state_to_events(new_state, s_events(sock)));
}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  /* set the correct events */
  set_events(sock, state_to_events(s_state(sock), new_events));
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  set_events(sock, 0); /* get rid of the socket */

  sockList[s_fd(sock)] = 0; /* zero the socket list entry */
}

/* engine event loop */
static void
engine_loop(struct Generators* gen)
{
  struct dvpoll dopoll;
  struct pollfd polls[POLLS_PER_DEVPOLL];
  struct Socket* sock;
  int nfds;
  int errors = 0;
  int i;

  while (running) {
    dopoll.dp_fds = polls; /* set up the struct dvpoll */
    dopoll.dp_nfds = POLLS_PER_DEVPOLL;

    /* calculate the proper timeout */
    dopoll.dp_timeout = time_next(gen) ? time_next(gen) * 1000 : -1;

    /* check for active files */
    nfds = ioctl(devpoll_fd, DP_POLL, &dopoll);

    CurrentTime = time(0); /* set current time... */

    if (nfds < 0) {
      if (errno != EINTR) { /* ignore interrupts */
	/* Log the poll error */
	log_write(LS_SOCKET, L_ERROR, 0, "ioctl(DP_POLL) error: %m");
	if (++errors > DEVPOLL_ERROR_THRESHOLD) /* too many errors, restart */
	  server_restart("too many /dev/poll errors");
      }
      /* old code did a sleep(1) here; with usage these days,
       * that may be too expensive
       */
      continue;
    }

    for (i = 0; i < nfds; i++) {
      assert(-1 < polls[i].fd);
      assert(0 != sockList[polls[i].fd]);
      assert(s_fd(sockList[polls[i].fd]) == polls[i].fd);

      sock = sockList[polls[i].fd];

      gen_ref_inc(sock); /* can't have it going away on us */

      /* XXX Here's where we actually process sockets and figure out what
       * XXX events have happened, be they errors, eofs, connects, or what
       * XXX have you.  I'll fill this in sometime later.
       */

      gen_ref_dec(sock); /* we're done with it */
    }

    timer_run(); /* execute any pending timers */
  }
}

struct Engine engine_devpoll = {
  "/dev/poll",		/* Engine name */
  engine_init,		/* Engine initialization function */
  0,			/* Engine signal registration function */
  engine_add,		/* Engine socket registration function */
  engine_state,		/* Engine socket state change function */
  engine_events,	/* Engine socket events mask function */
  engine_delete,	/* Engine socket deletion function */
  engine_loop		/* Core engine event loop */
};
