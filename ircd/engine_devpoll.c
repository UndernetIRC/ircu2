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
#include "config.h"

#include "ircd_events.h"

#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "s_debug.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/devpoll.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEVPOLL_ERROR_THRESHOLD	20	/* after 20 devpoll errors, restart */
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

static struct Socket** sockList;
static int devpoll_max;
static int devpoll_fd;

static int errors = 0;
static struct Timer clear_error;

/* decrements the error count once per hour */
static void
error_clear(struct Event* ev)
{
  if (!--errors) /* remove timer when error count reaches 0 */
    timer_del(ev_timer(ev));
}

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
  case SS_NOTSOCK: /* our signal socket */
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

    Debug((DEBUG_ENGINE, "devpoll: Removing old entry for socket %d [%p]",
	   s_fd(sock), sock));

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

  Debug((DEBUG_ENGINE, "devpoll: Registering interest on %d [%p] (state %s, "
	 "mask [%s])", s_fd(sock), sock, state_to_name(s_state(sock)),
	 sock_flags(s_events(sock))));

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

  Debug((DEBUG_ENGINE, "devpoll: Adding socket %d [%p], state %s, to engine",
	 s_fd(sock), sock, state_to_name(s_state(sock))));

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

  Debug((DEBUG_ENGINE, "devpoll: Changing state for socket %p to %s", sock,
	 state_to_name(new_state)));

  /* set the correct events */
  set_events(sock, state_to_events(new_state, s_events(sock)));
}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "devpoll: Changing event mask for socket %p to [%s]",
	 sock, sock_flags(new_events)));

  /* set the correct events */
  set_events(sock, state_to_events(s_state(sock), new_events));
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "devpoll: Deleting socket %d [%p], state %s",
	 s_fd(sock), sock, state_to_name(s_state(sock))));

  set_events(sock, 0); /* get rid of the socket */

  sockList[s_fd(sock)] = 0; /* zero the socket list entry */
}

/* engine event loop */
static void
engine_loop(struct Generators* gen)
{
  struct dvpoll dopoll;
  struct pollfd *polls;
  int polls_count;
  struct Socket* sock;
  int nfds;
  int i;
  int errcode;
  size_t codesize;

  if ((polls_count = feature_int(FEAT_POLLS_PER_LOOP)) < 20)
    polls_count = 20;
  polls = (struct pollfd *)MyMalloc(sizeof(struct pollfd) * polls_count);

  while (running) {
    if ((i = feature_int(FEAT_POLLS_PER_LOOP)) >= 20 && i != polls_count) {
      polls = (struct pollfd *)MyRealloc(polls, sizeof(struct pollfd) * i);
      polls_count = i;
    }

    dopoll.dp_fds = polls; /* set up the struct dvpoll */
    dopoll.dp_nfds = polls_count;

    /* calculate the proper timeout */
    dopoll.dp_timeout = timer_next(gen) ?
      (timer_next(gen) - CurrentTime) * 1000 : -1;

    Debug((DEBUG_INFO, "devpoll: delay: %Tu (%Tu) %d", timer_next(gen),
	   CurrentTime, dopoll.dp_timeout));

    /* check for active files */
    nfds = ioctl(devpoll_fd, DP_POLL, &dopoll);

    CurrentTime = time(0); /* set current time... */

    if (nfds < 0) {
      if (errno != EINTR) { /* ignore interrupts */
	/* Log the poll error */
	log_write(LS_SOCKET, L_ERROR, 0, "ioctl(DP_POLL) error: %m");
	if (!errors++)
	  timer_add(timer_init(&clear_error), error_clear, 0, TT_PERIODIC,
		    ERROR_EXPIRE_TIME);
	else if (errors > DEVPOLL_ERROR_THRESHOLD) /* too many errors... */
	  server_restart("too many /dev/poll errors");
      }
      /* old code did a sleep(1) here; with usage these days,
       * that may be too expensive
       */
      continue;
    }

    for (i = 0; i < nfds; i++) {
      assert(-1 < polls[i].fd);

      sock = sockList[polls[i].fd];
      if (!sock) /* slots may become empty while processing events */
	continue;

      assert(s_fd(sock) == polls[i].fd);

      gen_ref_inc(sock); /* can't have it going away on us */

      Debug((DEBUG_ENGINE, "devpoll: Checking socket %p (fd %d) state %s, "
	     "events %s", sock, s_fd(sock), state_to_name(s_state(sock)),
	     sock_flags(s_events(sock))));

      if (s_state(sock) != SS_NOTSOCK) {
	errcode = 0; /* check for errors on socket */
	codesize = sizeof(errcode);
	if (getsockopt(s_fd(sock), SOL_SOCKET, SO_ERROR, &errcode,
		       &codesize) < 0)
	  errcode = errno; /* work around Solaris implementation */

	if (errcode) { /* an error occurred; generate an event */
	  Debug((DEBUG_ENGINE, "devpoll: Error %d on fd %d, socket %p",
		 errcode, s_fd(sock), sock));
	  event_generate(ET_ERROR, sock, errcode);
	  gen_ref_dec(sock); /* careful not to leak reference counts */
	  continue;
	}
      }

      assert(!(polls[i].revents & POLLERR));

#ifdef POLLHUP
      if (polls[i].revents & POLLHUP) { /* hang-up on socket */
	Debug((DEBUG_ENGINE, "devpoll: EOF from client (POLLHUP)"));
	event_generate(ET_EOF, sock, 0);
	nfds--;
	continue;
      }
#endif /* POLLHUP */

      switch (s_state(sock)) {
      case SS_CONNECTING:
	if (polls[i].revents & POLLWRITEFLAGS) { /* connection completed */
	  Debug((DEBUG_ENGINE, "devpoll: Connection completed"));
	  event_generate(ET_CONNECT, sock, 0);
	}
	break;

      case SS_LISTENING:
	if (polls[i].revents & POLLREADFLAGS) { /* connect. to be accept. */
	  Debug((DEBUG_ENGINE, "devpoll: Ready for accept"));
	  event_generate(ET_ACCEPT, sock, 0);
	}
	break;

      case SS_NOTSOCK:
	if (polls[i].revents & POLLREADFLAGS) { /* data on socket */
	  /* can't peek; it's not a socket */
	  Debug((DEBUG_ENGINE, "devpoll: non-socket readable"));
	  event_generate(ET_READ, sock, 0);
	}
	break;

      case SS_CONNECTED:
	if (polls[i].revents & POLLREADFLAGS) { /* data on socket */
	  char c;

	  switch (recv(s_fd(sock), &c, 1, MSG_PEEK)) { /* check EOF */
	  case -1: /* error occurred?!? */
	    if (errno == EAGAIN) {
	      Debug((DEBUG_ENGINE, "devpoll: Resource temporarily "
		     "unavailable?"));
	      continue;
	    }
	    Debug((DEBUG_ENGINE, "devpoll: Uncaught error!"));
	    event_generate(ET_ERROR, sock, errno);
	    break;

	  case 0: /* EOF from client */
	    Debug((DEBUG_ENGINE, "devpoll: EOF from client"));
	    event_generate(ET_EOF, sock, 0);
	    break;

	  default: /* some data can be read */
	    Debug((DEBUG_ENGINE, "devpoll: Data to be read"));
	    event_generate(ET_READ, sock, 0);
	    break;
	  }
	}
	if (polls[i].revents & POLLWRITEFLAGS) { /* socket writable */
	  Debug((DEBUG_ENGINE, "devpoll: Data can be written"));
	  event_generate(ET_WRITE, sock, 0);
	}
	break;

      case SS_DATAGRAM: case SS_CONNECTDG:
	if (polls[i].revents & POLLREADFLAGS) { /* socket readable */
	  Debug((DEBUG_ENGINE, "devpoll: Datagram to be read"));
	  event_generate(ET_READ, sock, 0);
	}
	if (polls[i].revents & POLLWRITEFLAGS) { /* socket writable */
	  Debug((DEBUG_ENGINE, "devpoll: Datagram can be written"));
	  event_generate(ET_WRITE, sock, 0);
	}
	break;
      }

      assert(s_fd(sock) == polls[i].fd);

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
