/*
 * IRC - Internet Relay Chat, ircd/engine_select.c
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
#include "ircd_log.h"
#include "s_debug.h"

/* On BSD, define FD_SETSIZE to what we want before including sys/types.h */
#if  defined(__FreeBSD__) || defined(__NetBSD__) || defined(__bsdi__)
# if !defined(FD_SETSIZE)
#  define FD_SETSIZE	MAXCONNECTIONS
# endif
#endif

#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SELECT_ERROR_THRESHOLD	20	/* after 20 select errors, restart */
#define ERROR_EXPIRE_TIME	3600	/* expire errors after an hour */

static struct Socket* sockList[FD_SETSIZE];
static int highest_fd;
static fd_set global_read_set;
static fd_set global_write_set;

static int errors = 0;
static struct Timer clear_error;

/* decrements the error count once per hour */
static void
error_clear(struct Event* ev)
{
  if (!--errors) /* remove timer when error count reaches 0 */
    timer_del(ev_timer(ev));
}

/* initialize the select engine */
static int
engine_init(int max_sockets)
{
  int i;

  if (max_sockets > FD_SETSIZE) { /* too many sockets */
    log_write(LS_SYSTEM, L_WARNING, 0,
	      "select() engine cannot handle %d sockets (> %d)",
	      max_sockets, FD_SETSIZE);
    return 0;
  }

  FD_ZERO(&global_read_set); /* zero the global fd sets */
  FD_ZERO(&global_write_set);

  for (i = 0; i < FD_SETSIZE; i++) /* zero the sockList */
    sockList[i] = 0;

  highest_fd = -1; /* No fds in set */

  return 1; /* initialization successful */
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

/* Toggle bits in the global fd sets appropriately */
static void
set_or_clear(int fd, unsigned int clear, unsigned int set)
{
  if ((clear ^ set) & SOCK_EVENT_READABLE) { /* readable has changed */
    if (set & SOCK_EVENT_READABLE) /* it's set */
      FD_SET(fd, &global_read_set);
    else /* clear it */
      FD_CLR(fd, &global_read_set);
  }

  if ((clear ^ set) & SOCK_EVENT_WRITABLE) { /* writable has changed */
    if (set & SOCK_EVENT_WRITABLE) /* it's set */
      FD_SET(fd, &global_write_set);
    else /* clear it */
      FD_CLR(fd, &global_write_set);
  }
}

/* add a socket to be listened on */
static int
engine_add(struct Socket* sock)
{
  assert(0 != sock);
  assert(0 == sockList[s_fd(sock)]);

  /* bounds-check... */
  if (s_fd(sock) >= FD_SETSIZE) {
    log_write(LS_SYSTEM, L_ERROR, 0,
	      "Attempt to add socket %d (> %d) to event engine", s_fd(sock),
	      FD_SETSIZE);
    return 0;
  }

  sockList[s_fd(sock)] = sock; /* add to list */

  if (s_fd(sock) >= highest_fd) /* update highest_fd */
    highest_fd = s_fd(sock);

  Debug((DEBUG_ENGINE, "select: Adding socket %d to engine [%p], state %s",
	 s_fd(sock), sock, state_to_name(s_state(sock))));

  /* set the fd set bits */
  set_or_clear(s_fd(sock), 0, state_to_events(s_state(sock), s_events(sock)));

  return 1; /* success */
}

/* socket switching to new state */
static void
engine_state(struct Socket* sock, enum SocketState new_state)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "select: Changing state for socket %p to %s", sock,
	 state_to_name(new_state)));

  /* set the correct events */
  set_or_clear(s_fd(sock),
	       state_to_events(s_state(sock), s_events(sock)), /* old state */
	       state_to_events(new_state, s_events(sock))); /* new state */
}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "select: Changing event mask for socket %p to [%s]",
	 sock, sock_flags(new_events)));

  /* set the correct events */
  set_or_clear(s_fd(sock),
	       state_to_events(s_state(sock), s_events(sock)), /* old events */
	       state_to_events(s_state(sock), new_events)); /* new events */
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  assert(0 != sock);
  assert(sock == sockList[s_fd(sock)]);

  Debug((DEBUG_ENGINE, "select: Deleting socket %d [%p], state %s", s_fd(sock),
	 sock, state_to_name(s_state(sock))));

  FD_CLR(s_fd(sock), &global_read_set); /* clear event set bits */
  FD_CLR(s_fd(sock), &global_write_set);

  sockList[s_fd(sock)] = 0; /* zero the socket list entry */

  while (highest_fd > -1 && sockList[highest_fd] == 0) /* update highest_fd */
    highest_fd--;
}

/* engine event loop */
static void
engine_loop(struct Generators* gen)
{
  struct timeval wait;
  fd_set read_set;
  fd_set write_set;
  int nfds;
  int i;
  int errcode;
  size_t codesize;
  struct Socket *sock;

  while (running) {
    read_set = global_read_set; /* all hail structure copy!! */
    write_set = global_write_set;

    /* set up the sleep time */
    wait.tv_sec = timer_next(gen) ? (timer_next(gen) - CurrentTime) : -1;
    wait.tv_usec = 0;

    Debug((DEBUG_INFO, "select: delay: %Tu (%Tu) %Tu", timer_next(gen),
	   CurrentTime, wait.tv_sec));

    /* check for active files */
    nfds = select(highest_fd + 1, &read_set, &write_set, 0,
		  wait.tv_sec < 0 ? 0 : &wait);

    CurrentTime = time(0); /* set current time... */

    if (nfds < 0) {
      if (errno != EINTR) { /* ignore select interrupts */
	/* Log the select error */
	log_write(LS_SOCKET, L_ERROR, 0, "select() error: %m");
	if (!errors++)
	  timer_add(timer_init(&clear_error), error_clear, 0, TT_PERIODIC,
		    ERROR_EXPIRE_TIME);
	else if (errors > SELECT_ERROR_THRESHOLD) /* too many errors... */
	  server_restart("too many select errors");
      }
      /* old code did a sleep(1) here; with usage these days,
       * that may be too expensive
       */
      continue;
    }

    for (i = 0; nfds && i <= highest_fd; i++) {
      if (!(sock = sockList[i])) /* skip empty socket elements */
	continue;

      assert(s_fd(sock) == i);

      gen_ref_inc(sock); /* can't have it going away on us */

      Debug((DEBUG_ENGINE, "select: Checking socket %p (fd %d) state %s, "
	     "events %s", sock, i, state_to_name(s_state(sock)),
	     sock_flags(s_events(sock))));

      if (s_state(sock) != SS_NOTSOCK) {
	errcode = 0; /* check for errors on socket */
	codesize = sizeof(errcode);
	if (getsockopt(i, SOL_SOCKET, SO_ERROR, &errcode, &codesize) < 0)
	  errcode = errno; /* work around Solaris implementation */

	if (errcode) { /* an error occurred; generate an event */
	  Debug((DEBUG_ENGINE, "select: Error %d on fd %d, socket %p", errcode,
		 i, sock));
	  event_generate(ET_ERROR, sock, errcode);
	  gen_ref_dec(sock); /* careful not to leak reference counts */
	  continue;
	}
      }

      switch (s_state(sock)) {
      case SS_CONNECTING:
	if (FD_ISSET(i, &write_set)) { /* connection completed */
	  Debug((DEBUG_ENGINE, "select: Connection completed"));
	  event_generate(ET_CONNECT, sock, 0);
	  nfds--;
	  continue;
	}
	break;

      case SS_LISTENING:
	if (FD_ISSET(i, &read_set)) { /* connection to be accepted */
	  Debug((DEBUG_ENGINE, "select: Ready for accept"));
	  event_generate(ET_ACCEPT, sock, 0);
	  nfds--;
	}
	break;

      case SS_NOTSOCK:
	if (FD_ISSET(i, &read_set)) { /* data on socket */
	  /* can't peek; it's not a socket */
	  Debug((DEBUG_ENGINE, "select: non-socket readable"));
	  event_generate(ET_READ, sock, 0);
	  nfds--;
	}
	break;

      case SS_CONNECTED:
	if (FD_ISSET(i, &read_set)) { /* data to be read from socket */
	  char c;

	  switch (recv(i, &c, 1, MSG_PEEK)) { /* check for EOF */
	  case -1: /* error occurred?!? */
	    if (errno == EAGAIN) {
	      Debug((DEBUG_ENGINE, "select: Resource temporarily "
		     "unavailable?"));
	      continue;
	    }
	    Debug((DEBUG_ENGINE, "select: Uncaught error!"));
	    event_generate(ET_ERROR, sock, errno);
	    break;

	  case 0: /* EOF from client */
	    Debug((DEBUG_ENGINE, "select: EOF from client"));
	    event_generate(ET_EOF, sock, 0);
	    break;

	  default: /* some data can be read */
	    Debug((DEBUG_ENGINE, "select: Data to be read"));
	    event_generate(ET_READ, sock, 0);
	    break;
	  }
	}
	if (FD_ISSET(i, &write_set)) { /* data can be written to socket */
	  Debug((DEBUG_ENGINE, "select: Data can be written"));
	  event_generate(ET_WRITE, sock, 0);
	}
	if (FD_ISSET(i, &read_set) || FD_ISSET(i, &write_set))
	  nfds--;
	break;

      case SS_DATAGRAM: case SS_CONNECTDG:
	if (FD_ISSET(i, &read_set)) { /* data to be read from socket */
	  Debug((DEBUG_ENGINE, "select: Datagram to be read"));
	  event_generate(ET_READ, sock, 0);
	}
	if (FD_ISSET(i, &write_set)) { /* data can be written to socket */
	  Debug((DEBUG_ENGINE, "select: Datagram can be written"));
	  event_generate(ET_WRITE, sock, 0);
	}
	if (FD_ISSET(i, &read_set) || FD_ISSET(i, &write_set))
	  nfds--;
	break;
      }

      assert(s_fd(sock) == i);

      gen_ref_dec(sock); /* we're done with it */
    }

    timer_run(); /* execute any pending timers */
  }
}

struct Engine engine_select = {
  "select()",		/* Engine name */
  engine_init,		/* Engine initialization function */
  0,			/* Engine signal registration function (none) */
  engine_add,		/* Engine socket registration function */
  engine_state,		/* Engine socket state change function */
  engine_events,	/* Engine socket events mask function */
  engine_delete,	/* Engine socket deletion function */
  engine_loop		/* Core engine event loop */
};
