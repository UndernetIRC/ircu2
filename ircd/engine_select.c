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
#include "config.h"	/* for IRCD_FD_SETSIZE */
#include "ircd_events.h"

#include "ircd.h"
#include "ircd_log.h"

#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SELECT_ERROR_THRESHOLD	20	/* after 20 select errors, restart */

static struct Socket* sockList[IRCD_FD_SETSIZE];
static int highest_fd;
static fdset global_read_set;
static fdset global_write_set;

/* initialize the select engine */
static int
engine_init(int max_sockets)
{
  int i;

  if (max_sockets > IRCD_FD_SETSIZE) { /* too many sockets */
    log_write(LS_SYSTEM, L_WARNING, 0,
	      "select() engine cannot handle %d sockets (> %d)",
	      max_sockets, IRCD_FD_SETSIZE);
    return 0;
  }

  FD_ZERO(&global_read_set); /* zero the global fd sets */
  FD_ZERO(&global_write_set);

  for (i = 0; i < IRCD_FD_SETSIZE; i++) /* zero the sockList */
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
static void
engine_add(struct Socket* sock)
{
  assert(0 != sock);
  assert(0 == sockList[sock->s_fd]);
  assert(IRCD_FD_SETSIZE >= sock->s_fd);

  sockList[sock->s_fd] = sock; /* add to list */

  if (sock->s_fd >= highest_fd) /* update highest_fd */
    highest_fd = sock->s_fd;

  /* set the fd set bits */
  set_or_clear(sock->s_fd, 0, state_to_events(sock->s_state, sock->s_events));
}

/* socket switching to new state */
static void
engine_state(struct Socket* sock, enum SocketState new_state)
{
  assert(0 != sock);
  assert(sock == sockList[sock->s_fd]);

  /* set the correct events */
  set_or_clear(sock->s_fd,
	       state_to_events(sock->s_state, sock->s_events), /* old state */
	       state_to_events(new_state, sock->s_events)); /* new state */
}

/* socket events changing */
static void
engine_events(struct Socket* sock, unsigned int new_events)
{
  assert(0 != sock);
  assert(sock == sockList[sock->s_fd]);

  /* set the correct events */
  set_or_clear(sock->s_fd,
	       state_to_events(sock->s_state, sock->s_events), /* old events */
	       state_to_events(sock->s_state, new_events)); /* new events */
}

/* socket going away */
static void
engine_delete(struct Socket* sock)
{
  assert(0 != sock);
  assert(sock == sockList[sock->s_fd]);

  FD_CLR(sock->s_fd, &global_read_set); /* clear event set bits */
  FD_CLR(sock->s_fd, &global_write_set);

  sockList[sock->s_fd] = 0; /* zero the socket list entry */

  while (highest_fd > -1 && sockList[highest_fd] == 0) /* update highest_fd */
    highest_fd--;
}

static void
engine_loop(struct Generators* gen)
{
  struct timeval wait;
  fd_set read_set;
  fd_set write_set;
  int nfds;
  int errors = 0;
  int i;

  while (running) {
    read_set = global_read_set; /* all hail structure copy!! */
    write_set = global_write_set;

    wait.tv_sec = time_next(gen); /* set up the sleep time */
    wait.tv_usec = 0;

    /* check for active files */
    nfds = select(highest_fd + 1, &read_set, &write_set, 0,
		  wait.tv_sec ? &wait : 0);

    CurrentTime = time(0); /* set current time... */

    if (nfds < 0) {
      if (errno != EINTR) { /* ignore select interrupts */
	/* Log the select error */
	ircd_log(LS_SOCKET, L_ERROR, 0, "select() error: %m");
	if (++errors > SELECT_ERROR_THRESHOLD) /* too many errors, restart */
	  server_restart("too many select errors");
      }
      /* old code did a sleep(1) here; with usage these days,
       * that may be too expensive
       */
      continue;
    }

    for (i = 0; nfds && i <= highest_fd; i++) {
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
