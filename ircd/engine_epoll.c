/*
 * IRC - Internet Relay Chat, ircd/engine_epoll.c
 * Copyright (C) 2003 Michael Poole <mdpoole@troilus.org>
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
 */
/** @file
 * @brief Linux epoll_*() event engine.
 * @version $Id$
 */
#include "config.h"

#include "ircd.h"
#include "ircd_events.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "s_debug.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>

#define EPOLL_ERROR_THRESHOLD 20   /**< after 20 epoll errors, restart */
#define ERROR_EXPIRE_TIME     3600 /**< expire errors after an hour */

/** File descriptor for epoll pseudo-file. */
static int epoll_fd;
/** Number of recent epoll errors. */
static int errors;
/** Periodic timer to forget errors. */
static struct Timer clear_error;
/** Current array of event descriptors. */
static struct epoll_event *events;
/** Number of ::events elements that have been populated. */
static int events_used;

/** Decrement the error count (once per hour).
 * @param[in] ev Expired timer event (ignored).
 */
static void
error_clear(struct Event *ev)
{
  if (!--errors)
    timer_del(ev_timer(ev));
}

/** Initialize the epoll engine.
 * @param[in] max_sockets Maximum number of file descriptors to support.
 * @return Non-zero on success, or zero on failure.
 */
static int
engine_init(int max_sockets)
{
  if ((epoll_fd = epoll_create(max_sockets)) < 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "epoll() engine cannot initialize: %m");
    return 0;
  }
  return 1;
}

/** Set events for a particular socket.
 * @param[in] sock Socket to calculate events for.
 * @param[in] state Current socket state.
 * @param[in] events User-specified event interest list.
 * @param[out] evt epoll event structure for socket.
 */
static void
set_events(struct Socket *sock, enum SocketState state, unsigned int events, struct epoll_event *evt)
{
  assert(0 != sock);
  assert(0 <= s_fd(sock));
  memset(evt, 0, sizeof(*evt));

  evt->data.ptr = sock;

  switch (state) {
  case SS_CONNECTING:
    evt->events = EPOLLOUT;
    break;

  case SS_LISTENING:
  case SS_NOTSOCK:
    evt->events = EPOLLIN;
    break;

  case SS_CONNECTED:
  case SS_DATAGRAM:
  case SS_CONNECTDG:
    switch (events & SOCK_EVENT_MASK) {
    case 0:
      evt->events = 0;
      break;
    case SOCK_EVENT_READABLE:
      evt->events = EPOLLIN;
      break;
    case SOCK_EVENT_WRITABLE:
      evt->events = EPOLLOUT;
      break;
    case SOCK_EVENT_READABLE|SOCK_EVENT_WRITABLE:
      evt->events = EPOLLIN|EPOLLOUT;
      break;
    }
    break;
  }
}

/** Add a socket to the event engine.
 * @param[in] sock Socket to add to engine.
 * @return Non-zero on success, or zero on error.
 */
static int
engine_add(struct Socket *sock)
{
  struct epoll_event evt;

  assert(0 != sock);
  Debug((DEBUG_ENGINE, "epoll: Adding socket %d [%p], state %s, to engine",
         s_fd(sock), sock, state_to_name(s_state(sock))));
  set_events(sock, s_state(sock), s_events(sock), &evt);
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s_fd(sock), &evt) < 0) {
    event_generate(ET_ERROR, sock, errno);
    return 0;
  }
  return 1;
}

/** Handle state transition for a socket.
 * @param[in] sock Socket changing state.
 * @param[in] new_state New state for socket.
 */
static void
engine_set_state(struct Socket *sock, enum SocketState new_state)
{
  struct epoll_event evt;

  assert(0 != sock);
  Debug((DEBUG_ENGINE, "epoll: Changing state for socket %p to %s",
         sock, state_to_name(new_state)));
  set_events(sock, new_state, s_events(sock), &evt);
  if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s_fd(sock), &evt) < 0)
    event_generate(ET_ERROR, sock, errno);
}

/** Handle change to preferred socket events.
 * @param[in] sock Socket getting new interest list.
 * @param[in] new_events New set of interesting events for socket.
 */
static void
engine_set_events(struct Socket *sock, unsigned new_events)
{
  struct epoll_event evt;

  assert(0 != sock);
  Debug((DEBUG_ENGINE, "epoll: Changing event mask for socket %p to [%s]",
         sock, sock_flags(new_events)));
  set_events(sock, s_state(sock), new_events, &evt);
  if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s_fd(sock), &evt) < 0)
    event_generate(ET_ERROR, sock, errno);
}

/** Remove a socket from the event engine.
 * @param[in] sock Socket being destroyed.
 */
static void
engine_delete(struct Socket *sock)
{
  int ii;

  assert(0 != sock);
  Debug((DEBUG_ENGINE, "epoll: Deleting socket %d [%p], state %s",
	 s_fd(sock), sock, state_to_name(s_state(sock))));
  /* Drop any unprocessed events citing this socket. */
  for (ii = 0; ii < events_used; ii++) {
    if (events[ii].data.ptr == sock) {
      events[ii] = events[--events_used];
    }
  }
}

/** Run engine event loop.
 * @param[in] gen Lists of generators of various types.
 */
static void
engine_loop(struct Generators *gen)
{
  struct epoll_event *evt;
  struct Socket *sock;
  socklen_t codesize;
  int events_count, tmp, wait, errcode;

  if ((events_count = feature_int(FEAT_POLLS_PER_LOOP)) < 20)
    events_count = 20;
  events = MyMalloc(sizeof(events[0]) * events_count);
  while (running) {
    if ((tmp = feature_int(FEAT_POLLS_PER_LOOP)) >= 20 && tmp != events_count) {
      events = MyRealloc(events, sizeof(events[0]) * tmp);
      events_count = tmp;
    }

    wait = timer_next(gen) ? (timer_next(gen) - CurrentTime) * 1000 : -1;
    Debug((DEBUG_ENGINE, "epoll: delay: %d (%d) %d", timer_next(gen),
           CurrentTime, wait));
    events_used = epoll_wait(epoll_fd, events, events_count, wait);
    CurrentTime = time(0);

    if (events_used < 0) {
      if (errno != EINTR) {
        log_write(LS_SOCKET, L_ERROR, 0, "epoll() error: %m");
        if (!errors++)
          timer_add(timer_init(&clear_error), error_clear, 0, TT_PERIODIC,
                    ERROR_EXPIRE_TIME);
        else if (errors > EPOLL_ERROR_THRESHOLD)
          server_restart("too many epoll errors");
      }
      continue;
    }

    while (events_used > 0) {
      evt = &events[--events_used];
      if (!(sock = evt->data.ptr))
        continue;
      gen_ref_inc(sock);
      Debug((DEBUG_ENGINE,
             "epoll: Checking socket %p (fd %d) state %s, events %s",
             sock, s_fd(sock), state_to_name(s_state(sock)),
             sock_flags(s_events(sock))));

      if (evt->events & EPOLLERR) {
        errcode = 0;
        codesize = sizeof(errcode);
        if (getsockopt(s_fd(sock), SOL_SOCKET, SO_ERROR, &errcode,
                       &codesize) < 0)
          errcode = errno;
        if (errcode) {
          event_generate(ET_ERROR, sock, errcode);
          gen_ref_dec(sock);
          continue;
        }
      } else if (evt->events & EPOLLHUP) {
        event_generate(ET_EOF, sock, 0);
      } else switch (s_state(sock)) {
      case SS_CONNECTING:
        if (evt->events & EPOLLOUT) /* connection completed */
          event_generate(ET_CONNECT, sock, 0);
        break;

      case SS_LISTENING:
        if (evt->events & EPOLLIN) /* incoming connection */
          event_generate(ET_ACCEPT, sock, 0);
        break;

      case SS_NOTSOCK:
      case SS_CONNECTED:
      case SS_DATAGRAM:
      case SS_CONNECTDG:
        if (evt->events & EPOLLIN)
          event_generate(ET_READ, sock, 0);
        if (evt->events & EPOLLOUT)
          event_generate(ET_WRITE, sock, 0);
        break;
      }
      gen_ref_dec(sock);
    }
    timer_run();
  }
  MyFree(events);
}

/** Descriptor for epoll event engine. */
struct Engine engine_epoll = {
  "epoll()",
  engine_init,
  0,
  engine_add,
  engine_set_state,
  engine_set_events,
  engine_delete,
  engine_loop
};
