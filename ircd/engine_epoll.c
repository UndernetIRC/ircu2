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
 *
 * $Id$
 */
#include "config.h"

#include "ircd.h"
#include "ircd_events.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "s_debug.h"

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/unistd.h>

/* The GNU C library may have a valid header but stub implementations
 * of the epoll system calls.  If so, provide our own. */
#if defined(__stub_epoll_create) || defined(__stub___epoll_create)

/* Oh, did we mention that some glibc releases do not even define the
 * syscall numbers? */
#if !defined(__NR_epoll_create)
#if defined(__i386__)
#define __NR_epoll_create 254
#define __NR_epoll_ctl 255
#define __NR_epoll_wait 256
#elif defined(__ia64__)
#define __NR_epoll_create 1243
#define __NR_epoll_ctl 1244
#define __NR_epoll_wait 1245
#elif defined(__x86_64__)
#define __NR_epoll_create 214
#define __NR_epoll_ctl 233
#define __NR_epoll_wait 232
#else /* cpu types */
#error No system call numbers defined for epoll family.
#endif /* cpu types */
#endif /* !defined(__NR_epoll_create) */

_syscall1(int, epoll_create, int, size)
_syscall4(int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event)
_syscall4(int, epoll_wait, int, epfd, struct epoll_event *, pevents, int, maxevents, int, timeout)

#endif /* epoll_create defined as stub */

#define EPOLL_ERROR_THRESHOLD 20   /* after 20 epoll errors, restart */
#define ERROR_EXPIRE_TIME     3600 /* expire errors after an hour */

static int epoll_fd;
static int errors;
static struct Timer clear_error;

/* decrements the error count once per hour */
static void
error_clear(struct Event *ev)
{
  if (!--errors)
    timer_del(ev_timer(ev));
}

/* initialize the epoll engine */
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

static void
set_events(struct Socket *sock, enum SocketState state, unsigned int events, struct epoll_event *evt)
{
  assert(0 != sock);
  assert(0 <= s_fd(sock));

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

static void
engine_delete(struct Socket *sock)
{
  assert(0 != sock);
  Debug((DEBUG_ENGINE, "epoll: Deleting socket %d [%p], state %s",
	 s_fd(sock), sock, state_to_name(s_state(sock))));
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, s_fd(sock), NULL) < 0)
    log_write(LS_SOCKET, L_WARNING, 0,
              "Unable to delete epoll item for socket %d", s_fd(sock));
}

static void
engine_loop(struct Generators *gen)
{
  struct epoll_event *events;
  struct Socket *sock;
  size_t codesize;
  int events_count, i, wait, nevs, errcode;

  if ((events_count = feature_int(FEAT_POLLS_PER_LOOP)) < 20)
    events_count = 20;
  events = MyMalloc(sizeof(events[0]) * events_count);
  while (running) {
    if ((i = feature_int(FEAT_POLLS_PER_LOOP)) >= 20 && i != events_count) {
      events = MyRealloc(events, sizeof(events[0]) * i);
      events_count = i;
    }

    wait = timer_next(gen) ? (timer_next(gen) - CurrentTime) * 1000 : -1;
    Debug((DEBUG_INFO, "epoll: delay: %d (%d) %d", timer_next(gen),
           CurrentTime, wait));
    nevs = epoll_wait(epoll_fd, events, events_count, wait);
    CurrentTime = time(0);

    if (nevs < 0) {
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

    for (i = 0; i < nevs; i++) {
      if (!(sock = events[i].data.ptr))
        continue;
      gen_ref_inc(sock);
      Debug((DEBUG_ENGINE,
             "epoll: Checking socket %p (fd %d) state %s, events %s",
             sock, s_fd(sock), state_to_name(s_state(sock)),
             sock_flags(s_events(sock))));

      if (events[i].events & EPOLLERR) {
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
      }

      switch (s_state(sock)) {
      case SS_CONNECTING:
        if (events[i].events & EPOLLOUT) /* connection completed */
          event_generate(ET_CONNECT, sock, 0);
        break;

      case SS_LISTENING:
        if (events[i].events & EPOLLIN) /* incoming connection */
          event_generate(ET_ACCEPT, sock, 0);
        break;

      case SS_NOTSOCK:
      case SS_CONNECTED:
        if (events[i].events & EPOLLIN)
          event_generate((events[i].events & EPOLLHUP) ? ET_EOF : ET_READ, sock, 0);
        if (events[i].events & EPOLLOUT)
          event_generate(ET_WRITE, sock, 0);
        break;

      case SS_DATAGRAM:
      case SS_CONNECTDG:
        if (events[i].events & EPOLLIN)
          event_generate(ET_READ, sock, 0);
        if (events[i].events & EPOLLOUT)
          event_generate(ET_WRITE, sock, 0);
        break;
      }
      gen_ref_dec(sock);
    }
    timer_run();
  }
}

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
