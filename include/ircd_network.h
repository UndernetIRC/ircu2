#ifndef INCLUDED_ircd_network_h
#define INCLUDED_ircd_network_h
/*
 * IRC - Internet Relay Chat, include/ircd_network.h
 * Copyright (C) 2001 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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

#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_time_h
#include <time.h>	/* struct timespec */
#define INCLUDED_time_h
#endif

#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
  long int tv_sec;	/* seconds */
  long int tv_nsec;	/* nanoseconds */
};
#endif /* !HAVE_STRUCT_TIMESPEC */

typedef void (*EventCallBack)(struct Event*);

enum SocketState {
  SS_CONNECTING,	/* Connection in progress on socket */
  SS_LISTENING,		/* Socket is a listening socket */
  SS_CONNECTED,		/* Socket is a connected socket */
  SS_DATAGRAM,		/* Socket is a datagram socket */
  SS_CONNECTDG		/* Socket is a connected datagram socket */
};

enum TimerType {
  TT_ABSOLUTE,		/* timer that runs at a specific time */
  TT_RELATIVE,		/* timer that runs so many seconds in the future */
  TT_PERIODIC		/* timer that runs periodically */
};

enum EventType {
  ET_READ,		/* Readable event detected */
  ET_WRITE,		/* Writable event detected */
  ET_ACCEPT,		/* Connection can be accepted */
  ET_CONNECT,		/* Connection completed */
  ET_EOF,		/* End-of-file on connection */
  ET_ERROR,		/* Error condition detected */
  ET_SIGNAL,		/* A signal was received */
  ET_TIMER		/* A timer expired */
};

struct Socket {
  struct Socket*   s_next;	/* linked list of sockets */
  struct Socket**  s_prev_p;
  enum SocketState s_state;	/* state socket's in */
  unsigned int	   s_flags;	/* socket flags */
  int		   s_fd;	/* file descriptor for socket */
  EventCallBack	   s_callback;	/* single callback for socket */
  void*		   s_data;	/* data for socket--struct Client, etc. */
};

#define SOCK_EVENT_READABLE	0x0001	/* interested in readable */
#define SOCK_EVENT_WRITABLE	0x0002	/* interested in writable */
#define SOCK_FLAG_CLOSED	0x0010	/* socket got closed at some point */

struct Signal {
  struct Signal*  sig_next;	/* linked list of signals */
  struct Signal** sig_prev_p;
  int		  sig_signal;	/* signal number */
  unsigned int	  sig_count;	/* count of number of signals */
  EventCallBack	  sig_callback;	/* signal callback function */
  void*		  sig_data;	/* data for signal */
};

struct Timer {
  struct Timer*   t_next;	/* linked list of timers */
  struct Timer**  t_prev_p;
  enum TimerType  t_type;	/* what type of timer this is */
  struct timespec t_value;	/* value timer was added with */
  struct timespec t_expire;	/* time at which timer expires */
  EventCallBack	  t_callback;	/* timer callback function */
  void*		  t_data;	/* data for timer--struct Auth, whatever */
};

struct Event {
  struct Event*	   ev_next;	/* linked list of events on queue */
  struct Event**   ev_prev_p;
  enum EventType   ev_type;	/* Event type */
  EventCallBack	   ev_callback;	/* Event callback function */
  union {
    struct Socket* gen_socket;	/* Socket generating event */
    struct Signal* gen_signal;	/* signal generating event */
    struct Timer*  gen_timer;	/* Timer generating event */
  }		   ev_gen;	/* object generating event */
};

void event_generate(enum EventType type, void* gen);

#endif /* INCLUDED_ircd_network_h */
