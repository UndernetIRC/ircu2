#ifndef INCLUDED_ircd_events_h
#define INCLUDED_ircd_events_h
/*
 * IRC - Internet Relay Chat, include/ircd_events.h
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
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>	/* time_t */
#define INCLUDED_sys_types_h
#endif

struct Event;

typedef void (*EventCallBack)(struct Event*);

enum SocketState {
  SS_CONNECTING,	/* Connection in progress on socket */
  SS_LISTENING,		/* Socket is a listening socket */
  SS_CONNECTED,		/* Socket is a connected socket */
  SS_DATAGRAM,		/* Socket is a datagram socket */
  SS_CONNECTDG,		/* Socket is a connected datagram socket */
  SS_NOTSOCK		/* Socket isn't a socket at all */
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
  ET_EXPIRE,		/* A timer expired */
  ET_DESTROY		/* The generator is being destroyed */
};

struct GenHeader {
  struct GenHeader*  gh_next;	/* linked list of generators */
  struct GenHeader** gh_prev_p;
#ifdef IRCD_THREADED
  struct GenHeader*  gh_qnext;	/* linked list of generators in queue */
  struct GenHeader** gh_qprev_p;
  struct Event*	     gh_head;	/* head of event queue */
  struct Event*	     gh_tail;	/* tail of event queue */
#endif
  unsigned int	     gh_flags;	/* generator flags */
  unsigned int	     gh_ref;	/* reference count */
  EventCallBack	     gh_call;	/* generator callback function */
  void*		     gh_data;	/* extra data */
  union {
    void*	     ed_ptr;	/* engine data == pointer */
    int		     ed_int;	/* engine data == integer */
  }		     gh_engdata;/* engine data */
};

#define GEN_DESTROY	0x0001	/* generator is to be destroyed */
#define GEN_MARKED	0x0002	/* generator is marked for destruction */
#define GEN_ACTIVE	0x0004	/* generator is active */
#define GEN_READD	0x0008	/* generator (timer) must be re-added */
#define GEN_ERROR	0x0010	/* an error occurred on the generator */

struct Socket {
  struct GenHeader s_header;	/* generator information */
  enum SocketState s_state;	/* state socket's in */
  unsigned int	   s_events;	/* events socket is interested in */
  int		   s_fd;	/* file descriptor for socket */
};

#define SOCK_EVENT_READABLE	0x0001	/* interested in readable */
#define SOCK_EVENT_WRITABLE	0x0002	/* interested in writable */

#define SOCK_EVENT_MASK		(SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE)

#define SOCK_ACTION_SET		0x0000	/* set interest set as follows */
#define SOCK_ACTION_ADD		0x1000	/* add to interest set */
#define SOCK_ACTION_DEL		0x2000	/* remove from interest set */

#define SOCK_ACTION_MASK	0x3000	/* mask out the actions */

#define s_state(sock)	((sock)->s_state)
#define s_events(sock)	((sock)->s_events)
#define s_fd(sock)	((sock)->s_fd)
#define s_data(sock)	((sock)->s_header.gh_data)
#define s_ed_int(sock)	((sock)->s_header.gh_engdata.ed_int)
#define s_ed_ptr(sock)	((sock)->s_header.gh_engdata.ed_ptr)
#define s_active(sock)	((sock)->s_header.gh_flags & GEN_ACTIVE)

/* Note: The socket state overrides the socket event mask; that is, if
 * it's an SS_CONNECTING socket, the engine selects its own definition
 * of what that looks like and ignores s_events.  s_events is meaningful
 * only for SS_CONNECTED, SS_DATAGRAM, and SS_CONNECTDG, but may be set
 * prior to the state transition, if desired.
 */

struct Signal {
  struct GenHeader sig_header;	/* generator information */
  int		   sig_signal;	/* signal number */
};

#define sig_signal(sig)	((sig)->sig_signal)
#define sig_data(sig)	((sig)->sig_header.gh_data)
#define sig_ed_int(sig)	((sig)->sig_header.gh_engdata.ed_int)
#define sig_ed_ptr(sig)	((sig)->sig_header.gh_engdata.ed_ptr)
#define sig_active(sig)	((sig)->sig_header.gh_flags & GEN_ACTIVE)

struct Timer {
  struct GenHeader t_header;	/* generator information */
  enum TimerType   t_type;	/* what type of timer this is */
  time_t	   t_value;	/* value timer was added with */
  time_t	   t_expire;	/* time at which timer expires */
};

#define t_type(tim)	((tim)->t_type)
#define t_value(tim)	((tim)->t_value)
#define t_expire(tim)	((tim)->t_expire)
#define t_data(tim)	((tim)->t_header.gh_data)
#define t_ed_int(tim)	((tim)->t_header.gh_engdata.ed_int)
#define t_ed_ptr(tim)	((tim)->t_header.gh_engdata.ed_ptr)
#define t_active(tim)	((tim)->t_header.gh_flags & GEN_ACTIVE)
#define t_onqueue(tim)	((tim)->t_header.gh_prev_p)

struct Event {
  struct Event*	 ev_next;	/* linked list of events on queue */
  struct Event** ev_prev_p;
  enum EventType ev_type;	/* Event type */
  int		 ev_data;	/* extra data, like errno value */
  union {
    struct GenHeader* gen_header;	/* Generator header */
    struct Socket*    gen_socket;	/* Socket generating event */
    struct Signal*    gen_signal;	/* Signal generating event */
    struct Timer*     gen_timer;	/* Timer generating event */
  }		 ev_gen;	/* object generating event */
};

#define ev_type(ev)	((ev)->ev_type)
#define ev_data(ev)	((ev)->ev_data)
#define ev_socket(ev)	((ev)->ev_gen.gen_socket)
#define ev_signal(ev)	((ev)->ev_gen.gen_signal)
#define ev_timer(ev)	((ev)->ev_gen.gen_timer)

struct Generators {
  struct Socket* g_socket;	/* list of socket generators */
  struct Signal* g_signal;	/* list of signal generators */
  struct Timer*	 g_timer;	/* list of timer generators */
};

/* returns 1 if successfully initialized, 0 if not */
typedef int (*EngineInit)(int);

/* Tell engine about new signal; set to 0 if engine doesn't know signals */
typedef void (*EngineSignal)(struct Signal*);

/* Tell engine about new socket */
typedef int (*EngineAdd)(struct Socket*);

/* Tell engine about socket's new_state */
typedef void (*EngineState)(struct Socket*, enum SocketState new_state);

/* Tell engine about socket's new_events */
typedef void (*EngineEvents)(struct Socket*, unsigned int new_events);

/* Tell engine a socket's going away */
typedef void (*EngineDelete)(struct Socket*);

/* The actual event loop */
typedef void (*EngineLoop)(struct Generators*);

struct Engine {
  const char*	eng_name;	/* a name for the engine */
  EngineInit	eng_init;	/* initialize engine */
  EngineSignal	eng_signal;	/* express interest in a signal */
  EngineAdd	eng_add;	/* express interest in a socket */
  EngineState	eng_state;	/* mention a change in state to engine */
  EngineEvents	eng_events;	/* express interest in socket events */
  EngineDelete	eng_closing;	/* socket is being closed */
  EngineLoop	eng_loop;	/* actual event loop */
};

#define gen_ref_inc(gen)	(((struct GenHeader*) (gen))->gh_ref++)
#define gen_ref_dec(gen)						      \
do {									      \
  struct GenHeader* _gen = (struct GenHeader*) (gen);			      \
  if (!--_gen->gh_ref && (_gen->gh_flags & GEN_DESTROY)) {		      \
    gen_dequeue(_gen);							      \
    event_generate(ET_DESTROY, _gen, 0);				      \
  }									      \
} while (0)
#define gen_clear_error(gen)						      \
	(((struct GenHeader*) (gen))->gh_flags &= ~GEN_ERROR)

void gen_dequeue(void* arg);

void event_init(int max_sockets);
void event_loop(void);
void event_generate(enum EventType type, void* arg, int data);

struct Timer* timer_init(struct Timer* timer);
void timer_add(struct Timer* timer, EventCallBack call, void* data,
	       enum TimerType type, time_t value);
void timer_del(struct Timer* timer);
void timer_chg(struct Timer* timer, enum TimerType type, time_t value);
void timer_run(void);
#define timer_next(gen)	((gen)->g_timer ? (gen)->g_timer->t_expire : 0)

void signal_add(struct Signal* signal, EventCallBack call, void* data,
		int sig);

int socket_add(struct Socket* sock, EventCallBack call, void* data,
	       enum SocketState state, unsigned int events, int fd);
void socket_del(struct Socket* sock);
void socket_state(struct Socket* sock, enum SocketState state);
void socket_events(struct Socket* sock, unsigned int events);

const char* engine_name(void);

#ifdef DEBUGMODE
/* These routines pretty-print names for states and types for debug printing */

const char* state_to_name(enum SocketState state);
const char* timer_to_name(enum TimerType type);
const char* event_to_name(enum EventType type);
const char* gen_flags(unsigned int flags);
const char* sock_flags(unsigned int flags);

#endif /* DEBUGMODE */

#endif /* INCLUDED_ircd_events_h */
