/*
 * IRC - Internet Relay Chat, include/watch.h
 * Copyright (C) 2008 Kevin L. Mitchell
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
 */
/** @file
 * @brief Structures and functions for handling watches.
 * @version $Id$
 */
#ifndef INCLUDED_watch_h
#define INCLUDED_watch_h
#ifndef INCLUDED_register_h
#include "register.h"
#endif

/** Registration table for watches. */
#define WATCH_TABLE		"watches"

/** Event for object creation. */
#define WATCH_EV_CREATE		 0
/** Event for object destruction. */
#define WATCH_EV_DESTROY	 1
/** First permissible user-defined event. */
#define WATCH_EV_USER_MIN	 2
/** Last permissible user-defined event. */
#define WATCH_EV_USER_MAX	31

/** Convert an event into a mask bit setting. */
#define WE2M(ev)		(1 << (ev))

/** Minimum value for priority--first handlers to be processed. */
#define WATCH_PRIO_MIN		0
/** Maximum value for priority--last handlers to be processed. */
#define WATCH_PRIO_MAX		10000

/** Table of watches for particular kinds of objects. */
typedef struct WatchTab watchtab_t;
/** A specific watch. */
typedef struct Watch watch_t;

/** Type for event specifiers. */
typedef unsigned int watchev_t;
/** Mask of event specifiers. */
typedef unsigned long watchmask_t;
/** Watch priority, used for ordering. */
typedef unsigned int watchprio_t;

/** Callback function implementing the watch.
 * @param[in] watch The watch being processed.
 * @param[in] event The event being processed.
 * @param[in,out] obj The object the event occurred on.  Will exist,
 * even for the destruction event.
 * @param[in,out] extra Any extra data associated with the event.
 * @return 0 to continue processing watch list, non-zero to stop
 * processing.
 */
typedef int (*watchcall_t)(watch_t* watch, watchev_t event, void* obj,
			   void* extra);

/** Describes a table of watches. */
struct WatchTab {
  regent_t	wt_regent;	/**< Registration entry. */
  unsigned int	wt_count;	/**< Number of watches. */
  watch_t*	wt_watchlist;	/**< Linked list of watches. */
};

/** Magic number for watchtab_t. */
#define WATCHTAB_MAGIC 0x1b8235f0

/** Initialize a watchtab_t.
 * @param[in] name Name of the object that is being watched.
 */
#define WATCHTAB_INIT(name)			\
  { REGENT_INIT(WATCHTAB_MAGIC, (name)), 0, 0 }

/** Check a watchtab_t for validity. */
#define WATCHTAB_CHECK(wt)	REGENT_CHECK((wt), WATCHTAB_MAGIC)
/** Get the name of the watch table. */
#define wt_name(wt)		rl_id(wt)
/** Obtain the number of watches in table. */
#define wt_count(wt)		((wt)->wt_walk)
/** Obtain the pointer to the highest priority watch. */
#define wt_watchlist(wt)	((wt)->wt_watchlist)

/** Describes a watch_t. */
struct Watch {
  unsigned long	wat_magic;	/**< Magic number. */
  watch_t*	wat_next;	/**< Next watch in linked list. */
  watch_t*	wat_prev;	/**< Previous watch in linked list. */
  watchtab_t*	wat_tab;	/**< Table watch is in */
  watchprio_t	wat_prio;	/**< Priority value for watch. */
  watchmask_t	wat_mask;	/**< Mask for interesting events. */
  watchcall_t	wat_call;	/**< Callback function for watch. */
  void*		wat_extra;	/**< Extra data for callback function. */
};

/** Magic number for watch_t. */
#define WATCH_MAGIC 0x9c9c0014

/** Initialize a watch_t.
 * @param[in] prio Priority of the watch.  Watch handlers are called
 * from lowest priority value to highest.
 * @param[in] mask Mask of events we're interested in.
 * @param[in] call Callback routine to call.
 * @param[in] extra Extra data needed by the callback.
 */
#define WATCH_INIT(prio, mask, call, extra)			\
  { WATCH_MAGIC, 0, 0, 0, (prio), (mask), (call), (extra) }

/** Dynamically initialize a watch_t.
 * @param[in,out] watch The watch_t to be initialized.
 * @param[in] prio Priority of the watch.  Watch handlers are called
 * from lowest priority value to highest.
 * @param[in] mask Mask of events we're interested in.
 * @param[in] call Callback routine to call.
 * @param[in] extra Extra data needed by the callback.
 */
#define wat_init(watch, prio, mask, call, extra)	\
  do {							\
    watch_t _wat = (watch);				\
    _wat->wat_magic = WATCH_MAGIC;			\
    _wat->wat_next = _wat->wat_prev = 0;		\
    _wat->tab = 0;					\
    _wat->prio = (prio);				\
    _wat->mask = (mask);				\
    _wat->call = (call);				\
    _wat->extra = (extra);				\
  } while (0)

/** Check a watch_t for validity. */
#define WATCH_CHECK(wat)	((wat) && (wat)->wat_magic == WATCH_MAGIC)
/** Get the next watch in the list. */
#define wat_next(wat)		((wat)->wat_next)
/** Get the previous watch in the list. */
#define wat_prev(wat)		((wat)->wat_prev)
/** Get the table the watch is in. */
#define wat_tab(wat)		((wat)->wat_tab)
/** Get the watch's priority. */
#define wat_prio(wat)		((wat)->wat_prio)
/** Get the watch's mask value. */
#define wat_mask(wat)		((wat)->wat_mask)
/** Get the watch's callback function. */
#define wat_call(wat)		((wat)->wat_call)
/** Get extra data stored in the watch. */
#define wat_extra(wat)		((wat)->wat_extra)

/* Add a watch to the named table. */
extern int watch_add(const char* table, watch_t* watch);
/* Remove a watch from the named table. */
extern int watch_rem(const char* table, watch_t* watch);

/* Generate an event. */
extern int watch_event(watchtab_t* tab, watchev_t event, void* obj,
		       void* extra);

/* Flush all watches from the table. */
extern void watch_flush(watchtab_t* tab);

/* Initialize watches subsystem. */
extern void watch_init(void);

#endif /* INCLUDED_watch_h */
