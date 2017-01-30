/*
 * IRC - Internet Relay Chat, ircd/watch.c
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
 * @brief Implementation of generic watches.
 */
#include "config.h"

#include "watch.h"
#include "ircd_log.h"
#include "register.h"

/** @page watch Generic watches subsystem.
 *
 * @section introwat Introduction
 *
 * Many modules wish to know when certain events take place, such as
 * when a new user is created, in order to perform certain actions on
 * that new user.  In order to manage this, calls to the appropriate
 * module entry points have to be inserted into the code that handles
 * creation of a user, for instance.  Although this doesn't generally
 * cause abstraction boundary violation, it doesn't allow dynamic
 * expansion--which may be desirable with dynamically loadable
 * modules.
 *
 * This system changes all of that, and enables the addition of new
 * abstraction boundaries, resulting in even more modularity in places
 * where it wasn't possible before.  This is done by providing a
 * "watch" infrastructure--as for ancillary data, modules register a
 * watch table for a data structure, and then other modules may
 * register watch "handlers" that are notified of events.
 * Furthermore, handlers can be given a "priority," which is used by
 * the watch system to define an order in which those handlers are
 * processed.
 *
 * @section watchtab Watch Tables
 *
 * A watch table is an instance of watchtab_t, initialized with the
 * WATCHTAB_INIT() macro.  Its only attribute is a name, which must be
 * unique among all watch tables.  There should be one watchtab_t for
 * each structure upon which an event may occur.  Watch tables are
 * registered with the watches system by calling the reg()
 * registration system with the \a table set to WATCH_TABLE.  (See
 * \subpage register for more information about the registration
 * system.)  Besides the name, which may be retrieved using the
 * wt_name() macro, there is also a count of the number of watches
 * set, which can be retrieved with wt_count(), and the first watch in
 * the watches list may be obtained from wt_watchlist().  Finally, a
 * watchtab_t may be verified using the WATCHTAB_CHECK() macro.
 *
 * @section watches Setting and Removing Watches
 *
 * Setting and removing watches is very easy.  First, you allocate an
 * instance of watch_t, either statically initializing it with the
 * WATCH_INIT() macro or dynamically with the wat_init() macro.  You
 * can set the priority value for the watch (see @ref watchprio for a
 * discussion about priorities), along with the mask of events (see
 * @ref watchevs) and the callback for handling events (neither of
 * which may be 0!).  Additionally, you can set extra data to be
 * associated with the watch, for the use of the handler callback.
 *
 * Once you've created a watch, you simply add it to the watch table
 * for the structure you're interested in by passing it to the
 * watch_add() function.  Removing a watch is just as simple--simply
 * call the watch_rem() function.  Both watch_add() and watch_rem()
 * take the name of the table to which the watch should be added.
 *
 * @section watchprio Watch Priorities
 *
 * Sometimes a watch handler may depend on another handler occurring
 * either before or after it is called.  The priority value of a watch
 * allows this ordering to be performed quite simply.  Those watches
 * with a lower priority value are executed first, followed by those
 * with subsequently higher priority values.  The range of priorities
 * is given by the WATCH_PRIO_MIN and WATCH_PRIO_MAX values, which are
 * currently set to 0 and 10000, respectively.  A priority value
 * greater than WATCH_PRIO_MAX will be trimmed to be in the designated
 * range when a watch is passed to watch_add(), but otherwise there
 * are no constraints on its value.  Although each watch should have a
 * unique priority, having two or more watches with the same priority
 * is not an error--there simply isn't a way to predict in what order
 * the watch handlers are executed in.
 *
 * @subsection watchdep Watch Dependencies
 *
 * The priority mechanism was chosen because it is extremely simple to
 * code; adding a watch in the right place can be done by simply
 * traversing the linked list of watches until you find an element
 * with a higher priority, then placing the new watch just before that
 * element in the list.  The trade-off is that it is more difficult
 * for the module author to guarantee a strict dependency scheme,
 * because the ordering depends on the priority values each module
 * chooses.  A more general scheme would be to attach dependencies to
 * each watch, whereby it can specify that certain watches must occur
 * before and others must occur after calling that handler, allowing
 * the watch subsystem to determine an ordering that respects the
 * dependencies.  However, that is a lot of overhead for a system
 * that's expected to have probably only a couple of dozen watches at
 * most for any given watch table.  If it turns out dependencies are a
 * better way of handling this, this system will need to be rewritten.
 *
 * @section watchevs Watch Events
 *
 * Watches are useless without events.  Currently, the watches
 * subsystem supports up to 32 possible event types, two of which are
 * reserved for creation and destruction events (WATCH_EV_CREATE and
 * WATCH_EV_DESTROY, respectively).  Users may create their own event
 * types with numbers between WATCH_EV_USER_MIN and WATCH_EV_USER_MAX,
 * inclusive.  (The reason for the 32 event limit is because of the
 * representation of event masks; should more events be necessary, the
 * watchmask_t type will have to be changed.  If this is done,
 * consideration must be given to how a watchmask_t may be
 * initialized.)
 *
 * Each watch has an associated event mask that allows filtering of
 * events.  If a particular watch does not have an event listed in its
 * event mask, then it won't get called for those events.  This event
 * mask can be initialized as the bit-wise OR of each event, as
 * transformed by the WE2M() macro; i.e., to create an event mask for
 * only WATCH_EV_CREATE and WATCH_EV_DESTROY, simply use an event mask
 * initialized by <code>WE2M(WATCH_EV_CREATE) |
 * WE2M(WATCH_EV_DESTROY)</code>.
 *
 * The code responsible for maintaining the object being watched is
 * also responsible for generating events for the handlers to handle.
 * This is done by calling the watch_event() routine, passing it a
 * pointer to the table (note: \b not the name!), the event to
 * generate, and a pointer to the object that the event affects (which
 * must \b not be NULL!).  The caller may also pass an \a extra
 * parameter, which will be passed to the handler callbacks; this
 * could, for instance, be an error message explaining why the event
 * occurred.  The watch_event() function will return 0 unless one of
 * the handlers returned a non-zero value, in which case it will
 * return that value.
 *
 * @section watchhand Watch Handlers
 *
 * Watch handlers are functions compatible with the watchcall_t type.
 * They are called by watch_event(), and are passed a pointer to the
 * watch_t they were defined in, as well as the value of the event and
 * a pointer to the affected object.  Any extra data passed to
 * watch_event() will also be passed as the \a extra parameter in the
 * prototype.  Under most circumstances, these handlers should return
 * a 0 value; if they return non-zero, watch_event() will stop
 * processing watches and return that non-zero value.  A watch handler
 * should be careful to not trigger another call to watch_event(), if
 * it is avoidable.
 *
 * @section watchinfo Important Subsystem Information
 *
 * This subsystem provides two structures--struct WatchTab and struct
 * Watch--and 6 types: watchtab_t and watch_t, corresponding to the
 * two structures; watchev_t, for watch events; watchmask_t, for event
 * masks; watchprio_t, for watch priorities; and watchcall_t, for the
 * watch handler callback.  In particular, watchtab_t and watch_t
 * should be treated as opaque by all callers, and struct WatchTab and
 * struct Watch should not be referenced directly.  Any data needed
 * from these structures may be obtained using the provided macros.
 *
 * This subsystem makes use of ircu's registration subsystem.  In
 * addition, it references the assert() macro in ircd_log.h.  This
 * module requires explicit initialization, which may be performed by
 * calling watch_init().  This must be done before any module which is
 * watch-enabled.
 *
 * This subsystem performs no memory allocation whatsoever, and the
 * recommended allocation procedure for callers is to statically
 * allocate the structures that will be passed in.  Nevertheless, it
 * is possible to dynamically initialize a watch_t, if necessary,
 * through the use of the wat_init() macro.
 */

static int watch_unreg(regtab_t* table, watchtab_t* wt)
{
  /* Flush all watches in the table */
  watch_flush(wt);

  return 0;
}

/** Table of watches. */
static regtab_t watch_table = REGTAB_INIT(WATCH_TABLE, WATCHTAB_MAGIC, 0,
					  (unreg_t) watch_unreg);

/** Add a watch to the named table.
 * @param[in] table Name of watches table.
 * @param[in,out] watch Watch to add.
 * @return 0 if addition succeeded, non-zero otherwise.
 */
int watch_add(const char* table, watch_t* watch)
{
  watchtab_t *tab;
  watch_t *cursor = 0;

  assert(WATCH_CHECK(watch));
  assert(watch->wat_mask);
  assert(watch->wat_call);

  /* make sure the watch isn't already in a table */
  if (watch->wat_tab)
    return -2;

  /* look up the named table */
  if (!(tab = reg_find(WATCH_TABLE, table)))
    return -1;

  /* Sanity-check the priority of the watch */
  if (watch->wat_prio > WATCH_PRIO_MAX)
    watch->wat_prio = WATCH_PRIO_MAX;

  /* now, walk the list of watches to find a place to insert it */
  if (tab->wt_watchlist && tab->wt_watchlist->wat_prio < watch->wat_prio) {
    for (cursor = tab->wt_watchlist; ; cursor = cursor->wat_next)
      if (!cursor->wat_next || cursor->wat_next->wat_prio >= watch->wat_prio)
	break; /* found our insertion point */
  }

  assert(0 != cursor || 0 == tab->wt_watchlist);

  /* Insert new watch at the appropriate spot */
  if (!cursor) { /* put at head of list */
    watch->wat_next = tab->wt_watchlist;
    watch->wat_prev = 0;
    if (watch->wat_next)
      watch->wat_next->wat_prev = watch;
    tab->wt_watchlist = watch;
  } else { /* insert after cursor */
    watch->wat_next = cursor->wat_next;
    watch->wat_prev = cursor;
    if (cursor->wat_next)
      cursor->wat_next->wat_prev = watch;
    cursor->wat_next = watch;
  }

  /* Handle the final bits of data... */
  watch->wat_tab = tab;
  tab->wt_count++;

  return 0; /* it's been added. */
}

/** Remove a watch from the named table.
 * @param[in] table Name of watches table.
 * @param[in,out] watch Watch to remove.
 * @return 0 if removal succeeded, non-zero otherwise.
 */
int watch_rem(const char* table, watch_t* watch)
{
  watchtab_t *tab;

  assert(WATCH_CHECK(watch));

  /* look up the named table */
  if (!(tab = reg_find(WATCH_TABLE, table)))
    return -1;

  /* Is this watch even in this table? */
  if (watch->wat_tab != tab)
    return -2;

  /* OK, let's clip the watch out of the table. */
  if (watch->wat_next)
    watch->wat_next->wat_prev = watch->wat_prev;
  if (watch->wat_prev)
    watch->wat_prev->wat_next = watch->wat_next;
  else
    tab->wt_watchlist = watch->wat_next;

  /* decrement the count... */
  tab->wt_count--;

  /* and clear our watch */
  watch->wat_next = watch->wat_prev = 0;
  watch->wat_tab = 0;

  return 0; /* it's all gone! */
}

/** Generate an event.
 * @param[in] tab Table of object event occurred on.
 * @param[in] event Event that occurred.
 * @param[in,out] obj Object event occurred on.
 * @param[in,out] extra Extra data associated with event.
 * @return 0, or the return value of the first watch handler that
 * returned non-zero.
 */
int watch_event(watchtab_t* tab, watchev_t event, void* obj, void* extra)
{
  int retval;
  watchmask_t ev;
  watch_t *cursor;

  assert(WATCHTAB_CHECK(tab));
  assert(event >= WATCH_EV_CREATE && event <= WATCH_EV_USER_MAX);
  assert(0 != obj);

  ev = WE2M(event); /* convert event to a bit */

  /* walk through the list of watches */
  for (cursor = tab->wt_watchlist; cursor; cursor = cursor->wat_next)
    if ((cursor->wat_mask & ev) && /* filter based on event */
	/* then call the watch handler */
	(retval = (cursor->wat_call)(cursor, event, obj, extra)))
      return retval; /* handler returned non-zero */

  return 0;
}

/** Flush all watches from the table.
 * @param[in,out] tab Table to flush.
 */
void watch_flush(watchtab_t* tab)
{
  watch_t *cursor, *next;

  assert(WATCHTAB_CHECK(tab));

  /* OK, flush out all the watches in the table */
  for (cursor = tab->wt_watchlist; cursor; cursor = next) {
    next = cursor->wat_next; /* keep track of what comes next */

    cursor->wat_tab = 0; /* clear the entries in the watch */
    cursor->wat_next = cursor->wat_prev = 0;
  }

  /* Finally, zero the table */
  tab->wt_count = 0;
  tab->wt_watchlist = 0;
}

/** Initialize watches subsystem. */
void watch_init(void)
{
  reg(REG_TABLE, &watch_table);
}
