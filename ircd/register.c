/*
 * IRC - Internet Relay Chat, ircd/register.c
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
 * @brief Implementation of generic function registration.
 * @version $Id$
 */
#include "config.h"

#include "register.h"
#include "ircd_log.h"

#include <string.h>

/** @page register Generic registration subsystem.
 *
 * @section introreg Introduction
 *
 * Many things in ircu are table-driven.  These are mostly
 * subcommands, such as for /stats, or even the protocol commands
 * themselves.  Modules wishing to enhance the subcommand table for
 * something like /stats have formerly been required to directly
 * modify the table at the code level.  This makes it impossible for
 * dynamically loadable modules to do this form of enhancement.  This
 * subsystem is an attempt to unify many of these tables in a way that
 * does not significantly increase the overhead while allowing the
 * desired extensibility.  Note that this first version is based on
 * simple linked lists in the backend; if a different backend is
 * desired, change the definitions of struct RegEnt and struct RegTab
 * in register.h and update the functions _reg_find(), reg_add(),
 * reg_rem(), and reg_iter() in register.c.
 *
 * The basic structures in the registration subsystem are
 * <i>registration tables</i> and <i>registration entries</i>.  To
 * give a concrete example, each /stats subcommand would be defined by
 * an instance of a structure beginning with a registration entry (the
 * regent_t type).  The full list of registered /stats subcommands
 * would be represented by a registration table (the regtab_t type).
 *
 * @section howtoreg Registration How-To
 *
 * How does one create a new registration table, as in the case of the
 * /stats example above?  Simply allocate an instance of regtab_t,
 * initializing it with the REGTAB_INIT() macro.  The \a id attribute
 * specifies the unique name of the table, and \a magic specifies a
 * unique magic number used for sanity checks.  (See @ref advreg for
 * discussion of the \a reg and \a unreg parameters.)  Once you have a
 * valid regtab_t, pass a pointer to it to the reg() function to
 * register it with the table specified by the REG_TABLE constant.
 * Now you can register and unregister entries at will.
 *
 * Now, how does one go about registering and unregistering those
 * entries?  As noted above, the structure describing an entry in the
 * table must begin with a regent_t, which can be initialized with the
 * REGENT_INIT() macro.  The \a magic argument of this macro must
 * match the \a magic parameter of the intended registration table,
 * and the \a id argument of REGENT_INIT() must be a unique name for
 * the entry you're creating.  Now, you register the entry using the
 * reg() function, passing the name of the table and a pointer to the
 * entry; unregistering the entry is as simple as calling the unreg()
 * function.
 *
 * @section arrayreg Registration of Arrays of Entries
 *
 * "Great," you say.  "Now I can register new entries on the fly.
 * What if I have an array of entries to add, though?"  This,
 * fortunately, is simple; both reg() and unreg() come in reg_n() and
 * unreg_n() versions tailored to this task.  For these functions,
 * simply pass a pointer to the array--note, \b NOT an array of
 * pointers--and the number of elements goes in the \a n parameter.
 * You must also pass the size of a single element in \a size, so that
 * reg_n() and unreg_n() can find the next element in the array.  If
 * they fail while adding or removing an entry, the return value tells
 * you the index of the first entry that couldn't be added; otherwise,
 * if the functions process every entry successfully, the return value
 * will be \a n.
 *
 * @section searchreg Looking Up Registered Entries
 *
 * What good is being able to add entries if you can't find them?
 * This is where the reg_find() function comes in.  You pass it the
 * name of the table to search and the name of the entry to look for,
 * and it will return either a pointer to the relevant entry, or NULL
 * if there is no entry by that name.  Some applications also require
 * being able to iterate over all the entries in a table--/stats, for
 * instance, can send the user a list of all recognized subcommands,
 * along with some descriptive text for each of them.  This can be
 * done using the reg_iter() function, which simply calls a callback
 * on each element in the table.  Note that the visited order is
 * unspecified, and will change over time; if ordering is important to
 * your application, replace the linked list implementation with an
 * ordered data structure.
 *
 * @section advreg Advanced Registration
 *
 * The registration system provides table suppliers with the option of
 * calling registration and unregistration callbacks.  This might be
 * used, for instance, to double-check that certain required fields
 * are provided, or to add an entry to an application-defined
 * table--for instance, /stats might add an entry to a table indexed
 * by character code, to handle cases when a user uses "/stats i".
 * These callbacks must match the reg_t and unreg_t types, and are
 * called from the reg() and unreg() functions, respectively.  (They
 * are also, of course, called by reg_n() and unreg_n().)  If the
 * callbacks return a non-zero value, that will be returned to the
 * callers of reg() and unreg() (but not, alas, reg_n() or
 * unreg_n()).  Both callbacks are optional, so only specify the ones
 * you need--but always make sure that any added entry can be safely
 * removed, and won't be referenced after it is removed!
 *
 * @section inforeg Important Subsystem Information
 *
 * This subsystem provides two structures--struct RegEnt and struct
 * RegTab--and 5 types: regent_t and regtab_t, corresponding to the
 * two structures; reg_t and unreg_t, for the registration and
 * unregistration callback functions; and regiter_t, used for the
 * iterator function passed to reg_iter().  In particular, regent_t
 * and regtab_t should be treated as opaque by all callers, and struct
 * RegEnt and struct RegTab should not be referenced directly.  Any
 * data needed from these structures may be obtained using the
 * provided macros.
 *
 * This subsystem is intentionally designed to pull in as few other
 * ircu subsystems as possible, in order to minimize issues with
 * modularity.  It is almost completely self-contained in the
 * register.h and register.c files, and only references the assert()
 * macro in ircd_log.h.  Explicit initialization is also not needed;
 * it makes use of "lazy initialization," where the first statement in
 * every publicly-exposed function is a call to a macro which checks
 * whether initialization has been performed and performs it if not.
 * Finally, the subsystem performs no memory allocation whatsoever,
 * and the recommended allocation procedure for callers is to
 * statically allocate the structures that will be passed in.
 */

/** Macro to perform "lazy" initialization of the system. */
#define reg_init(void)					\
  do {							\
    if (!reg_initted) {					\
      reg_add(&reg_table, (regent_t*) &reg_table);	\
      reg_initted++; /* remember that we're done */	\
    }							\
  } while (0)

/* pre-declare reg_flush() */
static int reg_flush(regtab_t* table, regtab_t* entry);

/** Flag whether initialization has been done */
static int reg_initted = 0;
/** Table of registration tables */
static regtab_t reg_table = REGTAB_INIT(REG_TABLE, REGTAB_MAGIC, 0,
					(unreg_t) reg_flush);

/** Search a table for a named entry.
 * @param[in] table Table to search.
 * @param[in] id Identifier of the entry to look up.
 * @return Pointer to the identified entry, or NULL if there isn't one.
 */
static regent_t* _reg_find(regtab_t* table, const char* id)
{
  regent_t *cursor, *tmp;

  assert(0 != table);
  assert(0 != id);

  /* Loop through the linked list... */
  for (cursor = table->reg_list; cursor; cursor = cursor->rl_next)
    if (!strcmp(id, cursor->rl_id)) {
      /* simple optimization step: bubble found entries up in the list;
       * this will tend to move frequently accessed entries toward the
       * beginning of the list, while moving infrequently accessed
       * entries toward the end.
       */
      if ((tmp = cursor->rl_prev)) {
	tmp->rl_next = cursor->rl_next;
	cursor->rl_prev = tmp->rl_prev;

	tmp->rl_prev = cursor;
	cursor->rl_next = tmp;

	/* update surrounding entries in the list */
	if (cursor->rl_prev)
	  cursor->rl_prev->rl_next = cursor;
	if (tmp->rl_next)
	  tmp->rl_next->rl_prev = tmp;
      }

      return cursor; /* we found it! */
    }

  return 0; /* not found */
}

/** Add an entry to a table.  Searches the table to make sure the
 * entry isn't already there somewhere.
 * @param[in] table Table to add the entry to.
 * @param[in] entry Entry to add.
 */
static void reg_add(regtab_t* table, regent_t* entry)
{
  assert(0 != table);
  assert(0 != entry);
  assert(0 != entry->rl_desc);

  /* OK, add the new entry to the head of the linked list */
  entry->rl_next = table->reg_list;
  entry->rl_prev = 0;
  if (table->reg_list) /* update prev in following entry */
    table->reg_list->rl_prev = entry;
  table->reg_list = entry; /* update the list */

  /* and make sure the entry points to its descriptor */
  entry->rl_desc = table;
}

/** Remove an entry from a table.
 * @param[in] table Table to remove entry from.
 * @param[in] entry Entry to remove.
 */
static void reg_rem(regtab_t* table, regent_t* entry)
{
  assert(0 != table);
  assert(0 != entry);
  assert(table == entry->rl_desc);

  /* Simply clip it out of the list */
  if (entry->rl_next)
    entry->rl_next->rl_prev = entry->rl_prev;
  if (entry->rl_prev)
    entry->rl_prev->rl_next = entry->rl_next;
  else /* first entry in list */
    table->reg_list = entry->rl_next;

  /* zero what has to be zeroed */
  entry->rl_next = entry->rl_prev = 0;
  entry->rl_desc = 0;
}

/** Remove all entries from a table.
 * @param[in] table Pointer to reg_table.
 * @param[in] entry Table being unregistered.
 * @return 0 to accept the unregistration.
 */
static int reg_flush(regtab_t* table, regtab_t* entry)
{
  /* Unregister each entry in turn */
  while (entry->reg_list) {
    if (entry->reg_unreg) /* call unregistration callback */
      (entry->reg_unreg)(entry, (void*) entry->reg_list);
    /* Note: ignoring failures and trying hard */

    /* remove entry from the table */
    reg_rem(entry, entry->reg_list);
  }

  return 0;
}

/** Register a new entry in a table.
 * @param[in] table Name of table entry should belong to.
 * @param[in] entry Entry to add; must begin with a regent_t.
 * @return 0 if entry was added, non-zero otherwise; -1 means no table by
 * that name; -2 means the magic numbers don't match; -3 means it already
 * exists in the table; other values returned by table reg function.
 */
int reg(const char* table, void* entry)
{
  int retval;
  regtab_t *tab;

  reg_init(); /* initialize subsystem */

  /* look up the requested table */
  if (!(tab = (regtab_t*) _reg_find(&reg_table, table)))
    return -1; /* no such table */

  /* double-check the magic numbers */
  if (((regent_t*) entry)->rl_magic != tab->reg_magic)
    return -2; /* bad magic number */

  /* make sure the entry doesn't already exist */
  if (_reg_find(tab, ((regent_t*) entry)->rl_id))
    return -3; /* already exists in the table */

  /* perform any table-specific registration */
  if (tab->reg_reg && (retval = (tab->reg_reg)(tab, entry)))
    return retval;

  /* add it to the table */
  reg_add(tab, (regent_t*) entry);

  return 0; /* all set */
}

/** Register an array of entries in a table.
 * @param[in] table Name of table entries should belong to.
 * @param[in] ent_array Array of entries to add; each must be same size and
 * begin with a regent_t.
 * @param[in] n Number of entries in array.
 * @param[in] size Size of each entry in array.
 * @return n if all entries were added; -1 means no table by that name;
 * otherwise, the index of the first entry not added to the table.
 */
int reg_n(const char* table, void* ent_array, int n, size_t size)
{
  int i;
  regtab_t *tab;

  reg_init(); /* initialize subsystem */

  /* look up the requested table */
  if (!(tab = (regtab_t*) _reg_find(&reg_table, table)))
    return -1; /* no such table */

  /* walk through each array entry and add it */
  for (i = 0; i < n; i++) {
    /* obtain the indexed entry */
    regent_t *ent = (regent_t*) (((char*) ent_array) + i * size);

    /* double-check the magic numbers */
    if (ent->rl_magic != tab->reg_magic)
      return i;

    /* make sure the entry doesn't already exist */
    if (_reg_find(tab, ent->rl_id))
      return i; /* already exists in the table */

    /* perform any table-specific registration */
    if (tab->reg_reg && (tab->reg_reg)(tab, ent))
      return i;

    /* add it to the table */
    reg_add(tab, ent);
  }

  return i; /* should be n, indicating all entries processed */
}

/** Unregister an entry from a table.
 * @param[in] table Name of table entry should be removed from.
 * @param[in] entry Entry to remove; must begin with a regent_t.
 * @return 0 if entry was removed, non-zero otherwise; -1 means no table by
 * that name; other values returned by table unreg function.
 */
int unreg(const char* table, void* entry)
{
  int retval;
  regtab_t *tab;

  reg_init(); /* initialize subsystem */

  /* look up the requested table */
  if (!(tab = (regtab_t*) _reg_find(&reg_table, table)))
    return -1;

  assert(tab == ((regent_t*) entry)->rl_desc);

  /* perform any table-specific unregistration */
  if (tab->reg_unreg && (retval = (tab->reg_unreg)(tab, entry)))
    return retval;

  /* remove it from the table */
  reg_rem(tab, (regent_t*) entry);

  return 0; /* all set */
}

/** Unregister an array of entries from a table.
 * @param[in] table Name of table entries should be removed from.
 * @param[in] ent_array Array of entries to remove; each must be same size and
 * begin with a regent_t.
 * @param[in] n Number of entries in array.
 * @param[in] size Size of each entry in array.
 * @return n if all entries were removed; -1 means no table by that name;
 * otherwise, the index of the first entry not removed from the table.  Note
 * only table unreg function returning non-zero can halt processing.
 */
int unreg_n(const char* table, void* ent_array, int n, size_t size)
{
  int i;
  regtab_t *tab;

  reg_init(); /* initialize subsystem */

  /* look up the requested table */
  if (!(tab = (regtab_t*) _reg_find(&reg_table, table)))
    return -1; /* no such table */

  /* walk through each array entry and add it */
  for (i = 0; i < n; i++) {
    /* obtain the indexed entry */
    regent_t *ent = (regent_t*) (((char*) ent_array) + i * size);

    assert(tab == ent->rl_desc);

    /* perform any table-specific unregistration */
    if (tab->reg_unreg && (tab->reg_unreg)(tab, ent))
      return i;

    /* remove it from the table */
    reg_add(tab, ent);
  }

  return i; /* should be n, indicating all entries processed */
}


/** Find an entry in a table.
 * @param[in] table Name of table to search.
 * @param[in] id Name of entry to look up.
 * @return Pointer to entry, or NULL if not found.
 */
void* reg_find(const char* table, const char* id)
{
  regtab_t *tab;

  reg_init(); /* initialize subsystem */

  /* look up the requested table */
  if (!(tab = (regtab_t*) _reg_find(&reg_table, table)))
    return 0; /* couldn't even find table */

  /* return the result of looking up the entry */
  return (void*) _reg_find(tab, id);
}

/** Iterate over all entries in a table.
 * @param[in] table Name of table to walk.
 * @param[in] func Iteration function to execute.
 * @param[in] extra Extra data to pass to iteration function.
 * @return -1 if table doesn't exist; otherwise, 0 or whatever
 * non-zero value \a func returns.
 */
int reg_iter(const char* table, regiter_t func, void* extra)
{
  int retval;
  regtab_t *tab;
  regent_t *cursor;

  assert(0 != func);

  reg_init(); /* initialize subsystem */

  /* look up the requested table */
  if (!(tab = (regtab_t*) _reg_find(&reg_table, table)))
    return -1;

  /* walk the linked list */
  for (cursor = tab->reg_list; cursor; cursor = cursor->rl_next)
    if ((retval = (func)(tab, (void*) cursor, extra)))
      return retval; /* iteration function signaled for stop */

  return 0; /* all done */
}
