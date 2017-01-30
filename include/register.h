/*
 * IRC - Internet Relay Chat, include/register.h
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
 * @brief Structures and functions for handling generic function registration.
 */
#ifndef INCLUDED_register_h
#define INCLUDED_register_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>		/* size_t */
#define INCLUDED_sys_types_h
#endif

/** Name of table containing registered registration tables. */
#define REG_TABLE	"tables"

/** Specifies an element in the list of registered entities. */
typedef struct RegEnt regent_t;
/** Describes a table of registered entities. */ 
typedef struct RegTab regtab_t;

/** Optional registration callback for a table.
 * @param[in] table Table entry is to be registered in.
 * @param[in] entry Entry being registered.
 * @return 0 to accept registration, non-zero to reject it.
 */
typedef int (*reg_t)(regtab_t* table, void* entry);

/** Optional unregistration callback for a table.
 * @param[in] table Table entry is to be unregistered from.
 * @param[in] entry Entry being unregistered.
 * @return 0 to accept unregistration, non-zero to reject it.
 */
typedef int (*unreg_t)(regtab_t* table, void* entry);

/** Iteration callback for reg_iter().
 * @param[in] table Table entry is in.
 * @param[in] entry Entry in table.
 * @param[in] extra Extra pointer passed to reg_iter().
 * @return 0 to continue iteration, non-zero to stop iteration.
 */
typedef int (*regiter_t)(regtab_t* table, void* entry, void* extra);

/** Describes an entry in a table. */
struct RegEnt {
  unsigned long	rl_magic;	/**< Magic number */
  regent_t*	rl_next;	/**< Next entry in list */
  regent_t*	rl_prev;	/**< Previous entry in list */
  const char*	rl_id;		/**< Name we're identified by */
  regtab_t*	rl_desc;	/**< Descriptor for registration */
};

/** Initialize a regent_t.
 * @param[in] magic Magic number for this entry.
 * @param[in] id Name of the entry.
 */
#define REGENT_INIT(magic, id)			\
  { (magic), 0, 0, (id), 0 }

/** Check the regent_t magic number. */
#define REGENT_CHECK(re, magic)	((re) &&				\
				 ((regent_t*) (re))->rl_magic == (magic))
/** Get the name of an entry. */
#define rl_id(re)		(((regent_t*) (re))->rl_id)
/** Get the table entry is in. */
#define rl_desc(re)		(((regent_t*) (re))->rl_desc)

/** Describes a table of registered entries. */
struct RegTab {
  regent_t	reg_entry;	/**< Entry in registers list */
  unsigned long	reg_magic;	/**< Magic number for members of list */
  reg_t		reg_reg;	/**< Registration function */
  unreg_t	reg_unreg;	/**< Unregistration function */
  regent_t*	reg_list;	/**< List of registration descriptors */
};

/** Magic number for regtab_t. */
#define REGTAB_MAGIC 0xed99058e

/** Initialize a regtab_t.
 * @param[in] id Name of the table.
 * @param[in] magic Magic number for all entries in table.
 * @param[in] reg Pointer to registration callback, or NULL.  See reg_t.
 * @param[in] unreg Pointer to unregistration callback, or NULL.  See unreg_t.
 */
#define REGTAB_INIT(id, magic, reg, unreg)				\
  { REGENT_INIT(REGTAB_MAGIC, (id)), (magic), (reg), (unreg), 0 }

/** Check a registration table. */
#define REGTAB_CHECK(tab)	REGENT_CHECK((tab), REGTAB_MAGIC)
/** Get the name of a table. */
#define reg_name(tab)		rl_id(tab)
/** Get the magic number for table entries. */
#define reg_magic(tab)		((tab)->reg_magic)
/** Get the registration callback function. */
#define reg_reg(tab)		((tab)->reg_reg)
/** Get the unregistration callback function. */
#define reg_unreg(tab)		((tab)->reg_unreg)

/* register an entry in a named table */
extern int reg(const char* table, void* entry);
/* register an array of entries in a named table */
extern int reg_n(const char* table, void* ent_array, int n, size_t size);
/* unregister an entry from a named table */
extern int unreg(const char* table, void* entry);
/* unregister an array of entries from a named table */
extern int unreg_n(const char* table, void* ent_array, int n, size_t size);
/* look up an entry in the table */
extern void* reg_find(const char* table, const char* id);
/* iterate over entries in the table */
extern int reg_iter(const char* table, regiter_t func, void* extra);

#endif /* INCLUDED_register_h */
