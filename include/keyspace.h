/*
 * IRC - Internet Relay Chat, include/keyspace.h
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/** @file
 * @brief Structures and functions for allocating integer keys.
 * @version $Id$
 */
#ifndef INCLUDED_keyspace_h
#define INCLUDED_keyspace_h
#ifndef INCLUDED_flagset_h
#include "flagset.h"	/* flagpage_t */
#endif
#ifndef INCLUDED_limits_h
#include <limits.h>	/* UINT_MAX */
#define INCLUDED_limits_h
#endif

/** Invalid ircd_key_t value for returning errors from ks_reserve(). */
#define KEY_INVKEY	UINT_MAX

/** Specifies a key value. */
typedef unsigned int ircd_key_t;
/** Specifies a space of keys to allocate from. */
typedef struct KeySpace keyspace_t;

/** Optional growth callback for a key space.
 * @param[in] space Key space being grown.
 * @param[in] new New size for key space allocation.
 */
typedef void (*keygrow_t)(keyspace_t* space, ircd_key_t new);

/** Contains details of the key space. */
struct KeySpace {
  unsigned long	ks_magic;	/**< Magic number */
  unsigned int	ks_alloc;	/**< Total number of bitmap entries */
  ircd_key_t	ks_count;	/**< Current count of keys */
  ircd_key_t	ks_highest;	/**< Highest allocated key to date */
  ircd_key_t	ks_max;		/**< Maximum number of keys to allocate */
  ircd_key_t	ks_extern;	/**< External key tracker size */
  ircd_key_t	ks_chunk;	/**< Chunk to round key tracker size to */
  keygrow_t	ks_grow;	/**< External routine to signal on growth */
  flagpage_t*	ks_keys;	/**< Key allocation bitmap */
  void*		ks_extra;	/**< Extra data associated with keyspace */
};

/** Magic number for keyspace_t. */
#define KEYSPACE_MAGIC 0x44368132

/** Initialize a keyspace_t.
 * @param[in] max Maximum number of keys that can be reserved.
 * @param[in] chunk Chunk size for calling external routine.
 * @param[in] grow External routine to call when grown.
 * @param[in] extra Extra data to be associated with the keyspace.
 */
#define KEYSPACE_INIT(max, chunk, grow, extra)				\
  { KEYSPACE_MAGIC, 0, 0, 0, (max), 0, (chunk), (grow), 0, (extra) }

/** Check the keyspace_t magic number. */
#define KEYSPACE_CHECK(space)	((space) &&				\
				 (space)->ks_magic == KEYSPACE_MAGIC)

/** Get the number of entries allocated in the keys table. */
#define ks_alloc(space)		((space)->ks_alloc)
/** Get the count of the keys currently allocated. */
#define ks_count(space)		((space)->ks_count)
/** Get the value of the highest key that's been allocated. */
#define ks_highest(space)	((space)->ks_highest)
/** Get the maximum number of keys that can be allocated. */
#define ks_max(space)		((space)->ks_max)
/** Get the current size of the external array. */
#define ks_extern(space)	((space)->ks_extern)
/** Get the chunk size for allocation of the external array. */
#define ks_chunk(space)		((space)->ks_chunk)
/** Get the external array growth function callabck. */
#define ks_grow(space)		((space)->ks_grow)
/** Get the \a i entry in the keys table. */
#define ks_keys(space, i)	((space)->ks_keys[(i)])
/** Get extra data associated with the keyspace. */
#define ks_extra(space)		((space)->ks_extra)

/** Dynamically initialize a keyspace_t.
 * @param[in,out] space A pointer to the keyspace_t to be initialized.
 * @param[in] max Maximum number of keys that can be reserved.
 * @param[in] chunk Chunk size for calling external routine.
 * @param[in] grow External routine to call when grown.
 */
#define ks_init(space, max, chunk, grow, extra)	\
  do {						\
    keyspace_t* _ks = (space);			\
    _ks->ks_magic = KEYSPACE_MAGIC;		\
    _ks->ks_alloc = 0;				\
    _ks->ks_count = 0;				\
    _ks->ks_highest = 0;			\
    _ks->ks_max = (max);			\
    _ks->ks_extern = 0;				\
    _ks->ks_chunk = (chunk);			\
    _ks->ks_grow = (grow);			\
    _ks->ks_keys = 0;				\
    _ks->ks_extra = (extra);			\
  } while (0)

/* Reserve a key, optionally a specified one. */
extern ircd_key_t ks_reserve(keyspace_t* space);

/* Release an allocated key. */
extern void ks_release(keyspace_t* space, ircd_key_t key);

/* Clean up a keyspace. */
extern void ks_clean(keyspace_t* space);

#endif /* INCLUDED_keyspace_h */
