/*
 * IRC - Internet Relay Chat, ircd/keyspace.c
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
 * @brief Implementation of allocation of integer keys.
 * @version $Id$
 */
#include "config.h"

#include "keyspace.h"
#include "flagset.h"
#include "ircd_alloc.h"
#include "ircd_log.h"

/** @page keyspace Generic keyspace subsystem.
 *
 * @section introkey Introduction
 *
 * Many subsystems need to allocate small integers, called \em keys.
 * These keys are typically used as indexes into an array.  This
 * subsystem is a simple but efficient generic key allocation
 * subsystem.  It is modeled on the pthread_key_create() and
 * pthread_key_delete() routines, which manage keys for use by the
 * POSIX functions pthread_getspecific() and pthread_setspecific().
 * The primary difference between these POSIX interfaces and this
 * subsystem is that, for the POSIX routines, the key type is opaque,
 * whereas this subsystem provides simple integers.
 *
 * @section keyman Managing Keys
 *
 * Keys are represented by the type key_t, and they are allocated from
 * \a keyspaces, which are specified by a keyspace_t object.  This
 * keyspace_t object must be initialized either with KEYSPACE_INIT()
 * or ks_init()--the latter allowing for dynamic initialization.  Once
 * keys are allocated, the keyspace_t object will contain some
 * allocated memory, which may be reclaimed by calling the ks_clean()
 * routine on the keyspace.  Note that the keyspace must be
 * reinitialized by a call to ks_init() before it can be used again.
 *
 * Allocation of a key is simple--simply call the ks_reserve()
 * function, passing it a pointer to the keyspace.  If no more keys
 * can be allocated--there is a provision for setting the maximum
 * permissible key--ks_reserve() will return KEY_INVKEY.  Otherwise,
 * it returns a newly allocated key.  Allocation is done in a
 * tight-packed manner, so ks_reserve() may return keys that have been
 * released.  Once you're done with a key, simply call ks_release() to
 * return it to the system.
 *
 * @section advkey Advanced Key Management
 *
 * Most subsystems need to maintain an array in conjunction with the
 * keyspace.  This array may contain things such as a pointer to a
 * function to release whatever object the key is referring to.
 * Additionally, some subsystems need to impose an upper limit on the
 * keyspace.  Both of these are quite simple to accomplish.
 *
 * It is also possible, by specifying a non-zero \a extra argument to
 * KEYSPACE_INIT() or ks_init(), to associate arbitrary data--such as
 * a pointer to the externally maintained array--with a keyspace.
 *
 * @subsection maxkey Maximum Keys
 *
 * Both KEYSPACE_INIT() and ks_init() take an argument called \a max,
 * which specifies the maximum number of keys that the subsystem can
 * accommodate.  Once that number of keys has been allocated,
 * ks_reserve() will return KEY_INVKEY until a key has been released
 * by a call to ks_release().  If an upper limit is unnecessary or
 * undesired, simply pass 0 for \a max.
 *
 * @subsection externkey External Keys
 *
 * Managing an external array is also fairly simple to accomplish.
 * The keyspace subsystem will call a user-defined function whenever a
 * new key allocation requires that the external array (or whatever
 * the user is maintaining) needs to be resized.  This is accomplished
 * by specifying the \a chunk and \a grow arguments to KEYSPACE_INIT()
 * or ks_init().  Both of these arguments must be nonzero in order to
 * enable this advanced feature.
 *
 * The \a grow argument simply specifies a routine that will be called
 * with a pointer to the keyspace and the new size of the external
 * array.  This new size will be a multiple of the \a chunk size
 * specified when the keyspace was initialized.
 *
 * @section infokey Important Subsystem Information
 *
 * This subsystem provides one structure--struct KeySpace--and 2
 * types: key_t, for the value of keys; and keyspace_t, corresponding
 * to the struct KeySpace.  In particular, keyspace_t should be
 * treated as opaque by all callers, only referenced through the
 * provided macros, whereas key_t can be treated as an integral type
 * suitable for use as an array index.
 *
 * This subsystem is intentionally designed to pull in as few other
 * ircu subsystems as possible, in order to minimize issues with
 * modularity.  It is almost completely self-contained in the
 * keyspace.h and keyspace.c, referencing the assert() macro in
 * ircd_log.h and making use of the flagpage_t type and some
 * associated macros from flagset.h.  The subsystem itself needs no
 * initialization, as all data is completely contained in the
 * keyspace_t types, which are caller-allocated and initialized.
 *
 * This subsystem allocates a small amount of memory for tracking
 * which keys have been allocated and which ones are available.  This
 * memory is directly associated with the keyspaces that have been
 * utilized, and may be reclaimed by calling ks_clean() on those
 * keyspaces.
 */

/** Allocate a key from a keyspace.
 * @param[in,out] space The keyspace from which to allocate the key.
 * @return The reserved key, or #KEY_INVKEY if one could not be allocated.
 */
key_t
ks_reserve(keyspace_t* space)
{
  key_t key = KEY_INVKEY;

  assert(KEYSPACE_CHECK(space));

  /* Can we even allocate a key? */
  if (space->ks_count >= (space->ks_max ? space->ks_max : KEY_INVKEY))
    return KEY_INVKEY;

  /* Do we need to allocate some more keyspace? */
  if (space->ks_count == (space->ks_alloc * FLAGSET_NBITS)) {
    /* resize the key space */
    space->ks_keys = MyRealloc(space->ks_keys, sizeof(flagpage_t) *
			       (space->ks_alloc + 1));

    /* initialize the new element */
    space->ks_keys[space->ks_alloc++] = 0;

    /* select a key */
    key = space->ks_count;
  } else { /* find an empty slot in the bitmap */
    flagpage_t alloc, mask = ~0;
    int i = 0, b = FLAGSET_NBITS >> 1;

    /* search for a page with some unallocated bits */
    for (; i < space->ks_alloc; i++)
      if (~space->ks_keys[i]) /* if all bits set, == 0 and we go on */
	break;

    /* Now, find an unallocated key.  This algorithm searches the bit
     * page specified by i for the first zero bit.  (It actually
     * complements the key page in order to search for the first _set_
     * bit, which is a slightly easier task.)  alloc is the
     * complemented allocation bitmask, mask is the current testing
     * mask, b is the number of bits by which to shift the mask, and
     * key is the resultant index of the first clear bit.  The
     * algorithm works by performing a binary search on the allocation
     * bitmask: If there are no free bits on the right half, the
     * allocation bitmask is shifted by the appropriate number of
     * bits, and then the mask is reduced to half the bits it had
     * previously.  Note that the mask starts off with all bits set,
     * so the first bitmask update reduces it to half of all bits
     * set...
     */
    for (alloc = ~space->ks_keys[i], key = 0; b; b >>= 1) {
      mask >>= b; /* update the bitmask... */
      if (!(alloc & mask)) { /* any clear bits on the right? */
	alloc >>= b; /* nope, shift over some... */
	key += b; /* and update the bit count */
      }
    }

    /* now correct the key to account for the index i */
    key += i * FLAGSET_NBITS;
  }

  /* We have a key, let's mark it set and update some statistics */
  space->ks_count++;
  space->ks_keys[FLAGSET_INDEX(key)] |= FLAGSET_MASK(key);
  if (key > space->ks_highest) {
    space->ks_highest = key; /* keep track of highest key */

    /* inform the external support of a need to resize */
    if (space->ks_chunk && space->ks_grow &&
	space->ks_highest > space->ks_extern)
      (space->ks_grow)(space, space->ks_extern += space->ks_chunk);
  }

  /* Return the key */
  return key;
}

/** Release a key allocated from a keyspace.
 * @param[in,out] space The keyspace from which the key was allocated.
 * @param[in] key The key to release.
 */
void
ks_release(keyspace_t* space, key_t key)
{
  assert(KEYSPACE_CHECK(space));

  /* if the key was allocated, mark it free and decrement count */
  if (space->ks_keys[FLAGSET_INDEX(key)] & FLAGSET_MASK(key)) {
    space->ks_keys[FLAGSET_INDEX(key)] &= ~FLAGSET_MASK(key);
    space->ks_count--;
  }
}

/** Clean up a keyspace.
 * @param[in,out] space The key space to clean up.
 */
void
ks_clean(keyspace_t* space)
{
  assert(KEYSPACE_CHECK(space));

  /* we're just going to release all keys, so just free the key pages */
  if (space->ks_keys)
    MyFree(space->ks_keys);

  /* zero everything */
  space->ks_magic = 0;
  space->ks_alloc = 0;
  space->ks_count = 0;
  space->ks_highest = 0;
  space->ks_max = 0;
  space->ks_extern = 0;
  space->ks_chunk = 0;
  space->ks_grow = 0;
  space->ks_keys = 0;
}
