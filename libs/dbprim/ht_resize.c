/*
** Copyright (C) 2002 by Kevin L. Mitchell <klmitch@mit.edu>
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of the GNU Library General Public
** License as published by the Free Software Foundation; either
** version 2 of the License, or (at your option) any later version.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Library General Public License for more details.
**
** You should have received a copy of the GNU Library General Public
** License along with this library; if not, write to the Free
** Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
** MA 02111-1307, USA
**
** @(#)$Id$
*/
#include <stdlib.h>
#include <errno.h>

#include "dbprim.h"
#include "dbprim_int.h"

RCSTAG("@(#)$Id$");

/** \ingroup dbprim_hash
 * \brief Resize a hash table.
 *
 * This function resizes a hash table to the given \p new_size.  If \p
 * new_size is 0, then an appropriate new size based on the current
 * number of items in the hash table will be selected.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param new_size
 *		A new size value for the table.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_FROZEN	The table is currently frozen.
 * \retval DB_ERR_UNRECOVERABLE	A catastrophic error was encountered.
 *				The table is now unusable.
 * \retval ENOMEM		No memory could be allocated for the
 *				new bucket table.
 */
unsigned long
ht_resize(hash_table_t *table, unsigned long new_size)
{
  unsigned long retval;
  link_head_t *htab;
  link_elem_t *elem;
  hash_entry_t *ent;
  int i;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table)) /* verify that it's really a table */
    return DB_ERR_BADARGS;

  if (table->ht_flags & HASH_FLAG_FREEZE) /* don't resize frozen tables */
    return DB_ERR_FROZEN;

  if (!new_size) /* select the new table size, defaulting to fuzzed current */
    new_size = _hash_fuzz(table->ht_count ? table->ht_count : 1);
  new_size = _hash_prime(new_size); /* prime it! */

  /* Call the resize calback */
  if (table->ht_resize && (retval = (*table->ht_resize)(table, new_size)))
    return retval;

  /* allocate new table array */
  if (!(htab = (link_head_t *)malloc(new_size * sizeof(link_head_t))))
    return errno;

  /* initialize the new array */
  for (i = 0; i < new_size; i++)
    if ((retval = ll_init(&htab[i], table))) { /* initialize listhead array */
      free(htab);
      return retval;
    }

  /* rehash the table */
  for (i = 0; i < table->ht_modulus; i++) /* step through each element */
    for (elem = ll_first(&table->ht_table[i]); elem;
	 elem = ll_first(&table->ht_table[i])) {
      ent = le_object(elem);

      /* calculate new hash value */
      ent->he_hash = (*table->ht_func)(table, &ent->he_key) % new_size;

      if ((retval = ll_remove(&table->ht_table[i], elem)) ||
	  (retval = ll_add(&htab[ent->he_hash], elem, LINK_LOC_HEAD, 0))) {
	/* This is catastrophic!  We've lost some elements.  Shouldn't
	 * ever happen, but you know bugs...
	 */
	free(htab); /* free allocated memory */
	free(table->ht_table);

	table->ht_modulus = 0; /* reset table to reflect empty state */
	table->ht_count = 0;
	table->ht_rollover = 0;
	table->ht_rollunder = 0;
	table->ht_table = 0;

	return DB_ERR_UNRECOVERABLE;
      }
    }

  if (table->ht_table) /* OK, free old table value */
    free(table->ht_table);

  table->ht_modulus = new_size; /* set new table size and roll values */
  table->ht_rollover = _hash_rollover(new_size);
  table->ht_rollunder = _hash_rollunder(new_size);
  table->ht_table = htab; /* store new table */

  return 0;
}
