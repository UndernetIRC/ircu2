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
#include "dbprim.h"
#include "dbprim_int.h"

RCSTAG("@(#)$Id$");

/** \ingroup dbprim_hash
 * \brief Find an entry in a hash table.
 *
 * This function looks up an entry matching the given \p key.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param entry_p
 *		A pointer to a pointer to a #hash_entry_t.  This is a
 *		result parameter.  If \c NULL is passed, the lookup
 *		will be performed and an appropriate error code
 *		returned. 
 * \param key	A pointer to a #db_key_t describing the item to find.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_NOENTRY	No matching entry was found.
 */
unsigned long
ht_find(hash_table_t *table, hash_entry_t **entry_p, db_key_t *key)
{
  unsigned long hash;
  link_elem_t *elem;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table) || !key) /* verify arguments */
    return DB_ERR_BADARGS;

  if (!table->ht_count) /* no entries in table... */
    return DB_ERR_NOENTRY;

  hash = (*table->ht_func)(table, key) % table->ht_modulus; /* get hash */

  /* walk through each element in that section */
  for (elem = ll_first(&table->ht_table[hash]); elem; elem = le_next(elem))
    /* compare keys... */
    if (!(*table->ht_comp)(table, key,
			   he_key((hash_entry_t *)le_object(elem)))) {
      /* found one, return it */
      if (entry_p)
	*entry_p = le_object(elem);
      return 0;
    }

  return DB_ERR_NOENTRY; /* couldn't find a matching entry */
}
