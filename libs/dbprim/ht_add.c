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
 * \brief Add an entry to a hash table.
 *
 * This function adds an entry to a hash table.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param entry	A pointer to a #hash_entry_t to be added to the
 *		table.
 * \param key	A pointer to a #db_key_t containing the key for the
 *		entry.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval DB_ERR_BUSY		The entry is already in a table.
 * \retval DB_ERR_FROZEN	The table is currently frozen.
 * \retval DB_ERR_NOTABLE	The bucket table has not been
 *				allocated and automatic growth is not
 *				enabled.
 * \retval DB_ERR_DUPLICATE	The entry is a duplicate of an
 *				existing entry.
 * \retval DB_ERR_UNRECOVERABLE	An unrecoverable error occurred while
 *				resizing the table.
 */
unsigned long
ht_add(hash_table_t *table, hash_entry_t *entry, db_key_t *key)
{
  unsigned long retval;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table) || !he_verify(entry) || !key) /* verify arguments */
    return DB_ERR_BADARGS;

  if (entry->he_table) /* it's already in a table... */
    return DB_ERR_BUSY;

  if (table->ht_flags & HASH_FLAG_FREEZE) /* don't add to frozen tables */
    return DB_ERR_FROZEN;

  if (!table->ht_table && !(table->ht_flags & HASH_FLAG_AUTOGROW))
    return DB_ERR_NOTABLE;

  /* It looks like we could optimize here, but don't be deceived--the table
   * may grow between here and when we fill in the entry's hash value, and
   * that would change the hash value.
   */
  if (!ht_find(table, 0, key)) /* don't permit duplicates */
    return DB_ERR_DUPLICATE;

  /* increment element count and grow the table if necessary and allowed */
  if (++table->ht_count > table->ht_rollover &&
      (table->ht_flags & HASH_FLAG_AUTOGROW) &&
      (retval = ht_resize(table, 0)))
    return retval;

  /* Force the link element to point to the entry */
  le_object(&entry->he_elem) = entry;

  /* copy key value into the hash entry */
  entry->he_key = *key; /* thank goodness for structure copy! */

  /* get the hash value for the entry */
  entry->he_hash =
    (*table->ht_func)(table, &entry->he_key) % table->ht_modulus;

  /* Now add the entry to the table... */
  if ((retval = ll_add(&table->ht_table[entry->he_hash], &entry->he_elem,
		       LINK_LOC_HEAD, 0))) {
    table->ht_count--; /* decrement the count--don't worry about shrinking */
    return retval;
  }

  entry->he_table = table; /* point entry at table */

  return 0;
}
