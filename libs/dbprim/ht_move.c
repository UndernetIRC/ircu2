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
 * \brief Move an entry in the hash table.
 *
 * This function moves an existing entry in the hash table to
 * correspond to the new key.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param entry	A pointer to a #hash_entry_t to be moved.  It must
 *		already be in the hash table.
 * \param key	A pointer to a #db_key_t describing the new key for
 *		the entry.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval DB_ERR_UNUSED	Entry is not in a hash table.
 * \retval DB_ERR_WRONGTABLE	Entry is not in this hash table.
 * \retval DB_ERR_FROZEN	Hash table is frozen.
 * \retval DB_ERR_DUPLICATE	New key is a duplicate of an existing
 *				key.
 * \retval DB_ERR_READDFAILED	Unable to re-add entry to table.
 */
unsigned long
ht_move(hash_table_t *table, hash_entry_t *entry, db_key_t *key)
{
  unsigned long retval;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table) || !he_verify(entry) || !key) /* verify arguments */
    return DB_ERR_BADARGS;

  if (!entry->he_table) /* it's not in a table */
    return DB_ERR_UNUSED;
  if (entry->he_table != table) /* it's in the wrong table */
    return DB_ERR_WRONGTABLE;

  if (table->ht_flags & HASH_FLAG_FREEZE) /* don't mess with frozen tables */
    return DB_ERR_FROZEN;

  if (!ht_find(table, 0, key)) /* don't permit duplicates */
    return DB_ERR_DUPLICATE;

  /* remove the entry from the table */
  if ((retval = ll_remove(&table->ht_table[entry->he_hash], &entry->he_elem)))
    return retval;

  /* rekey the entry */
  entry->he_key = *key; /* thank goodness for structure copy! */

  /* get the new hash value for the entry */
  entry->he_hash =
    (*table->ht_func)(table, &entry->he_key) % table->ht_modulus;

  /* Now re-add it to the table */
  if ((retval = ll_add(&table->ht_table[entry->he_hash], &entry->he_elem,
		       LINK_LOC_HEAD, 0))) {
    table->ht_count--; /* decrement the count--don't worry about shrinking */
    entry->he_table = 0; /* zero the table pointer */
    return DB_ERR_READDFAILED;
  }

  return 0;
}
