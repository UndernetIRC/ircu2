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
 * \brief Remove an element from a hash table.
 *
 * This function removes the given element from the specified hash
 * table.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param entry	A pointer to a #hash_entry_t to be removed from the
 *		table.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval DB_ERR_UNUSED	Entry is not in a hash table.
 * \retval DB_ERR_WRONGTABLE	Entry is not in this hash table.
 * \retval DB_ERR_FROZEN	Hash table is frozen.
 * \retval DB_ERR_UNRECOVERABLE	An unrecoverable error occurred while
 *				resizing the table.
 */
unsigned long
ht_remove(hash_table_t *table, hash_entry_t *entry)
{
  unsigned long retval = 0;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table) || !he_verify(entry)) /* verify arguments */
    return DB_ERR_BADARGS;

  if (!entry->he_table) /* it's not in a table */
    return DB_ERR_UNUSED;
  if (entry->he_table != table) /* it's in the wrong table */
    return DB_ERR_WRONGTABLE;

  if (table->ht_flags & HASH_FLAG_FREEZE) /* don't remove from frozen tables */
    return DB_ERR_FROZEN;

  /* remove the entry from the table */
  if ((retval = ll_remove(&table->ht_table[entry->he_hash], &entry->he_elem)))
    return retval;

  entry->he_table = 0; /* reset the table */

  /* decrement element count and shrink the table if necessary and allowed */
  if (--table->ht_count < table->ht_rollunder &&
      (table->ht_flags & HASH_FLAG_AUTOSHRINK))
    retval = ht_resize(table, 0);

  return retval;
}
