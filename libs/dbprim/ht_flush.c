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

#include "dbprim.h"
#include "dbprim_int.h"

RCSTAG("@(#)$Id$");

/** \ingroup dbprim_hash
 * \brief Flush a hash table.
 *
 * This function flushes a hash table--that is, it removes each entry
 * from the table.  If a \p flush_func is specified, it will be called
 * on the entry after it has been removed from the table, and may
 * safely call <CODE>free()</CODE>.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param flush_func
 *		A pointer to a callback function used to perform
 *		user-specified actions on an entry after removing it
 *		from the table.  May be \c NULL.  See the
 *		documentation for #hash_iter_t for more information.
 * \param extra	A \c void pointer that will be passed to \p
 *		flush_func.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_FROZEN	The hash table is frozen.
 */
unsigned long
ht_flush(hash_table_t *table, hash_iter_t flush_func, void *extra)
{
  unsigned long retval = 0;
  int i;
  link_elem_t *elem;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table)) /* verify arguments */
    return DB_ERR_BADARGS;

  if (table->ht_flags & HASH_FLAG_FREEZE) /* don't mess with frozen tables */
    return DB_ERR_FROZEN;

  /* walk through all the elements */
  for (i = 0; i < table->ht_modulus; i++)
    for (elem = ll_first(&table->ht_table[i]); elem;
	 elem = ll_first(&table->ht_table[i])) {
      ht_remove(table, le_object(elem)); /* remove the entry... */

      table->ht_flags |= HASH_FLAG_FREEZE; /* freeze the table */

      if (flush_func) /* call flush function */
	retval = (*flush_func)(table, le_object(elem), extra);

      table->ht_flags &= ~HASH_FLAG_FREEZE; /* unfreeze table... */

      if (retval) /* if flush function failed, error out */
	return retval;
    }

  table->ht_count = 0; /* clear the entry count */

  if (table->ht_flags & HASH_FLAG_AUTOSHRINK) /* shrink the table... */
    return ht_free(table); /* by calling ht_free() */

  return 0;
}
