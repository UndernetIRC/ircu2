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
 * \brief Iterate over each entry in a hash table.
 *
 * This function iterates over every entry in a hash table (in an
 * unspecified order), executing the given \p iter_func on each entry.
 *
 * \param table	A pointer to a #hash_table_t.
 * \param iter_func
 *		A pointer to a callback function used to perform
 *		user-specified actions on an entry in a hash table. \c
 *		NULL is an invalid value.  See the documentation for
 *		#hash_iter_t for more information.
 * \param extra	A \c void pointer that will be passed to \p
 *		iter_func.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_FROZEN	The hash table is frozen.
 */
unsigned long
ht_iter(hash_table_t *table, hash_iter_t iter_func, void *extra)
{
  unsigned long retval;
  int i;
  link_elem_t *elem;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ht_verify(table) || !iter_func) /* verify arguments */
    return DB_ERR_BADARGS;

  if (table->ht_flags & HASH_FLAG_FREEZE) /* don't mess with frozen tables */
    return DB_ERR_FROZEN;

  table->ht_flags |= HASH_FLAG_FREEZE; /* freeze the table */

  /* walk through all the elements and call the iteration function */
  for (i = 0; i < table->ht_modulus; i++)
    for (elem = ll_first(&table->ht_table[i]); elem; elem = le_next(elem))
      if ((retval = (*iter_func)(table, le_object(elem), extra))) {
	table->ht_flags &= ~HASH_FLAG_FREEZE; /* unfreeze the table */
	return retval;
      }

  table->ht_flags &= ~HASH_FLAG_FREEZE; /* unfreeze the table */

  return 0;
}
