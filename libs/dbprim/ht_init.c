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
#include <errno.h>
#include <stdlib.h>

#include "dbprim.h"
#include "dbprim_int.h"

RCSTAG("@(#)$Id$");

/** \ingroup dbprim_hash
 * \brief Dynamically initialize a hash table.
 *
 * This function dynamically initializes a hash table.
 *
 * \param table	A pointer to a #hash_table_t to be initialized.
 * \param flags	A bit-wise OR of #HASH_FLAG_AUTOGROW and
 *		#HASH_FLAG_AUTOSHRINK.  If neither behavior is
 *		desired, use 0.
 * \param func	A #hash_func_t function pointer for a hash function.
 * \param comp	A #hash_comp_t function pointer for a comparison
 *		function.
 * \param resize
 *		A #hash_resize_t function pointer for determining
 *		whether resizing is permitted and/or for notification
 *		of the resize.
 * \param extra	Extra pointer data that should be associated with the
 *		hash table.
 * \param init_mod
 *		An initial modulus for the table.  This will
 *		presumably be extracted by ht_modulus() in a previous
 *		invocation of the application.  A 0 value is valid.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval ENOMEM		Unable to allocate memory.
 */
unsigned long
ht_init(hash_table_t *table, unsigned long flags, hash_func_t func,
	hash_comp_t comp, hash_resize_t resize, void *extra,
	unsigned long init_mod)
{
  int i;
  unsigned long retval;

  initialize_dbpr_error_table(); /* set up error tables */

  if (!table || !func || !comp) /* verify arguments */
    return DB_ERR_BADARGS;

  /* initialize the table */
  table->ht_flags = flags & (HASH_FLAG_AUTOGROW | HASH_FLAG_AUTOSHRINK);
  table->ht_modulus = _hash_prime(init_mod);
  table->ht_count = 0;
  table->ht_rollover = _hash_rollover(table->ht_modulus);
  table->ht_rollunder = _hash_rollunder(table->ht_modulus);
  table->ht_table = 0;
  table->ht_func = func;
  table->ht_comp = comp;
  table->ht_resize = resize;
  table->ht_extra = extra;

  if (table->ht_modulus) { /* have an initial size? */
    if (!(table->ht_table =
	  (link_head_t *)malloc(table->ht_modulus * sizeof(link_head_t))))
      return errno; /* failed to allocate memory? */

    for (i = 0; i < table->ht_modulus; i++) /* initialize the listhead array */
      if ((retval = ll_init(&table->ht_table[i], table))) {
	free(table->ht_table);
	return retval;
      }
  }

  table->ht_magic = HASH_TABLE_MAGIC; /* set the magic number */

  return 0;
}
