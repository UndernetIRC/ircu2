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

/** \ingroup dbprim_smat
 *
 * This function dynamically initializes a sparse matrix table.
 *
 * \param table	A pointer to a #smat_table_t to be initialized.
 * \param flags	A bit-wise OR of #HASH_FLAG_AUTOGROW and
 *		#HASH_FLAG_AUTOSHRINK.  If neither behavior is
 *		desired, use 0.
 * \param resize
 *		A #hash_resize_t function pointer for determining
 *		whether resizing is permitted and/or for notification
 *		of the resize.
 * \param extra	Extra pointer data that should be associated with the
 *		sparse matrix table.
 * \param init_mod
 *		An initial modulus for the table.  This will
 *		presumably be extracted by st_modulus() in a previous
 *		invocation of the application.  A 0 value is valid.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval ENOMEM		Unable to allocate memory.
 */
unsigned long
st_init(smat_table_t *table, unsigned long flags, smat_resize_t resize,
	void *extra, unsigned long init_mod)
{
  unsigned long retval;

  initialize_dbpr_error_table(); /* set up error tables */

  if (!table) /* verify arguments */
    return DB_ERR_BADARGS;

  table->st_resize = resize;

  /* initialize the hash table */
  if ((retval = ht_init(&table->st_table, flags, _smat_hash, _smat_comp,
			_smat_resize, extra, init_mod)))
    return retval;

  table->st_magic = SMAT_TABLE_MAGIC; /* initialize the rest of the table */

  return 0;
}
