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
 * \brief Resize a sparse matrix table.
 *
 * This function resizes the hash table associated with a sparse
 * matrix based on the \p new_size parameter.  See the documentation
 * for ht_resize() for more information.
 *
 * \param table	A pointer to a #smat_table_t.
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
st_resize(smat_table_t *table, unsigned long new_size)
{
  initialize_dbpr_error_table(); /* initialize error table */

  if (!st_verify(table)) /* verify that it's really a table */
    return DB_ERR_BADARGS;

  return ht_resize(&table->st_table, new_size); /* call out to hash */
}
