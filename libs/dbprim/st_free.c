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
 * \brief Free memory used by an empty sparse matrix table.
 *
 * This function releases the memory used by the bucket table of the
 * empty hash table associated with a sparse matrix.
 *
 * \param table	A pointer to a #smat_table_t.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval DB_ERR_FROZEN	The table is frozen.
 * \retval DB_ERR_NOTEMPTY	The table is not empty.
 */
unsigned long
st_free(smat_table_t *table)
{
  initialize_dbpr_error_table(); /* initialize error table */

  if (!st_verify(table)) /* verify argument */
    return DB_ERR_BADARGS;

  return ht_free(&table->st_table); /* call out to hash */
}
