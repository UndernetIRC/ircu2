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

unsigned long
_st_remove(smat_table_t *table, smat_entry_t *entry, unsigned int remflag)
{
  unsigned long retval;

  if (remflag & ST_REM_HASH) { /* remove from hash table */
    if ((retval = ht_remove(&table->st_table, &entry->se_hash)))
      return retval;
  }

  if (remflag & ST_REM_FIRST) { /* remove from first linked list */
    if ((retval = ll_remove(entry->se_link[SMAT_LOC_FIRST].le_head,
			    &entry->se_link[SMAT_LOC_FIRST])))
      return retval;
  }

  if (remflag & ST_REM_SECOND) { /* remove from second linked list */
    if ((retval = ll_remove(entry->se_link[SMAT_LOC_SECOND].le_head,
			    &entry->se_link[SMAT_LOC_SECOND])))
      return retval;
  }

  if (remflag & ST_REM_FREE) /* free entry */
    _smat_free(entry);

  return 0;
}

/** \ingroup dbprim_smat
 * \brief Remove an entry from a sparse matrix.
 *
 * This function removes the given entry from the specified sparse
 * matrix.
 *
 * \param table	A pointer to a #smat_table_t.
 * \param entry	A pointer to a #smat_entry_t to be removed from the
 *		table.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 * \retval DB_ERR_WRONGTABLE	Entry is not in this sparse matrix.
 * \retval DB_ERR_UNRECOVERABLE	An unrecoverable error occurred while
 *				removing the entry from the table.
 */
unsigned long
st_remove(smat_table_t *table, smat_entry_t *entry)
{
  initialize_dbpr_error_table(); /* initialize error table */

  /* verify arguments */
  if (!st_verify(table) || !se_verify(entry))
    return DB_ERR_BADARGS;

  /* verify entry is in this table */
  if (entry->se_table != table)
    return DB_ERR_WRONGTABLE;

  /* remove the entry from the linked lists and from the hash table */
  if (_st_remove(table, entry, (ST_REM_HASH | ST_REM_FIRST | ST_REM_SECOND |
				ST_REM_FREE)))
    return DB_ERR_UNRECOVERABLE;

  return 0;
}
