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

struct _st_flush_s {
  smat_table_t *sf_table;	/* pointer to the smat table */
  smat_iter_t	sf_flush;	/* flush function */
  void	       *sf_extra;	/* extra data */
};

static unsigned long
_st_flush_iter(hash_table_t *table, hash_entry_t *ent, void *extra)
{
  unsigned long retval = 0;
  struct _st_flush_s *sf;

  sf = extra;

  /* Remove the object from all lists first */
  _st_remove(sf->sf_table, he_value(ent), ST_REM_FIRST | ST_REM_SECOND);

  /* call the user flush function if so desired */
  if (sf->sf_flush)
    retval = (*sf->sf_flush)(sf->sf_table, he_value(ent), sf->sf_extra);

  _smat_free(he_value(ent)); /* destroy the entry */

  return retval;
}

/** \ingroup dbprim_smat
 * \brief Flush a sparse matrix.
 *
 * This function flushes a sparse matrix--that is, it removes each
 * entry from the matrix.  If a \p flush_func is specified, it will be
 * called on the entry after it has been removed from the table, and
 * may safely call <CODE>free()</CODE>.
 *
 * \param table	A pointer to a #smat_table_t.
 * \param flush_func
 *		A pointer to a callback function used to perform
 *		user-specified actions on an entry after removing it
 *		from the table.  May be \c NULL.  See the
 *		documentation for #smat_iter_t for more information.
 * \param extra	A \c void pointer that will be passed to \p
 *		iter_func.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_FROZEN	The sparse matrix is frozen.
 */
unsigned long
st_flush(smat_table_t *table, smat_iter_t flush_func, void *extra)
{
  struct _st_flush_s sf;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!st_verify(table)) /* verify arguments */
    return DB_ERR_BADARGS;

  /* initialize extra data... */
  sf.sf_table = table;
  sf.sf_flush = flush_func;
  sf.sf_extra = extra;

  /* call into linked list library to flush the list */
  return ht_flush(&table->st_table, _st_flush_iter, &sf);
}
