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

struct _sh_find_s {
  smat_comp_t	sf_comp;	/* comparison function */
  db_key_t     *sf_key;		/* original key */
};

static unsigned long
_sh_find_comp(db_key_t *key, void *data)
{
  struct _sh_find_s *sf;

  sf = dk_key(key);

  /* Call the user's comparison function--with some translation */
  return (*sf->sf_comp)(sf->sf_key, data);
}

/** \ingroup dbprim_smat
 * \brief Find an entry in a row or column of a sparse matrix.
 *
 * This function iterates through the given row or column of a
 * sparse matrix looking for an element that matches the given \p key.
 *
 * \param head	A pointer to a #smat_head_t.
 * \param elem_p
 *		A pointer to a pointer to a #smat_entry_t.  This is a
 *		result pramater.  \c NULL is an invalid value.
 * \param comp_func
 *		A pointer to a comparison function used to compare the
 *		key to a particular entry.  See the documentation for
 *		#smat_comp_t for more information.
 * \param start	A pointer to a #smat_entry_t describing where in the
 *		row or column to start.  If \c NULL is passed, the
 *		beginning of the row or column will be assumed.
 * \param key	A key to search for.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_WRONGTABLE	\p start is not in this row or column.
 * \retval DB_ERR_NOENTRY	No matching entry was found.
 */
unsigned long
sh_find(smat_head_t *head, smat_entry_t **elem_p, smat_comp_t comp_func,
	smat_entry_t *start, db_key_t *key)
{
  unsigned long retval;
  link_elem_t *elem;
  struct _sh_find_s sf;
  db_key_t fkey;

  initialize_dbpr_error_table(); /* initialize error table */

  /* verify arguments */
  if (!sh_verify(head) || !elem_p || !comp_func || !key ||
      (start && !se_verify(start)))
    return DB_ERR_BADARGS;

  /* Set up for the call to ll_find()... */
  sf.sf_comp = comp_func;
  sf.sf_key = key;
  dk_key(&fkey) = &sf;

  /* call into the linked list library to find the element */
  if ((retval = ll_find(&head->sh_head, &elem, _sh_find_comp,
			start ? &start->se_link[head->sh_elem] : 0, &fkey)))
    return retval;

  *elem_p = le_object(elem); /* set the entry pointer correctly */

  return 0;
}
