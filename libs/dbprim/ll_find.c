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

/** \ingroup dbprim_link
 * \brief Find an element in a linked list.
 *
 * This function iterates through a linked list looking for an element
 * that matches the given \p key.
 *
 * \param list	A pointer to a #link_head_t.
 * \param elem_p
 *		A pointer to a pointer to a #link_elem_t.  This is a
 *		result parameter.  \c NULL is an invalid value.
 * \param comp_func
 *		A pointer to a comparison function used to compare the
 *		key to a particular element.  See the documentation
 *		for #link_comp_t for more information.
 * \param start	A pointer to a #link_elem_t describing where in the
 *		linked list to start.  If \c NULL is passed, the
 *		beginning of the list will be assumed.
 * \param key	A key to search for.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_WRONGTABLE	\p start is not in this linked list.
 * \retval DB_ERR_NOENTRY	No matching entry was found.
 */
unsigned long
ll_find(link_head_t *list, link_elem_t **elem_p, link_comp_t comp_func,
	link_elem_t *start, db_key_t *key)
{
  link_elem_t *elem;

  initialize_dbpr_error_table(); /* initialize error table */

  /* Verify arguments */
  if (!ll_verify(list) || !elem_p || !comp_func || !key ||
      (start && !le_verify(start)))
    return DB_ERR_BADARGS;

  /* Verify that the start element is in this list */
  if (start && list != start->le_head)
    return DB_ERR_WRONGTABLE;

  /* search the list... */
  for (elem = start ? start : list->lh_first; elem; elem = elem->le_next)
    if (!(*comp_func)(key, elem->le_object)) { /* Compare... */
      *elem_p = elem; /* comparison function must return "0" on match */
      return 0;
    }

  return DB_ERR_NOENTRY; /* Couldn't find the element */
}
