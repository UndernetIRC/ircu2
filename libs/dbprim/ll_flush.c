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
 * \brief Flush a linked list.
 *
 * This function flushes a linked list--that is, it removes each
 * element from the list.  If a \p flush_func is specified, it will be
 * called on the entry after it has been removed from the list, and
 * may safely call <CODE>free()</CODE>.
 *
 * \param list	A pointer to a #link_head_t.
 * \param flush_func
 *		A pointer to a callback function used to perform
 *		user-specified actions on an element after removing it
 *		from the list.  May be \c NULL.  See the documentation
 *		for #link_iter_t for more information.
 * \param extra	A \c void pointer that will be passed to \p
 *		flush_func.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 */
unsigned long
ll_flush(link_head_t *list, link_iter_t flush_func, void *extra)
{
  link_elem_t *elem;
  unsigned long retval;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ll_verify(list)) /* Verify arguments */
    return DB_ERR_BADARGS;

  while ((elem = list->lh_first)) { /* Walk through the list... */
    ll_remove(list, elem); /* remove the element */
    /* call flush function, erroring out if it fails */
    if (flush_func && (retval = (*flush_func)(list, elem, extra)))
      return retval;
  }

  list->lh_count = 0; /* clear the list head */
  list->lh_first = 0;
  list->lh_last = 0;

  return 0;
}
