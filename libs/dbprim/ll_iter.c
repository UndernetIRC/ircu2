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
 * \brief Iterate over each entry in a linked list.
 *
 * This function iterates over a linked list, executing the given \p
 * iter_func for each entry.
 *
 * \param list	A pointer to a #link_head_t.
 * \param iter_func
 *		A pointer to a callback function used to perform
 *		user-specified actions on an element in a linked
 *		list.  \c NULL is an invalid value.  See the
 *		documentation for #link_iter_t for more information.
 * \param extra	A \c void pointer that will be passed to \p
 *		iter_func.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 */
unsigned long
ll_iter(link_head_t *list, link_iter_t iter_func, void *extra)
{
  unsigned long retval;
  link_elem_t *elem;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!ll_verify(list) || !iter_func) /* verify arguments */
    return DB_ERR_BADARGS;

  /* Walk through list and return first non-zero return value */
  for (elem = list->lh_first; elem; elem = elem->le_next)
    if ((retval = (*iter_func)(list, elem, extra)))
      return retval;

  return 0;
}
