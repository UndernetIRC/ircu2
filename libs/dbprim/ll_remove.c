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
 * \brief Remove an element from a linked list.
 *
 * This function removes a specified element from a linked list.
 *
 * \param list	A pointer to a #link_head_t.
 * \param elem	A pointer to the #link_elem_t describing the element
 *		to be removed.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_UNUSED	\p elem is not in a linked list.
 * \retval DB_ERR_WRONGTABLE	\p elem is not in this linked list.
 */
unsigned long
ll_remove(link_head_t *list, link_elem_t *elem)
{
  initialize_dbpr_error_table(); /* initialize error table */

  if (!ll_verify(list) || !le_verify(elem)) /* First, verify the arguments */
    return DB_ERR_BADARGS;

  if (!elem->le_head) /* is the element even being used? */
    return DB_ERR_UNUSED;
  if (list != elem->le_head) /* Verify that the element is in this list */
    return DB_ERR_WRONGTABLE;

  list->lh_count--; /* OK, reduce the list count */

  if (elem->le_next) /* Clip the list back together */
    elem->le_next->le_prev = elem->le_prev;
  if (elem->le_prev)
    elem->le_prev->le_next = elem->le_next;
  else
    list->lh_first = elem->le_next;

  if (list->lh_last == elem) /* Make sure we know where the last element is */
    list->lh_last = elem->le_prev;

  elem->le_next = 0; /* Clear the element out */
  elem->le_prev = 0;
  elem->le_head = 0;

  return 0;
}
