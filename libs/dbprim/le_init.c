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
 * \brief Dynamically initialize a linked list element.
 *
 * This function dynamically initializes a linked list element.
 *
 * \param elem	A pointer to a #link_elem_t to be initialized.
 * \param object
 *		A pointer to \c void used to represent the object
 *		associated with the element.  May not be \c NULL.
 *
 * \retval DB_ERR_BADARGS	A \c NULL pointer was passed for \p
 *				elem or \p object.
 */
unsigned long
le_init(link_elem_t *elem, void *object)
{
  initialize_dbpr_error_table(); /* initialize error table */

  if (!elem || !object) /* verify arguments */
    return DB_ERR_BADARGS;

  elem->le_next = 0; /* initialize the element */
  elem->le_prev = 0;
  elem->le_object = object;
  elem->le_head = 0;
  elem->le_flags = 0;

  elem->le_magic = LINK_ELEM_MAGIC; /* set the magic number */

  return 0;
}
