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
 * \brief Dynamically initialize a linked list head.
 *
 * This function dynamically initializes a linked list head.
 *
 * \param list	A pointer to a #link_head_t to be initialized.
 * \param extra	A pointer to \c void containing extra pointer data
 *		associated with the linked list.
 *
 * \retval DB_ERR_BADARGS	A \c NULL pointer was passed for \p
 *				list.
 */
unsigned long
ll_init(link_head_t *list, void *extra)
{
  initialize_dbpr_error_table(); /* set up error tables */

  if (!list) /* must have a list head */
    return DB_ERR_BADARGS;

  list->lh_count = 0; /* initialize the list head */
  list->lh_first = 0;
  list->lh_last = 0;
  list->lh_extra = extra;

  list->lh_magic = LINK_HEAD_MAGIC; /* set the magic number */

  return 0;
}
