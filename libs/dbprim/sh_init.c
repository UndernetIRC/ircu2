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
 * \brief Dynamically initialize a sparse matrix row or column head.
 *
 * This function dynamically initializes a sparse matrix row or column
 * linked list head.  The \p elem argument specifies whether the
 * object is to be associated with a #SMAT_LOC_FIRST list or a
 * #SMAT_LOC_SECOND list.
 *
 * \param head	A pointer to a #smat_head_t to be initialized.
 * \param elem	Either #SMAT_LOC_FIRST or #SMAT_LOC_SECOND.
 * \param object
 *		A pointer to the object containing the sparse matrix
 *		row or column head.
 *
 * \retval DB_ERR_BADARGS	An invalid argument was given.
 */
unsigned long
sh_init(smat_head_t *head, smat_loc_t elem, void *object)
{
  unsigned long retval;

  initialize_dbpr_error_table(); /* initialize error table */

  /* verify arguments... */
  if (!head || (elem != SMAT_LOC_FIRST && elem != SMAT_LOC_SECOND))
    return DB_ERR_BADARGS;

  /* initialize list head */
  if ((retval = ll_init(&head->sh_head, object)))
    return retval;

  head->sh_elem = elem; /* initialize list head */
  head->sh_table = 0;

  head->sh_magic = SMAT_HEAD_MAGIC; /* set magic number */

  return 0;
}
