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
 * \brief Move an entry within a row or column list.
 *
 * This function allows the specified entry to be shifted within the
 * linked list describing the row or column.  It is very similar to
 * the ll_move() function.
 *
 * \param head	A pointer to a #smat_head_t.
 * \param elem	A pointer to the #smat_entry_t describing the entry to
 *		be moved.
 * \param loc	A #link_loc_t indicating where the entry should be
 *		moved to.
 * \param elem2	A pointer to a #smat_entry_t describing another entry
 *		in the list if \p loc is #LINK_LOC_BEFORE or
 *		#LINK_LOC_AFTER.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_BUSY		\p elem and \p elem2 are the same
 *				entry.
 * \retval DB_ERR_WRONGTABLE	\p elem or \p elem2 are in a different
 *				row or column.
 * \retval DB_ERR_UNUSED	\p elem or \p elem2 are not in any row
 *				or column.
 */
unsigned long
sh_move(smat_head_t *head, smat_entry_t *elem, link_loc_t loc,
	smat_entry_t *elem2)
{
  initialize_dbpr_error_table(); /* initialize error table */

  /* Verify arguments--if elem is set, must be a valid element; if
   * location is before or after, elem must be set
   */
  if (!sh_verify(head) || !se_verify(elem) || (elem2 && !se_verify(elem2)))
    return DB_ERR_BADARGS;

  /* OK, call out to the linked list operation--it'll figure
   * everything else out
   */
  return ll_move(&head->sh_head, &elem->se_link[head->sh_elem], loc,
		 elem2 ? &elem2->se_link[head->sh_elem] : 0);
}
