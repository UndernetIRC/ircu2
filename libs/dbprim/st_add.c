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
#include <errno.h>

#include "dbprim.h"
#include "dbprim_int.h"

RCSTAG("@(#)$Id$");

/** \ingroup dbprim_smat
 * \brief Add an entry to a sparse matrix.
 *
 * This function adds an entry to a sparse matrix.  The entry is
 * referenced in three different places, thus the complex set of
 * arguments.  This function will allocate a #smat_entry_t and return
 * it through the \c entry_p result parameter.
 *
 * \param table	A pointer to a #smat_table_t.
 * \param entry_p
 *		A pointer to a pointer to a #smat_entry_t.  This is a
 *		result parameter.  If \c NULL is passed, the addition
 *		will be performed and an appropriate error code
 *		returned.
 * \param head1	A pointer to a #smat_head_t representing a
 *		#SMAT_LOC_FIRST sparse matrix list.
 * \param loc1	A #link_loc_t indicating where the entry should be
 *		added for \c head1.
 * \param ent1	A pointer to a #smat_entry_t describing another
 *		element in the list represented by \c head1 if \p loc1
 *		is #LINK_LOC_BEFORE or #LINK_LOC_AFTER.
 * \param head2	A pointer to a #smat_head_t representing a
 *		#SMAT_LOC_SECOND sparse matrix list.
 * \param loc2	A #link_loc_t indicating where the entry should be
 *		added for \c head2.
 * \param ent2	A pointer to a #smat_entry_t describing another
 *		element in the list represented by \c head2 if \p loc2
 *		is #LINK_LOC_BEFORE or #LINK_LOC_AFTER.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_BUSY		One of the arguments is already in the
 *				table.
 * \retval DB_ERR_FROZEN	The table is currently frozen.
 * \retval DB_ERR_NOTABLE	The bucket table has not been
 *				allocated and automatic growth is not
 *				enabled.
 * \retval DB_ERR_WRONGTABLE	One of the arguments was not in the
 *				proper table or list.
 * \retval DB_ERR_UNUSED	One of the \c ent arguments is not
 *				presently in a list.
 * \retval DB_ERR_UNRECOVERABLE	An unrecoverable error occurred while
 *				resizing the table.
 * \retval ENOMEM		No memory could be allocated for the
 *				#smat_entry_t structure.
 */
unsigned long
st_add(smat_table_t *table, smat_entry_t **entry_p,
       smat_head_t *head1, link_loc_t loc1, smat_entry_t *ent1,
       smat_head_t *head2, link_loc_t loc2, smat_entry_t *ent2)
{
  smat_entry_t *se;
  unsigned long retval = 0;
  unsigned int freeflags = 0;
  db_key_t key;

  initialize_dbpr_error_table(); /* initialize error table */

  /* Verify arguments--like ll_add(), but has to account for two seperate
   * linked lists
   */
  if (!st_verify(table) || !sh_verify(head1) || !sh_verify(head2) ||
      head1->sh_elem != SMAT_LOC_FIRST || head2->sh_elem != SMAT_LOC_SECOND ||
      (ent1 && !se_verify(ent1)) || (ent2 && !se_verify(ent2)) ||
      ((loc1 == LINK_LOC_BEFORE || loc1 == LINK_LOC_AFTER) && !ent1) ||
      ((loc2 == LINK_LOC_BEFORE || loc2 == LINK_LOC_AFTER) && !ent2))
    return DB_ERR_BADARGS;

  /* verify that everything's in the right tables... */
  if ((head1->sh_table && head1->sh_table != table) ||
      (head2->sh_table && head2->sh_table != table) ||
      (ent1 && ent1->se_table != table) ||
      (ent2 && ent2->se_table != table))
    return DB_ERR_WRONGTABLE;

  if (!(se = _smat_alloc())) /* get an entry object */
    return ENOMEM;

  freeflags |= ST_REM_FREE; /* entry has been allocated */

  se->se_object[SMAT_LOC_FIRST] = sh_object(head1); /* set up the hash key */
  se->se_object[SMAT_LOC_SECOND] = sh_object(head2);
  dk_key(&key) = &se->se_object;
  dk_len(&key) = 0;

  /* add the element to the hash table first */
  if ((retval = ht_add(&table->st_table, &se->se_hash, &key)))
    goto error;

  freeflags |= ST_REM_HASH; /* entry must be removed from hash table */

  /* add the element to the first linked list */
  if ((retval = ll_add(&head1->sh_head, &se->se_link[SMAT_LOC_FIRST], loc1,
		       ent1 ? &ent1->se_link[SMAT_LOC_FIRST] : 0)))
    goto error;

  freeflags |= ST_REM_FIRST; /* entry must be removed from linked list 1 */

  /* add the element to the second linked list */
  if ((retval = ll_add(&head2->sh_head, &se->se_link[SMAT_LOC_SECOND], loc2,
		       ent2 ? &ent2->se_link[SMAT_LOC_SECOND] : 0)))
    goto error;

  head1->sh_table = head2->sh_table = table; /* remember our table */
  se->se_table = table;

  if (!entry_p) /* user wants to know which entry it is */
    *entry_p = se;

  return 0; /* all done! */

 error:
  /* unlink entry from linked list 1 */
  if ((freeflags & ST_REM_FIRST) &&
      ll_remove(&head1->sh_head, &se->se_link[SMAT_LOC_FIRST]))
    return DB_ERR_UNRECOVERABLE;

  /* remove element from hash table */
  if ((freeflags & ST_REM_HASH) && ht_remove(&table->st_table, &se->se_hash))
    return DB_ERR_UNRECOVERABLE;

  /* return element to free pool */
  if (freeflags & ST_REM_FREE)
    _smat_free(se);

  return retval; /* return error */
}
