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
 * \brief Find an entry in a sparse matrix.
 *
 * This function looks up the entry matching the given \p head1 and \p
 * head2.
 *
 * \param table	A pointer to a #smat_table_t.
 * \param entry_p
 *		A pointer to a pointer to a #smat_entry_t.  This is a
 *		result parameter.  If \c NULL is passed, the lookup
 *		will be performed and an appropriate error code
 *		returned.
 * \param head1	A pointer to a #smat_head_t initialized to
 *		#SMAT_LOC_FIRST.
 * \param head2	A pointer to a #smat_head_t initialized to
 *		#SMAT_LOC_SECOND.
 *
 * \retval DB_ERR_BADARGS	An argument was invalid.
 * \retval DB_ERR_WRONGTABLE	One or both of \p head1 or \p head2
 *				are not referenced in this table.
 * \retval DB_ERR_NOENTRY	No matching entry was found.
 */
unsigned long
st_find(smat_table_t *table, smat_entry_t **entry_p, smat_head_t *head1,
	smat_head_t *head2)
{
  hash_entry_t *ent;
  unsigned long retval;
  void *object[2];
  db_key_t key;

  initialize_dbpr_error_table(); /* initialize error table */

  /* Verify arguments */
  if (!st_verify(table) || !sh_verify(head1) || !sh_verify(head2) ||
      head1->sh_elem != SMAT_LOC_FIRST || head2->sh_elem != SMAT_LOC_SECOND)
    return DB_ERR_BADARGS;

  /* If there are no entries in one of the lists, then return "no entry" */
  if (!head1->sh_table || !head2->sh_table || head1->sh_head.lh_count == 0 ||
      head2->sh_head.lh_count == 0)
    return DB_ERR_NOENTRY;

  /* verify that everything's in the right tables */
  if (head1->sh_table != table || head2->sh_table != table)
    return DB_ERR_WRONGTABLE;

  /* Build the search key */
  object[SMAT_LOC_FIRST] = sh_object(head1);
  object[SMAT_LOC_SECOND] = sh_object(head2);
  dk_key(&key) = object;
  dk_len(&key) = 0;

  /* look up the entry */
  if ((retval = ht_find(&table->st_table, &ent, &key)))
    return retval;

  /* If the user wants the object, return it to him */
  if (entry_p)
    *entry_p = he_value(ent);

  return 0; /* search successful */
}
