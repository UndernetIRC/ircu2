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

/** \ingroup dbprim_hash
 * \brief Dynamically initialize a hash table entry.
 *
 * This function dynamically initializes a hash table entry.
 *
 * \param entry	A pointer to a #hash_entry_t to be initialized.
 * \param value	A pointer to \c void which will be the value of the
 *		hash table entry.
 *
 * \retval DB_ERR_BADARGS	A \c NULL pointer was passed for \p
 *				entry.
 */
unsigned long
he_init(hash_entry_t *entry, void *value)
{
  unsigned long retval;

  initialize_dbpr_error_table(); /* initialize error table */

  if (!entry) /* verify arguments */
    return DB_ERR_BADARGS;

  /* initialize the link entry */
  if ((retval = le_init(&entry->he_elem, entry)))
    return retval;

  entry->he_table = 0; /* initialize the rest of the hash entry */
  entry->he_hash = 0;
  entry->he_key.dk_key = 0;
  entry->he_key.dk_len = 0;
  entry->he_value = value;

  entry->he_magic = HASH_ENTRY_MAGIC; /* set the magic number */

  return 0;
}
