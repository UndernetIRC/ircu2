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

unsigned long
_smat_comp(hash_table_t *table, db_key_t *key1, db_key_t *key2)
{
  int i;
  void **objects1, **objects2;

  if (!key1 || !key2 || !dk_key(key1) || !dk_key(key2)) /* if invalid... */
    return 1; /* return "no match" */

  objects1 = dk_key(key1); /* massage these into a useful form */
  objects2 = dk_key(key2);

  /* walk through the elements in the array and compare them */
  for (i = SMAT_LOC_FIRST; i < SMAT_LOC_SECOND; i++)
    if (objects1[i] != objects2[i])
      return 1; /* they don't match */

  return 0; /* we've got a match */
}
