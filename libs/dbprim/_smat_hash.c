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
_smat_hash(hash_table_t *table, db_key_t *key)
{
  int i, j;
  unsigned int hash = 0;
  void **objects;
  unsigned char *c;

  if (!key || !dk_key(key)) /* if the key's invalid, return 0 */
    return 0;

  objects = dk_key(key); /* get the key--a pair of pointers */

  /* walk through both elements in the array... */
  for (i = SMAT_LOC_FIRST; i < SMAT_LOC_SECOND; i++) {
    c = objects[i]; /* get a char pointer to the pointer value */
    for (j = 0; j < sizeof(void *); j++) /* step through each character */
      hash = (hash * 257) + c[j];
  }

  return hash; /* return the hash value */
}
