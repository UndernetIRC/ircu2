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
#include <stdio.h>
#include <stdlib.h>

#include "dbprim.h"

#define OBJECT	(void *)0x91827364
#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

static void
check_init(hash_entry_t *entry, char *how)
{
  if (entry->he_magic != HASH_ENTRY_MAGIC) /* Verify magic was set */
    printf("FAIL/%s_magic:Initialization failed to set magic number\n", how);
  else
    printf("PASS/%s_magic:Initialization set magic number properly\n", how);

  if (!le_verify(&entry->he_elem)) /* verify element was initialized */
    printf("FAIL/%s_elem:Initialization failed to initialize linked list "
	   "element\n", how);
  else
    printf("PASS/%s_elem:Initialization initialized linked list element\n",
	   how);

  if (entry->he_table != 0) /* verify table was cleared */
    printf("FAIL/%s_table:Initialization failed to clear table\n", how);
  else
    printf("PASS/%s_table:Initialization set table to 0\n", how);

  if (entry->he_hash != 0) /* verify hash value was cleared */
    printf("FAIL/%s_hash:Initialization failed to clear hash value\n", how);
  else
    printf("PASS/%s_hash:Initialization set hash value to 0\n", how);

  if (dk_key(&entry->he_key) != 0) /* verify key value was cleared */
    printf("FAIL/%s_key:Initialization failed to clear database key\n", how);
  else
    printf("PASS/%s_key:Initialization set database key to 0\n", how);

  if (dk_len(&entry->he_key) != 0) /* verify key length was cleared */
    printf("FAIL/%s_keylen:Initialization failed to clear database key "
	   "length\n", how);
  else
    printf("PASS/%s_keylen:Initialization set database key length to 0\n",
	   how);

  if (entry->he_value != OBJECT) /* verify value was set properly */
    printf("FAIL/%s_value:Initialization failed to set value\n", how);
  else
    printf("PASS/%s_value:Initialization set value properly\n", how);
}

/* Check return value of operation and report PASS/FAIL */
static void
check_result(unsigned long result, unsigned long expected, char *test,
	     char *info, int die)
{
  if (result != expected) {
    printf("FAIL/%s:%s incorrectly returned %lu (expected %lu)\n", test, info,
	   result, expected);
    if (die)
      exit(0);
  } else
    printf("PASS/%s:%s correctly returned %lu\n", test, info, result);
}

int
main(int argc, char **argv)
{
  hash_entry_t entry = HASH_ENTRY_INIT(OBJECT);

  /* Check that the static initializer produces a passable structure */
  check_init(&entry, "he_static");

  /* now, check what he_init does with bad arguments */
  check_result(he_init(0, 0), DB_ERR_BADARGS, "he_init_noargs",
	       "he_init() with no valid arguments", 0);

  /* Scramble the structure */
  entry.he_magic = DEADINT;
  entry.he_elem.le_magic = DEADINT;
  entry.he_table = DEADPTR;
  entry.he_hash = DEADINT;
  entry.he_key.dk_key = DEADPTR;
  entry.he_key.dk_len = DEADINT;
  entry.he_value = DEADPTR;

  /* Now try to initialize our structure and see what happens */
  check_result(he_init(&entry, OBJECT), 0, "he_dynamic",
	       "he_init() to dynamically initialize hash entry", 0);

  /* Finally, verify initialization */
  check_init(&entry, "he_dynamic");

  return 0;
}
