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
#include "dbprim_int.h"

#define TABLE0	(void *)0x76543210
#define TABLE1	(void *)0x87654321

#define OBJECT0 (void *)0x01234567
#define OBJECT1 (void *)0x12345678
#define OBJECT2 (void *)0x23456789
#define OBJECT3 (void *)0x3456789a
#define OBJECT4 (void *)0x456789ab

#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

/* Check return value of add operation and report PASS/FAIL */
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

static unsigned long
check_func(hash_table_t *table, db_key_t *key)
{
  return dk_len(key);
}

static unsigned long
check_comp(hash_table_t *table, db_key_t *key1, db_key_t *key2)
{
  return (!(dk_len(key1) == dk_len(key2) && dk_key(key1) == dk_key(key2)));
}

int
main(int argc, char **argv)
{
  int i;
  hash_table_t table[] = { /* some tables to operate on */
    HASH_TABLE_INIT(0, check_func, check_comp, 0, TABLE0),
    HASH_TABLE_INIT(0, check_func, check_comp, 0, TABLE1),
    { DEADINT, DEADINT, DEADINT, DEADINT, DEADINT, DEADINT, DEADPTR,
      (hash_func_t)DEADPTR, (hash_comp_t)DEADPTR, (hash_resize_t)DEADPTR,
      DEADPTR } /* table[2] */
  };
  hash_entry_t entry[] = { /* some entries to operate on */
    HASH_ENTRY_INIT(OBJECT0),
    HASH_ENTRY_INIT(OBJECT1),
    HASH_ENTRY_INIT(OBJECT2),
    HASH_ENTRY_INIT(OBJECT3),
    HASH_ENTRY_INIT(OBJECT4),
  };
  db_key_t key[] = { /* some keys... */
    DB_KEY_INIT("obj0", 0),
    DB_KEY_INIT("obj1", 1),
    DB_KEY_INIT("obj2", 2),
    DB_KEY_INIT("obj3", 3),
    DB_KEY_INIT("obj4", 4),
  };

  /* initialize the tables with a size */
  if (ht_init(&table[0], 0, check_func, check_comp, 0, TABLE0, 7) ||
      ht_init(&table[1], 0, check_func, check_comp, 0, TABLE1, 7) ||
      !table[0].ht_table || !table[1].ht_table)
    return -1; /* failed to initialize test */

  /* Add some entries to various hash tables */
  for (i = 0; i < 5; i++)
    if (ht_add(&table[0], &entry[i], &key[i]))
      return -1; /* failed to initialize test */

  /* Check handling of bad arguments */
  check_result(ht_free(0), DB_ERR_BADARGS, "ht_free_noargs",
	       "ht_free() with no valid arguments", 0);
  check_result(ht_free(&table[2]), DB_ERR_BADARGS, "ht_free_badtable",
	       "ht_free() with bad table", 0);

  /* Freeze the table temporarily */
  ht_flags(&table[1]) |= HASH_FLAG_FREEZE;
  /* check if frozen tables are excluded */
  check_result(ht_free(&table[1]), DB_ERR_FROZEN, "ht_free_frozen",
	       "ht_free() on frozen table", 1);
  /* Unfreeze the table */
  ht_flags(&table[1]) &= ~HASH_FLAG_FREEZE;

  /* Check if non-empty tables are excluded */
  check_result(ht_free(&table[0]), DB_ERR_NOTEMPTY, "ht_free_nonempty",
	       "ht_free() on non-empty table", 0);

  /* OK, now try to free the table */
  check_result(ht_free(&table[1]), 0, "ht_free_t0", "ht_free() on empty table",
	       1);

  /* Verify that table pointer is now 0 */
  if (table[1].ht_table != 0)
    printf("FAIL/ht_free_t0_table:Table not cleared properly\n");
  else
    printf("PASS/ht_free_t0_table:Table properly cleared\n");

  return 0;
}
