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
#define OBJECT5 (void *)0x56789abc
#define OBJECT6 (void *)0x6789abcd

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
    HASH_ENTRY_INIT(OBJECT5),
    HASH_ENTRY_INIT(OBJECT6),
    { DEADINT, { DEADINT, DEADPTR, DEADPTR, DEADPTR, DEADPTR, DEADINT },
      DEADPTR, DEADINT, { DEADPTR, DEADINT }, DEADPTR } /* entry[7] */
  };
  db_key_t key[] = { /* some keys... */
    DB_KEY_INIT("obj0", 0),
    DB_KEY_INIT("obj1", 1),
    DB_KEY_INIT("obj2", 2),
    DB_KEY_INIT("obj3", 3),
    DB_KEY_INIT("obj4", 4),
    DB_KEY_INIT("obj5", 5),
    DB_KEY_INIT("obj6", 6)
  };

  /* initialize the tables with a size */
  if (ht_init(&table[0], 0, check_func, check_comp, 0, TABLE0, 7) ||
      ht_init(&table[1], 0, check_func, check_comp, 0, TABLE1, 7))
    return -1; /* failed to initialize test */

  /* Add some entries to various hash tables */
  for (i = 0; i < 5; i++)
    if (ht_add(&table[0], &entry[i], &key[i]))
      return -1; /* failed to initialize test */
  if (ht_add(&table[1], &entry[5], &key[5]))
    return -1; /* failed to initialize test */

  /* Check handling of bad arguments */
  check_result(ht_remove(0, 0), DB_ERR_BADARGS, "ht_remove_noargs",
	       "ht_remove() with no valid arguments", 0);
  check_result(ht_remove(&table[2], &entry[0]), DB_ERR_BADARGS,
	       "ht_remove_badtable", "ht_remove() with bad table", 1);
  check_result(ht_remove(&table[0], &entry[7]), DB_ERR_BADARGS,
	       "ht_remove_badentry", "ht_remove() with bad entry", 1);

  /* Check if unused entry is excluded */
  check_result(ht_remove(&table[0], &entry[6]), DB_ERR_UNUSED,
	       "ht_remove_unused", "ht_remove() with unused entry", 1);
  /* How about wrong table? */
  check_result(ht_remove(&table[0], &entry[5]), DB_ERR_WRONGTABLE,
	       "ht_remove_wrongtable", "ht_remove() with entry in wrong table",
	       1);

  /* Freeze the table temporarily */
  ht_flags(&table[0]) |= HASH_FLAG_FREEZE;
  /* check if frozen tables are excluded */
  check_result(ht_remove(&table[0], &entry[0]), DB_ERR_FROZEN,
	       "ht_remove_frozen", "ht_remove() on frozen table", 1);
  /* Unfreeze the table */
  ht_flags(&table[0]) &= ~HASH_FLAG_FREEZE;

  /* OK, try removing an entry */
  check_result(ht_remove(&table[0], &entry[0]), 0, "ht_remove_t0e0",
	       "Remove entry 0 in table 0", 1);
  /* check to see if we can find it */
  check_result(ht_find(&table[0], 0, &key[0]), DB_ERR_NOENTRY,
	       "ht_remove_find_t0e0", "Attempt to look up removed entry", 0);

  /* Check to see if the removed entry's table pointer is 0 */
  if (he_table(&entry[0]) != 0)
    printf("FAIL/ht_remove_t0e0_table:Table pointer not reset\n");
  else
    printf("PASS/ht_remove_t0e0_table:Table pointer properly reset\n");

  /* Finally, check to see if the count is correct */
  if (ht_count(&table[0]) != 4)
    printf("FAIL/ht_remove_t0e0_count:Table count not adjusted; is %ld, "
	   "should be 4\n", ht_count(&table[0]));
  else
    printf("PASS/ht_remove_t0e0_count:Table count correctly adjusted\n");

  return 0;
}
