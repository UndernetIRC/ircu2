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
    { DEADINT, { DEADINT, DEADPTR, DEADPTR, DEADPTR, DEADPTR, DEADINT },
      DEADPTR, DEADINT, { DEADPTR, DEADINT }, DEADPTR } /* entry[6] */
  };
  hash_entry_t *entry_p;
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

  /* Check ht_find()'s handling of bad arguments */
  check_result(ht_find(0, 0, 0), DB_ERR_BADARGS, "ht_find_noargs",
	       "ht_find() with no valid arguments", 0);
  check_result(ht_find(&table[2], 0, &key[6]), DB_ERR_BADARGS,
	       "ht_find_badtable", "ht_find() with bad table", 0);
  check_result(ht_find(&table[0], 0, 0), DB_ERR_BADARGS,
	       "ht_find_badkey", "ht_find() with bad key", 0);

  /* Check if empty tables return DB_ERR_NOENTRY */
  check_result(ht_find(&table[0], 0, &key[6]), DB_ERR_NOENTRY,
	       "ht_find_emptytable", "ht_find() with empty table", 1);

  /* Check ht_add()'s handling of bad arguments */
  check_result(ht_add(0, 0, 0), DB_ERR_BADARGS, "ht_add_noargs",
	       "ht_add() with no valid arguments", 0);
  check_result(ht_add(&table[2], &entry[0], &key[0]), DB_ERR_BADARGS,
	       "ht_add_badtable", "ht_add() with bad table", 1);
  check_result(ht_add(&table[0], &entry[6], &key[6]), DB_ERR_BADARGS,
	       "ht_add_badentry", "ht_add() with bad entry", 1);
  check_result(ht_add(&table[0], &entry[0], 0), DB_ERR_BADARGS, "ht_add_nokey",
	       "ht_add() with no key", 1);

  /* Freeze the table temporarily */
  ht_flags(&table[0]) |= HASH_FLAG_FREEZE;
  /* Check adds to frozen tables */
  check_result(ht_add(&table[0], &entry[0], &key[0]), DB_ERR_FROZEN,
	       "ht_add_frozen", "ht_add() on frozen table", 1);
  /* Unfreeze the table */
  ht_flags(&table[0]) &= ~HASH_FLAG_FREEZE;

  /* Add an element to a hash table */
  check_result(ht_add(&table[1], &entry[5], &key[5]), 0, "ht_add_t1e5",
	       "Add entry 5 to table 1", 1);

  /* Now try to add the same element to another hash table */
  check_result(ht_add(&table[0], &entry[5], &key[5]), DB_ERR_BUSY,
	       "ht_add_busy", "Add busy entry 5 to table 0", 1);

  /* Try ht_find() to see if it can find elements */
  check_result(ht_find(&table[1], &entry_p, &key[5]), 0, "ht_find_t1e5",
	       "Look up entry 5 in table 1", 1);
  if (entry_p != &entry[5]) {
    printf("FAIL/ht_find_t1e5_entry:Attempt to look up entry 5 retrieved "
	   "%p (correct answer is %p)\n", (void *)entry_p, (void *)&entry[5]);
    return 0;
  } else
    printf("PASS/ht_find_t1e5_entry:Retrieved correct entry %p\n",
	   (void *)entry_p);

  /* Try looking up an element that isn't there in a populated table */
  check_result(ht_find(&table[1], 0, &key[6]), DB_ERR_NOENTRY,
	       "ht_find_t1e6", "Look up non-existant entry 5 in table 1", 1);

  /* Now we know that ht_find() works properly--finish testing ht_add() */
  check_result(ht_add(&table[1], &entry[0], &key[5]), DB_ERR_DUPLICATE,
	       "ht_add_duplicate", "Attempt to add duplicate entry to table",
	       1);

  /* Now try adding several entries to the table */
  check_result(ht_add(&table[0], &entry[0], &key[0]), 0, "ht_add_t0e0",
	       "Add entry 0 to table 0", 1);
  check_result(ht_add(&table[0], &entry[1], &key[1]), 0, "ht_add_t0e1",
	       "Add entry 1 to table 0", 1);
  check_result(ht_add(&table[0], &entry[2], &key[2]), 0, "ht_add_t0e2",
	       "Add entry 2 to table 0", 1);
  check_result(ht_add(&table[0], &entry[3], &key[3]), 0, "ht_add_t0e3",
	       "Add entry 3 to table 0", 1);
  check_result(ht_add(&table[0], &entry[4], &key[4]), 0, "ht_add_t0e4",
	       "Add entry 4 to table 0", 1);

  /* Check to see if an element can be found */
  check_result(ht_find(&table[0], 0, &key[2]), 0, "ht_find_t0e2",
	       "Find entry 2 in table 0", 1);

  return 0;
}
