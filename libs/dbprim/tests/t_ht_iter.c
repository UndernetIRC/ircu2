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
#include <stdio.h>
#include <stdlib.h>

#include "dbprim.h"
#include "dbprim_int.h"

#define TABLE0	(void *)0x76543210

#define OBJECT0 (void *)0x01234567
#define OBJECT1 (void *)0x12345678
#define OBJECT2 (void *)0x23456789
#define OBJECT3 (void *)0x3456789a
#define OBJECT4 (void *)0x456789ab
#define OBJECT5 (void *)0x56789abc
#define OBJECT6 (void *)0x6789abcd
#define OBJECT7 (void *)0x789abcde

#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

struct itercheck {
  hash_table_t *ent_table;
  hash_entry_t *ent_array;
  unsigned int	ent_mask;
};

#define BIT(n)	(1 << (n))
#define BITMASK	0x000000ff

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

static unsigned long
check_iter(hash_table_t *table, hash_entry_t *ent, void *extra)
{
  struct itercheck *itcheck;

  itcheck = extra;

  /* If we were told to return an error, return one */
  if (!itcheck->ent_array)
    return EINVAL;

  /* OK, verify that the hash table is the same as the one we expect */
  if (table != itcheck->ent_table)
    printf("FAIL/ht_iter_functab_e%d:Hash tables do not match\n",
	   dk_len(he_key(ent)));
  else
    printf("PASS/ht_iter_functab_e%d:Hash tables match\n",
	   dk_len(he_key(ent)));

  /* Now verify that everything matches up... */
  if (ent != &itcheck->ent_array[dk_len(he_key(ent))])
    printf("FAIL/ht_iter_funcent_e%d:Entries do not match\n",
	   dk_len(he_key(ent)));
  else
    printf("PASS/ht_iter_funcent_e%d:Entries match\n", dk_len(he_key(ent)));

  /* Finally, set the visited bitmask */
  itcheck->ent_mask |= BIT(dk_len(he_key(ent)));

  return 0;
}

int
main(int argc, char **argv)
{
  int i;
  hash_table_t table[] = { /* some tables to operate on */
    HASH_TABLE_INIT(0, check_func, check_comp, 0, TABLE0),
    { DEADINT, DEADINT, DEADINT, DEADINT, DEADINT, DEADINT, DEADPTR,
      (hash_func_t)DEADPTR, (hash_comp_t)DEADPTR, (hash_resize_t)DEADPTR,
      DEADPTR } /* table[1] */
  };
  hash_entry_t entry[] = { /* some entries to operate on */
    HASH_ENTRY_INIT(OBJECT0),
    HASH_ENTRY_INIT(OBJECT1),
    HASH_ENTRY_INIT(OBJECT2),
    HASH_ENTRY_INIT(OBJECT3),
    HASH_ENTRY_INIT(OBJECT4),
    HASH_ENTRY_INIT(OBJECT5),
    HASH_ENTRY_INIT(OBJECT6),
    HASH_ENTRY_INIT(OBJECT7),
  };
  db_key_t key[] = { /* some keys... */
    DB_KEY_INIT("obj0", 0),
    DB_KEY_INIT("obj1", 1),
    DB_KEY_INIT("obj2", 2),
    DB_KEY_INIT("obj3", 3),
    DB_KEY_INIT("obj4", 4),
    DB_KEY_INIT("obj5", 5),
    DB_KEY_INIT("obj6", 6),
    DB_KEY_INIT("obj7", 7)
  };
  struct itercheck itcheck = { 0, 0, 0 };

  /* initialize the tables with a size */
  if (ht_init(&table[0], 0, check_func, check_comp, 0, TABLE0, 8))
    return -1; /* failed to initialize test */

  /* Add some entries to various hash tables */
  for (i = 0; i < 8; i++)
    if (ht_add(&table[0], &entry[i], &key[i]))
      return -1; /* failed to initialize test */

  /* Check handling of bad arguments */
  check_result(ht_iter(0, 0, 0), DB_ERR_BADARGS, "ht_iter_noargs",
	       "ht_iter() with no valid arguments", 0);
  check_result(ht_iter(&table[1], check_iter, &itcheck), DB_ERR_BADARGS,
	       "ht_iter_badtable", "ht_iter() with bad table", 0);
  check_result(ht_iter(&table[0], 0, &itcheck), DB_ERR_BADARGS,
	       "ht_iter_baditer", "ht_iter() with bad iteration function", 0);

  /* Freeze the table temporarily */
  ht_flags(&table[0]) |= HASH_FLAG_FREEZE;
  /* check if frozen tables are excluded */
  check_result(ht_iter(&table[0], check_iter, &itcheck), DB_ERR_FROZEN,
	       "ht_iter_frozen", "ht_iter() on frozen table", 0);
  /* Unfreeze the table */
  ht_flags(&table[0]) &= ~HASH_FLAG_FREEZE;

  /* Check to see if ht_iter() returns what the iter function returns */
  check_result(ht_iter(&table[0], check_iter, &itcheck), EINVAL,
	       "ht_iter_funcreturn",
	       "ht_iter() returning iteration function return value", 0);

  /* Now iterate through the list */
  itcheck.ent_table = &table[0];
  itcheck.ent_array = entry;
  itcheck.ent_mask = 0;
  check_result(ht_iter(&table[0], check_iter, &itcheck), 0, "ht_iter_function",
	       "ht_iter() iteration", 0);

  /* Did it iterate through them all? */
  if (itcheck.ent_mask == BITMASK)
    printf("PASS/ht_iter_func_mask:ht_iter() visited all items\n");
  else
    printf("FAIL/ht_iter_func_mask:ht_iter() visited only items in bitmask "
	   "0x%02x\n", itcheck.ent_mask);

  return 0;
}
