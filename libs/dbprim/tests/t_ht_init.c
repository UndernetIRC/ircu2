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

#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

static void
check_init(hash_table_t *table, unsigned long flags, unsigned long mod,
	   unsigned long over, unsigned long under, hash_func_t func,
	   hash_comp_t comp, void *extra, char *how)
{
  if (table->ht_magic != HASH_TABLE_MAGIC) /* Verify magic was set */
    printf("FAIL/%s_magic:Initialization failed to set magic number\n", how);
  else
    printf("PASS/%s_magic:Initialization set magic number properly\n", how);

  if (table->ht_flags != flags) /* verify flags were set */
    printf("FAIL/%s_flags:Initialization failed to set flags\n", how);
  else
    printf("PASS/%s_flags:Initialization set flags properly\n", how);

  if (table->ht_modulus != mod) /* verify modulus was set */
    printf("FAIL/%s_modulus:Initialization failed to set modulus to %ld "
	   "(%ld instead)\n", how, mod, table->ht_modulus);
  else
    printf("PASS/%s_modulus:Initialization set modulus to %ld\n", how, mod);

  if (table->ht_count != 0) /* verify count was set */
    printf("FAIL/%s_count:Initialization failed to clear count\n", how);
  else
    printf("PASS/%s_count:Initialization set count to 0\n", how);

  if (table->ht_rollover != over) /* verify rollover was set */
    printf("FAIL/%s_rollover:Initialization failed to set rollover to %ld "
	   "(%ld instead)\n", how, over, table->ht_rollover);
  else
    printf("PASS/%s_rollover:Initialization set rollover to %ld\n", how, over);

  if (table->ht_rollunder != under) /* verify rollunder was set */
    printf("FAIL/%s_rollunder:Initialization failed to set rollunder to %ld "
	   "(%ld instead)\n", how, under, table->ht_rollunder);
  else
    printf("PASS/%s_rollunder:Initialization set rollunder to %ld\n", how,
	   under);

  if (table->ht_func != func) /* verify func was set */
    printf("FAIL/%s_func:Initialization failed to set func\n", how);
  else
    printf("PASS/%s_func:Initialization set func properly\n", how);

  if (table->ht_comp != comp) /* verify comp was set */
    printf("FAIL/%s_comp:Initialization failed to set comp\n", how);
  else
    printf("PASS/%s_comp:Initialization set comp properly\n", how);

  if (table->ht_resize != 0) /* verify resize was set */
    printf("FAIL/%s_rsize:Initialization failed to set resize\n", how);
  else
    printf("PASS/%s_rsize:Initialization set resize properly\n", how);

  if (table->ht_extra != extra) /* verify extra was set */
    printf("FAIL/%s_extra:Initialization failed to set extra\n", how);
  else
    printf("PASS/%s_extra:Initialization set extra properly\n", how);

  if (mod == 0) {
    if (table->ht_table != 0) /* verify that table was not allocated */
      printf("FAIL/%s_table:Initialization failed to clear table\n", how);
    else
      printf("PASS/%s_table:Initialization set table to 0\n", how);
  } else {
    int i;

    if (table->ht_table == 0) /* verify that table was not allocated */
      printf("FAIL/%s_table:Initialization failed to set table\n", how);
    else
      printf("PASS/%s_table:Initialization set table properly\n", how);

    for (i = 0; i < mod; i++) /* verify buckets initialized */
      if (table->ht_table == 0 || i >= table->ht_modulus ||
	  !ll_verify(&table->ht_table[i]))
	printf("FAIL/%s_bucket%d:Initialization failed to initialize "
	       "bucket %d\n", how, i, i);
      else
	printf("PASS/%s_bucket%d:Initialization initialized bucket "
	       "%d properly\n", how, i, i);
  }
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

/* Scramble the table */
static void
scramble(hash_table_t *table)
{
  table->ht_magic = DEADINT;
  table->ht_flags = DEADINT;
  table->ht_modulus = DEADINT;
  table->ht_count = DEADINT;
  table->ht_rollover = DEADINT;
  table->ht_rollunder = DEADINT;
  table->ht_table = DEADPTR;
  table->ht_func = (hash_func_t)DEADPTR;
  table->ht_comp = (hash_comp_t)DEADPTR;
  table->ht_extra = DEADPTR;
}

static unsigned long
check_func(hash_table_t *table, db_key_t *key)
{
  return 0;
}

static unsigned long
check_comp(hash_table_t *table, db_key_t *key1, db_key_t *key2)
{
  return 0;
}

int
main(int argc, char **argv)
{
  unsigned long mod;
  hash_table_t table = HASH_TABLE_INIT(0x80010000 | HASH_FLAG_AUTOGROW,
				       check_func, check_comp, 0, 0);

  /* Check that the static initializer produces a passable structure */
  check_init(&table, HASH_FLAG_AUTOGROW, 0, 0, 0, check_func, check_comp,
	     0, "ht_static");

  /* now, check what ht_init does with bad arguments */
  check_result(ht_init(0, 0, 0, 0, 0, 0, 0), DB_ERR_BADARGS, "ht_init_noargs",
	       "ht_init() with no valid arguments", 0);
  check_result(ht_init(0, 0, check_func, check_comp, 0, 0, 0), DB_ERR_BADARGS,
	       "ht_init_notable", "ht_init() with no table", 0);
  check_result(ht_init(&table, 0, 0, check_comp, 0, 0, 0), DB_ERR_BADARGS,
	       "ht_init_nofunc", "ht_init() with no hash function", 0);
  check_result(ht_init(&table, 0, check_func, 0, 0, 0, 0), DB_ERR_BADARGS,
	       "ht_init_nocomp", "ht_init() with no comparison function", 0);

  /* Scramble the structure */
  scramble(&table);

  /* Now try to initialize our structure with a 0 mod and see what happens */
  check_result(ht_init(&table, 0x80010000 | HASH_FLAG_AUTOGROW, check_func,
		       check_comp, 0, 0, 0), 0, "ht_dynamic_nomod",
	       "ht_init() with zero modulus", 0);
  check_init(&table, HASH_FLAG_AUTOGROW, 0, 0, 0, check_func, check_comp,
	     0, "ht_dynamic_nomod");

  /* Scramble the structure again */
  scramble(&table);

  /* Now try to initialize our structure with a non-0 mod and see what
   * happens
   */
  check_result(ht_init(&table, 0x80010000 | HASH_FLAG_AUTOGROW, check_func,
		       check_comp, 0, 0, 6), 0, "ht_dynamic_mod6",
	       "ht_init() with non-zero modulus", 0);
  mod = 7; /* next prime after 6 */
  check_init(&table, HASH_FLAG_AUTOGROW, mod, (mod * 4) / 3, (mod * 3) / 4,
	     check_func, check_comp, 0, "ht_dynamic_mod6");

  return 0;
}
