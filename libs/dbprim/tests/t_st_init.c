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

#define TABLE0	(void *)0x76543210

#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

static void
check_init(smat_table_t *table, unsigned long flags, unsigned long mod,
	   smat_resize_t rsize, void *extra, char *how)
{
  if (table->st_magic != SMAT_TABLE_MAGIC) /* Verify magic was set */
    printf("FAIL/%s_magic:Initialization failed to set magic number\n", how);
  else
    printf("PASS/%s_magic:Initialization set magic number properly\n", how);

  if (!ht_verify(&table->st_table)) /* Verify hash table initialized */
    printf("FAIL/%s_htinit:Initialization failed to initialize hash table\n",
	   how);
  else
    printf("PASS/%s_htinit:Initialization initialized hash table properly\n",
	   how);

  if (ht_flags(&table->st_table) != flags) /* verify flags were set */
    printf("FAIL/%s_hflags:Initialization failed to set flags\n", how);
  else
    printf("PASS/%s_hflags:Initialization set flags properly\n", how);

  if (ht_modulus(&table->st_table) != mod) /* verify modulus was set */
    printf("FAIL/%s_hmodulus:Initialization failed to set modulus to %ld "
	   "(%ld instead)\n", how, mod, ht_modulus(&table->st_table));
  else
    printf("PASS/%s_hmodulus:Initialization set modulus to %ld\n", how, mod);

  if (ht_func(&table->st_table) != _smat_hash) /* verify func was set */
    printf("FAIL/%s_hfunc:Initialization failed to set hash func\n", how);
  else
    printf("PASS/%s_hfunc:Initialization set hash func properly\n", how);

  if (ht_comp(&table->st_table) != _smat_comp) /* verify comp was set */
    printf("FAIL/%s_hcomp:Initialization failed to set hash comp\n", how);
  else
    printf("PASS/%s_hcomp:Initialization set hash comp properly\n", how);

  if (ht_rsize(&table->st_table) != _smat_resize) /* verify resize was set */
    printf("FAIL/%s_hrsize:Initialization failed to set hash resize\n", how);
  else
    printf("PASS/%s_hrsize:Initialization set hash resize properly\n", how);

  if (table->st_resize != rsize) /* verify resize was set */
    printf("FAIL/%s_rsize:Initialization failed to set resize\n", how);
  else
    printf("PASS/%s_rsize:Initialization set resize properly\n", how);

  if (ht_extra(&table->st_table) != extra) /* verify extra was set */
    printf("FAIL/%s_hextra:Initialization failed to set extra\n", how);
  else
    printf("PASS/%s_hextra:Initialization set extra properly\n", how);
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
scramble(smat_table_t *table)
{
  table->st_magic = DEADINT;
  table->st_resize = (smat_resize_t)DEADPTR;
  table->st_table.ht_magic = DEADINT;
  ht_flags(&table->st_table) = DEADINT;
  ht_modulus(&table->st_table) = DEADINT;
  ht_func(&table->st_table) = (hash_func_t)DEADPTR;
  ht_comp(&table->st_table) = (hash_comp_t)DEADPTR;
  ht_extra(&table->st_table) = DEADPTR;
}

static unsigned long
check_rsize(smat_table_t *tab, unsigned long new_mod)
{
  return 0;
}

int
main(int argc, char **argv)
{
  smat_table_t table = SMAT_TABLE_INIT(0x80010000 | HASH_FLAG_AUTOGROW,
				       check_rsize, TABLE0);

  /* Check that the static initializer produces a passable structure */
  check_init(&table, HASH_FLAG_AUTOGROW, 0, check_rsize, TABLE0, "st_static");

  /* now, check what ht_init does with bad arguments */
  check_result(st_init(0, 0, 0, 0, 0), DB_ERR_BADARGS, "st_init_noargs",
	       "st_init() with no valid arguments", 0);

  /* Scramble the structure */
  scramble(&table);

  /* Now try to initialize our structure with a 0 mod and see what happens */
  check_result(st_init(&table, 0x80010000 | HASH_FLAG_AUTOGROW, check_rsize,
		       TABLE0, 0), 0, "st_dynamic_nomod",
	       "st_init() with zero modulus", 0);
  check_init(&table, HASH_FLAG_AUTOGROW, 0, check_rsize, TABLE0,
	     "st_dynamic_nomod");

  /* Scramble the structure again */
  scramble(&table);

  /* Now try to initialize our structure with a non-0 mod and see what
   * happens
   */
  check_result(st_init(&table, 0x80010000 | HASH_FLAG_AUTOGROW, check_rsize,
		       TABLE0, 6), 0, "st_dynamic_mod6",
	       "st_init() with non-zero modulus", 0);
  check_init(&table, HASH_FLAG_AUTOGROW, 7, check_rsize, TABLE0,
	     "st_dynamic_mod6");

  return 0;
}
