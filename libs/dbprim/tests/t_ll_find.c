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

/* Check that a list head matches expectations */
static void
check_list(link_head_t *list, unsigned int count, link_elem_t *head,
	   link_elem_t *tail, char *test, char *info)
{
  if (list->lh_count != count) { /* Check count first */
    printf("FAIL/%s_count:%s: Count mismatch\n", test, info);
    exit(0);
  } else
    printf("PASS/%s_count:%s: Counts match\n", test, info);

  if (list->lh_first != head) { /* then check the head pointer */
    printf("FAIL/%s_first:%s: Head pointer mismatch\n", test, info);
    exit(0);
  } else
    printf("PASS/%s_first:%s: Head pointers match\n", test, info);

  if (list->lh_last != tail) { /* finally check the tail pointer */
    printf("FAIL/%s_last:%s: Tail pointer mismatch\n", test, info);
    exit(0);
  } else
    printf("PASS/%s_last:%s: Tail pointers match\n", test, info);
}

/* Verify that find found element we were expecting */
static void
check_element(link_elem_t *actual, link_elem_t *expected, char *test,
	      char *info)
{
  if (actual != expected)
    printf("FAIL/%s_result:%s: Elements don't match\n", test, info);
  else
    printf("PASS/%s_result:%s: Elements match\n", test, info);
}

/* Comparison function */
static unsigned long
compare(db_key_t *key, void *value)
{
  if (dk_key(key) == value)
    return 0;

  return 1;
}

int
main(int argc, char **argv)
{
  int i;
  link_head_t list[] = { /* some lists to operate on */
    LINK_HEAD_INIT(0),
    LINK_HEAD_INIT(0),
    { DEADINT, DEADINT, DEADPTR, DEADPTR, 0 } /* list[2] is a bad list */
  };
  link_elem_t elem[] = { /* some elements to operate on */
    LINK_ELEM_INIT(OBJECT0),
    LINK_ELEM_INIT(OBJECT1),
    LINK_ELEM_INIT(OBJECT2),
    LINK_ELEM_INIT(OBJECT3),
    LINK_ELEM_INIT(OBJECT4),
    LINK_ELEM_INIT(OBJECT5),
    LINK_ELEM_INIT(OBJECT6),
    { DEADINT, DEADPTR, DEADPTR, DEADPTR, DEADPTR, DEADINT } /* elem[7] */
  };
  link_elem_t *res = 0;
  db_key_t key = DB_KEY_INIT(0, 0);

  /* First, build the lists */
  for (i = 0; i < 5; i++)
    if (ll_add(&list[0], &elem[i], LINK_LOC_TAIL, 0))
      return -1; /* failed to initialize test */

  if (ll_add(&list[1], &elem[5], LINK_LOC_TAIL, 0))
    return -1; /* failed to initialize test */

  /* Baseline checks */
  check_list(&list[0], 5, &elem[0], &elem[4], "ll_find_baseline_l0",
	     "Verify baseline list[0]");
  check_list(&list[1], 1, &elem[5], &elem[5], "ll_find_baseline_l1",
	     "Verify baseline list[1]");

  /* Check to see if ll_find verifies its arguments correctly */
  check_result(ll_find(0, 0, 0, 0, 0), DB_ERR_BADARGS, "ll_find_noargs",
	       "ll_find() with no arguments", 0);
  check_result(ll_find(&list[2], &res, compare, 0, &key), DB_ERR_BADARGS,
	       "ll_find_badlist", "ll_find() with bad list", 0);
  check_result(ll_find(&list[0], 0, compare, 0, &key), DB_ERR_BADARGS,
	       "ll_find_badresult", "ll_find() with bad result", 0);
  check_result(ll_find(&list[0], &res, 0, 0, &key), DB_ERR_BADARGS,
	       "ll_find_badcompare", "ll_find() with bad comparison function",
	       0);
  check_result(ll_find(&list[0], &res, compare, &elem[7], &key),
	       DB_ERR_BADARGS, "ll_find_badstart",
	       "ll_find() with bad start element", 0);
  check_result(ll_find(&list[0], &res, compare, 0, 0), DB_ERR_BADARGS,
	       "ll_find_badkey", "ll_find() with bad key", 0);

  /* OK, verify that it checks that the start element is in the wrong table */
  check_result(ll_find(&list[0], &res, compare, &elem[5], &key),
	       DB_ERR_WRONGTABLE, "ll_find_wrongtable",
	       "ll_find() with start element in wrong table", 0);

  /* Next, see if it can find an element that shouldn't be there */
  check_result(ll_find(&list[0], &res, compare, 0, &key), DB_ERR_NOENTRY,
	       "ll_find_noentry", "ll_find() for non-existant entry", 0);

  /* OK, try to find an element in a single-entry list */
  dk_key(&key) = OBJECT5;
  check_result(ll_find(&list[1], &res, compare, 0, &key), 0,
	       "ll_find_oneentry", "ll_find() for one-entry list", 0);
  check_element(res, &elem[5], "ll_find_oneentry",
		"ll_find() for one-entry list");

  /* Next, try to find the head element... */
  dk_key(&key) = OBJECT0;
  check_result(ll_find(&list[0], &res, compare, 0, &key), 0,
	       "ll_find_head", "ll_find() for head", 0);
  check_element(res, &elem[0], "ll_find_head", "ll_find() for head");

  /* Now the tail element... */
  dk_key(&key) = OBJECT4;
  check_result(ll_find(&list[0], &res, compare, 0, &key), 0,
	       "ll_find_tail", "ll_find() for tail", 0);
  check_element(res, &elem[4], "ll_find_tail", "ll_find() for tail");

  /* Next try the middle... */
  dk_key(&key) = OBJECT2;
  check_result(ll_find(&list[0], &res, compare, 0, &key), 0,
	       "ll_find_middle", "ll_find() for middle", 0);
  check_element(res, &elem[2], "ll_find_middle", "ll_find() for middle");

  /* Now try starting at an arbitrary place in the middle of the list */
  le_object(&elem[3]) = OBJECT1;
  dk_key(&key) = OBJECT1;
  check_result(ll_find(&list[0], &res, compare, &elem[2], &key), 0,
	       "ll_find_start", "ll_find() with start", 0);
  check_element(res, &elem[3], "ll_find_start", "ll_find() with start");

  return 0;
}
