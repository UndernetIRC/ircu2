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
#define OBJECT7 (void *)0x789abcde

#define OBJECT8 (void *)0x89abcdef

#define OBJECT9 (void *)0x9abcdef0

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
	   link_elem_t *tail, int idx, char *test, char *info)
{
  if (list->lh_count != count) { /* Check count first */
    printf("FAIL/%s_%d_count:%s: Count mismatch\n", test, idx, info);
    exit(0);
  } else
    printf("PASS/%s_%d_count:%s: Counts match\n", test, idx, info);

  if (list->lh_first != head) { /* then check the head pointer */
    printf("FAIL/%s_%d_first:%s: Head pointer mismatch\n", test, idx, info);
    exit(0);
  } else
    printf("PASS/%s_%d_first:%s: Head pointers match\n", test, idx, info);

  if (list->lh_last != tail) { /* finally check the tail pointer */
    printf("FAIL/%s_%d_last:%s: Tail pointer mismatch\n", test, idx, info);
    exit(0);
  } else
    printf("PASS/%s_%d_last:%s: Tail pointers match\n", test, idx, info);
}

/* Check that a list element matches expectations */
static void
check_elem(link_elem_t *elem, link_elem_t *prev, link_elem_t *next,
	   link_head_t *head, int l_idx, int e_idx, char *test, char *info)
{
  if (elem->le_next != next) { /* check next pointer first */
    printf("FAIL/%s_%d/%d_next:%s: Next pointer mismatch\n", test, l_idx,
	   e_idx, info);
    exit(0);
  } else
    printf("PASS/%s_%d/%d_next:%s: Next pointers match\n", test, l_idx, e_idx,
	   info);

  if (elem->le_prev != prev) { /* then check prev pointer */
    printf("FAIL/%s_%d/%d_prev:%s: Prev pointer mismatch\n", test, l_idx,
	   e_idx, info);
    exit(0);
  } else
    printf("PASS/%s_%d/%d_prev:%s: Prev pointers match\n", test, l_idx, e_idx,
	   info);

  if (elem->le_head != head) { /* finally check list head pointer */
    printf("FAIL/%s_%d/%d_head:%s: Head pointer mismatch\n", test, l_idx,
	   e_idx, info);
    exit(0);
  } else
    printf("PASS/%s_%d/%d_head:%s: Head pointers match\n", test, l_idx, e_idx,
	   info);
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
    LINK_ELEM_INIT(OBJECT7),
    LINK_ELEM_INIT(OBJECT8),
    LINK_ELEM_INIT(OBJECT9),
    { DEADINT, DEADPTR, DEADPTR, DEADPTR, DEADPTR, DEADINT } /* elem[10] */
  };

  /* First, build the lists */
  for (i = 0; i < 8; i++)
    if (ll_add(&list[0], &elem[i], LINK_LOC_TAIL, 0))
      return -1; /* failed to initialize test */

  if (ll_add(&list[1], &elem[8], LINK_LOC_TAIL, 0))
    return -1; /* failed to initialize test */

  /* Baseline checks */
  check_list(&list[0], 8, &elem[0], &elem[7], 0, "ll_remove_baseline",
	     "Verify baseline list[0]");
  check_list(&list[1], 1, &elem[8], &elem[8], 1, "ll_remove_baseline",
	     "Verify baseline list[1]");

  /* Check to see if ll_remove verifies its arguments correctly */
  check_result(ll_remove(0, 0), DB_ERR_BADARGS, "ll_remove_noargs",
	       "ll_remove() with no arguments", 0);
  check_result(ll_remove(&list[2], &elem[0]), DB_ERR_BADARGS,
	       "ll_remove_badlist", "ll_remove() with bad list", 1);
  check_result(ll_remove(&list[0], &elem[10]), DB_ERR_BADARGS,
	       "ll_remove_badelem", "ll_remove() with bad element", 1);

  /* Unused element test */
  check_result(ll_remove(&list[0], &elem[9]), DB_ERR_UNUSED,
	       "ll_remove_unused", "ll_remove() with unused element", 1);

  /* Wrong list test */
  check_result(ll_remove(&list[0], &elem[8]), DB_ERR_WRONGTABLE,
	       "ll_remove_wronglist", "ll_remove() with element in wrong list",
	       1);

  /* Make sure removing from a one-item list does the right thing */
  check_result(ll_remove(&list[1], &elem[8]), 0, "ll_remove_l1e8",
	       "Remove an item from one-item list", 1);
  check_list(&list[1], 0, 0, 0, 1, "ll_remove_l1e8",
	     "Test removal of an item from one-item list");

  /* Now try removing an item from the head of a longer list */
  check_result(ll_remove(&list[0], &elem[0]), 0, "ll_remove_l0e0",
	       "Remove an item from head of list", 1);
  check_list(&list[0], 7, &elem[1], &elem[7], 0, "ll_remove_l0e0",
	     "Test removal of an item from head of list");
  check_elem(&elem[1], 0, &elem[2], &list[0], 0, 1, "ll_remove_l0e0",
	     "Test removal of an item from head of list");

  /* Now try the tail... */
  check_result(ll_remove(&list[0], &elem[7]), 0, "ll_remove_l0e7",
	       "Remove an item from tail of list", 1);
  check_list(&list[0], 6, &elem[1], &elem[6], 0, "ll_remove_l0e7",
	     "Test removal of an item from tail of list");
  check_elem(&elem[6], &elem[5], 0, &list[0], 0, 6, "ll_remove_l0e7",
	     "Test removal of an item from tail of list");

  /* Finally, try the middle of the list */
  check_result(ll_remove(&list[0], &elem[3]), 0, "ll_remove_l0e3",
	       "Remove an item from middle of list", 1);
  check_list(&list[0], 5, &elem[1], &elem[6], 0, "ll_remove_l0e3",
	     "Test removal of an item from middle of list");
  check_elem(&elem[2], &elem[1], &elem[4], &list[0], 0, 2, "ll_remove_l0e3",
	     "Test removal of an item from middle of list");
  check_elem(&elem[4], &elem[2], &elem[5], &list[0], 0, 4, "ll_remove_l0e3",
	     "Test removal of an item from middle of list");

  return 0;
}
