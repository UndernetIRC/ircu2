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

#define OBJECTA (void *)0xabcdef01

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

/* Check the status of the list */
static void
check_list_order(link_head_t *lists, int list_idx, link_elem_t *elems,
		 int elem1_idx, int elem2_idx, int elem3_idx, int elem4_idx,
		 int elem5_idx, char *test, char *info)
{
  /* Check that the list head looks correct first */
  check_list(&lists[list_idx], 5, &elems[elem1_idx], &elems[elem5_idx],
	     list_idx, test, info);
  /* Now check that all elements are there and are in the proper order */
  check_elem(&elems[elem1_idx], 0, &elems[elem2_idx], &lists[list_idx],
	     list_idx, elem1_idx, test, info);
  check_elem(&elems[elem2_idx], &elems[elem1_idx], &elems[elem3_idx],
	     &lists[list_idx], list_idx, elem2_idx, test, info);
  check_elem(&elems[elem3_idx], &elems[elem2_idx], &elems[elem4_idx],
	     &lists[list_idx], list_idx, elem3_idx, test, info);
  check_elem(&elems[elem4_idx], &elems[elem3_idx], &elems[elem5_idx],
	     &lists[list_idx], list_idx, elem4_idx, test, info);
  check_elem(&elems[elem5_idx], &elems[elem4_idx], 0, &lists[list_idx],
	     list_idx, elem5_idx, test, info);
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
    LINK_ELEM_INIT(OBJECTA),
    { DEADINT, DEADPTR, DEADPTR, DEADPTR, DEADPTR, DEADINT } /* elem[11] */
  };

  /* First, build the lists */
  for (i = 0; i < 5; i++)
    if (ll_add(&list[0], &elem[i], LINK_LOC_TAIL, 0) ||
	ll_add(&list[1], &elem[i + 5], LINK_LOC_TAIL, 0))
      return -1; /* failed to initialize test */
    
  /* Baseline--verify that the lists are in proper order */
  check_list_order(list, 0, elem, 0, 1, 2, 3, 4, "ll_move_baseline",
		   "Verify baseline list[0] ordering");
  check_list_order(list, 1, elem, 5, 6, 7, 8, 9, "ll_move_baseline",
		   "Verify baseline list[1] ordering");

  /* OK, now check to see if ll_move verifies its arguments correctly */
  check_result(ll_move(0, 0, LINK_LOC_HEAD, 0), DB_ERR_BADARGS,
	       "ll_move_noargs", "ll_move() with no arguments", 0);
  check_result(ll_move(&list[2], &elem[0], LINK_LOC_HEAD, 0), DB_ERR_BADARGS,
	       "ll_move_badlist", "ll_move() with bad list", 1);
  check_result(ll_move(&list[0], &elem[11], LINK_LOC_HEAD, 0),
	       DB_ERR_BADARGS, "ll_move_badnew",
	       "ll_move() with bad new element", 1);
  check_result(ll_move(&list[0], &elem[0], LINK_LOC_TAIL, &elem[11]),
	       DB_ERR_BADARGS, "ll_move_badelem",
	       "ll_move() with bad element", 1);
  check_result(ll_move(&list[0], &elem[0], LINK_LOC_BEFORE, 0),
	       DB_ERR_BADARGS, "ll_move_before_noelem",
	       "ll_move() before with no element", 1);
  check_result(ll_move(&list[0], &elem[0], LINK_LOC_AFTER, 0),
	       DB_ERR_BADARGS, "ll_move_after_noelem",
	       "ll_move() after with no element", 1);

  /* Make sure movement of object around itself is rejected */
  check_result(ll_move(&list[0], &elem[0], LINK_LOC_BEFORE, &elem[0]),
	       DB_ERR_BUSY, "ll_move_neweqelem",
	       "ll_move() with new == element", 1);

  /* Check to see if unused elements are detected correctly */
  check_result(ll_move(&list[0], &elem[10], LINK_LOC_HEAD, 0),
	       DB_ERR_UNUSED, "ll_move_newunused",
	       "ll_move() with unused new element", 1);
  check_result(ll_move(&list[0], &elem[4], LINK_LOC_HEAD, &elem[10]),
	       DB_ERR_UNUSED, "ll_move_elemunused",
	       "ll_move() with unused original element", 1);

  /* Next check to see if list mismatches are handled properly */
  check_result(ll_move(&list[0], &elem[5], LINK_LOC_HEAD, 0),
	       DB_ERR_WRONGTABLE, "ll_move_newwronglist",
	       "ll_move() with new element in wrong list", 1);
  check_result(ll_move(&list[0], &elem[4], LINK_LOC_HEAD, &elem[5]),
	       DB_ERR_WRONGTABLE, "ll_move_elemwronglist",
	       "ll_move() with original element in wrong list", 1);

  /* OK, now let's actually do something */

  /* Start off with moving the tail element to the head of the list */
  check_result(ll_move(&list[0], &elem[4], LINK_LOC_HEAD, 0), 0,
	       "ll_move_l0e4h", "Move tail element to head of list", 1);
  check_list_order(list, 0, elem, 4, 0, 1, 2, 3, "ll_move_l0e4h",
		   "Test movement of tail element to head of list");

  /* Now try the head element back to the tail of the list */
  check_result(ll_move(&list[0], &elem[4], LINK_LOC_TAIL, 0), 0,
	       "ll_move_l0e4t", "Move head element to tail of list", 1);
  check_list_order(list, 0, elem, 0, 1, 2, 3, 4, "ll_move_l0e4t",
		   "Test movement of head element to tail of list");

  /* Let's now move the tail element to *after* the head of the list */
  check_result(ll_move(&list[0], &elem[4], LINK_LOC_AFTER, &elem[0]), 0,
	       "ll_move_l0e4a0", "Move tail element to after head of list", 1);
  check_list_order(list, 0, elem, 0, 4, 1, 2, 3, "ll_move_l0e4a0",
		   "Test movement of tail to after head of list");

  /* How about moving the head element to *before* the tail of the list? */
  check_result(ll_move(&list[0], &elem[0], LINK_LOC_BEFORE, &elem[3]), 0,
	       "ll_move_l0e0b3", "Move head element to before tail of list",
	       1);
  check_list_order(list, 0, elem, 4, 1, 2, 0, 3, "ll_move_l0e0b3",
		   "Test movement of head to before tail of list");

  /* OK, now do some dancing element checks */
  check_result(ll_move(&list[0], &elem[4], LINK_LOC_AFTER, &elem[1]), 0,
	       "ll_move_l0e4a1", "Swap elements with LINK_LOC_AFTER", 1);
  check_list_order(list, 0, elem, 1, 4, 2, 0, 3, "ll_move_l0e4a1",
		   "Swap elements with LINK_LOC_AFTER");
  check_result(ll_move(&list[0], &elem[3], LINK_LOC_BEFORE, &elem[0]), 0,
	       "ll_move_l0e3b0", "Swap elements with LINK_LOC_BEFORE", 1);
  check_list_order(list, 0, elem, 1, 4, 2, 3, 0, "ll_move_l0e3b0",
		   "Swap elements with LINK_LOC_BEFORE");

  /* Finally, verify that moving heads/tails to the head/tail (respectively)
   * works properly.
   */
  check_result(ll_move(&list[0], &elem[1], LINK_LOC_HEAD, 0), 0,
	       "ll_move_l0e1h", "Move head element to head", 1);
  check_list_order(list, 0, elem, 1, 4, 2, 3, 0, "ll_move_l0e1h",
		   "Move head element to head");
  check_result(ll_move(&list[0], &elem[0], LINK_LOC_TAIL, 0), 0,
	       "ll_move_l0e0t", "Move tail element to tail", 1);
  check_list_order(list, 0, elem, 1, 4, 2, 3, 0, "ll_move_l0e0t",
		   "Move tail element to tail");

  return 0;
}
