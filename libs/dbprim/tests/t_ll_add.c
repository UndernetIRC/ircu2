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

/* Check that a list element matches expectations */
static void
check_elem(link_elem_t *elem, link_elem_t *prev, link_elem_t *next,
	   link_head_t *head, char *test, char *info)
{
  if (elem->le_next != next) { /* check next pointer first */
    printf("FAIL/%s_next:%s: Next pointer mismatch\n", test, info);
    exit(0);
  } else
    printf("PASS/%s_next:%s: Next pointers match\n", test, info);

  if (elem->le_prev != prev) { /* then check prev pointer */
    printf("FAIL/%s_prev:%s: Prev pointer mismatch\n", test, info);
    exit(0);
  } else
    printf("PASS/%s_prev:%s: Prev pointers match\n", test, info);

  if (elem->le_head != head) { /* finally check list head pointer */
    printf("FAIL/%s_head:%s: Head pointer mismatch\n", test, info);
    exit(0);
  } else
    printf("PASS/%s_head:%s: Head pointers match\n", test, info);
}

int
main(int argc, char **argv)
{
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
    { DEADINT, DEADPTR, DEADPTR, DEADPTR, DEADPTR, DEADINT } /* elem[6] */
  };

  /* Check the cases that yield "BADARGS" */
  check_result(ll_add(0, 0, LINK_LOC_HEAD, 0), DB_ERR_BADARGS,
	       "ll_add_noargs", "ll_add() with no arguments", 0);
  check_result(ll_add(&list[2], &elem[0], LINK_LOC_HEAD, 0), DB_ERR_BADARGS,
	       "ll_add_badlist", "ll_add() with bad list", 0);
  check_result(ll_add(&list[0], &elem[6], LINK_LOC_HEAD, 0), DB_ERR_BADARGS,
	       "ll_add_badnew", "ll_add() with bad new element", 0);
  check_result(ll_add(&list[0], &elem[0], LINK_LOC_HEAD, &elem[6]),
	       DB_ERR_BADARGS, "ll_add_badelem", "ll_add() with bad element",
	       0);
  check_result(ll_add(&list[0], &elem[0], LINK_LOC_BEFORE, 0),
	       DB_ERR_BADARGS, "ll_add_before_noelem",
	       "ll_add() before with no element", 0);
  check_result(ll_add(&list[0], &elem[0], LINK_LOC_AFTER, 0), DB_ERR_BADARGS,
	       "ll_add_after_noelem", "ll_add() after with no element", 0);

  /* OK, now add an element to one list */
  check_result(ll_add(&list[0], &elem[0], LINK_LOC_HEAD, 0), 0,
	       "ll_add_l0e0", "ll_add() head list[0] elem[0]", 1);

  /* Verify that it added correctly */
  check_list(&list[0], 1, &elem[0], &elem[0], "list_l0e0",
	     "List 0 head after first insert");
  check_elem(&elem[0], 0, 0, &list[0], "elem_l0e0",
	     "Element 0 after first insert");

  /* Now try to add it to a second list */
  check_result(ll_add(&list[1], &elem[0], LINK_LOC_HEAD, 0), DB_ERR_BUSY,
	       "ll_add_l1e0", "ll_add() head list[1] elem[0]", 1);

  /* OK, now try adding another element to a second list, using TAIL */
  check_result(ll_add(&list[1], &elem[1], LINK_LOC_TAIL, 0), 0,
	       "ll_add_l1e1", "ll_add() tail list[1] elem[1]", 1);

  /* Verify that it added correctly */
  check_list(&list[1], 1, &elem[1], &elem[1], "list_l1e1",
	     "List 1 head after second insert");
  check_elem(&elem[1], 0, 0, &list[1], "elem_l1e1",
	     "Element 1 after second insert");

  /* Now try adding an element to list[0] after an element in list[1] */
  check_result(ll_add(&list[0], &elem[2], LINK_LOC_AFTER, &elem[1]),
	       DB_ERR_WRONGTABLE, "ll_add_l0e2a1",
	       "ll_add() list[0] elem[2] after elem[1] (list[1])", 1);

  /* Now try adding after an element that hasn't been inserted anywhere */
  check_result(ll_add(&list[0], &elem[2], LINK_LOC_AFTER, &elem[3]),
	       DB_ERR_UNUSED, "ll_add_l0e2a3",
	       "ll_add() list[0] elem[2] after elem[3] (no list)", 1);

  /* Let's now try adding to the head of a list */
  check_result(ll_add(&list[0], &elem[2], LINK_LOC_TAIL, 0), 0, "ll_add_l0e2t",
	       "ll_add() tail list[0] elem[2]", 1);

  /* Verify that it added correctly */
  check_list(&list[0], 2, &elem[0], &elem[2], "list_l0e0e2",
	     "List 0 head after third insert");
  check_elem(&elem[0], 0, &elem[2], &list[0], "elem_l0e0e2_0",
	     "Element 0 after third insert");
  check_elem(&elem[2], &elem[0], 0, &list[0], "elem_l0e0e2_2",
	     "Element 2 after third insert");

  /* Now try for the head */
  check_result(ll_add(&list[1], &elem[3], LINK_LOC_HEAD, 0), 0, "ll_add_l1e3h",
	       "ll_add() head list[1] elem[3]", 1);

  /* Verify that it added correctly */
  check_list(&list[1], 2, &elem[3], &elem[1], "list_l1e3e1",
	     "List 1 head after fourth insert");
  check_elem(&elem[1], &elem[3], 0, &list[1], "elem_l1e3e1_1",
	     "Element 1 after fourth insert");
  check_elem(&elem[3], 0, &elem[1], &list[1], "elem_l1e3e1_3",
	     "Element 3 after fourth insert");

  /* Let's try adding an element in the middle by inserting before last */
  check_result(ll_add(&list[0], &elem[4], LINK_LOC_BEFORE, ll_last(&list[0])),
	       0, "ll_add_l0e4b2", "ll_add() list[0] elem[4] before elem[2]",
	       1);

  /* Verify that it added correctly */
  check_list(&list[0], 3, &elem[0], &elem[2], "list_l0e0e4e2",
	     "List 0 head after fifth insert");
  check_elem(&elem[0], 0, &elem[4], &list[0], "elem_l0e0e4e2_0",
	     "Element 0 after fifth insert");
  check_elem(&elem[2], &elem[4], 0, &list[0], "elem_l0e0e4e2_2",
	     "Element 2 after fifth insert");
  check_elem(&elem[4], &elem[0], &elem[2], &list[0], "elem_l0e0e4e2_4",
	     "Element 4 after fifth insert");

  /* OK, now try inserting after first */
  check_result(ll_add(&list[1], &elem[5], LINK_LOC_AFTER, ll_first(&list[1])),
	       0, "ll_add_l1e5a3", "ll_add() list[1] elem[5] after elem[3]",
	       1);

  /* Verify that it added correctly */
  check_list(&list[1], 3, &elem[3], &elem[1], "list_l1e3e5e1",
	     "List 1 head after sixth insert");
  check_elem(&elem[1], &elem[5], 0, &list[1], "elem_l1e3e5e1_1",
	     "Element 1 after sixth insert");
  check_elem(&elem[3], 0, &elem[5], &list[1], "elem_l1e3e5e1_3",
	     "Element 3 after sixth insert");
  check_elem(&elem[5], &elem[3], &elem[1], &list[1], "elem_l1e3e5e1_5",
	     "Element 5 after sixth insert");

  return 0;
}
