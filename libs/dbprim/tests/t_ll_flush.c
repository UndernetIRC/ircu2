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

struct flushcheck {
  link_head_t *elem_list;
  link_elem_t *elem_array;
  int	       elem_idx;
};

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

static unsigned long
check_flush(link_head_t *head, link_elem_t *elem, void *extra)
{
  struct flushcheck *itcheck;

  itcheck = extra;

  /* OK, verify that the list head is the same as the one we expect */
  if (head != itcheck->elem_list)
    printf("FAIL/ll_flush_funchead_e%d:List heads do not match\n",
	   itcheck->elem_idx);
  else
    printf("PASS/ll_flush_funchead_e%d:List heads match\n", itcheck->elem_idx);

  /* Now verify that the element is what we expect. */
  if (elem != &itcheck->elem_array[itcheck->elem_idx])
    printf("FAIL/ll_flush_funcelem_e%d:Elements do not match\n",
	   itcheck->elem_idx);
  else
    printf("PASS/ll_flush_funcelem_e%d:Elements match\n", itcheck->elem_idx);

  /* Increment index and return error if it was 0 */
  return (!itcheck->elem_idx++ ? EINVAL : 0);
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
  };
  struct flushcheck itcheck = { 0, 0, 0 };

  /* First, build the lists */
  for (i = 0; i < 5; i++)
    if (ll_add(&list[0], &elem[i], LINK_LOC_TAIL, 0) ||
	ll_add(&list[1], &elem[i + 5], LINK_LOC_TAIL, 0))
      return -1; /* failed to initialize test */

  /* Baseline checks */
  check_list(&list[0], 5, &elem[0], &elem[4], "ll_flush_baseline_l0",
	     "Verify baseline list 0");
  check_list(&list[1], 5, &elem[5], &elem[9], "ll_flush_baseline_l1",
	     "Verify baseline list 1");

  /* Check to see if ll_flush() verifies its arguments correctly */
  check_result(ll_flush(0, 0, 0), DB_ERR_BADARGS, "ll_flush_noargs",
	       "ll_flush() with no arguments", 0);
  check_result(ll_flush(&list[2], check_flush, &itcheck), DB_ERR_BADARGS,
	       "ll_flush_badlist", "ll_flush() with bad list", 0);

  /* Check to see if ll_flush() operates properly with no flush function */
  check_result(ll_flush(&list[1], 0, 0), 0, "ll_flush_nofunc",
	       "ll_flush() with no flush function", 0);
  check_list(&list[1], 0, 0, 0, "ll_flush_nofunc",
	     "Test ll_flush() element removal (no flush function)");

  /* Now check to see if ll_flush() returns what the flush function returns */
  itcheck.elem_list = &list[0];
  itcheck.elem_array = elem;
  itcheck.elem_idx = 0;
  check_result(ll_flush(&list[0], check_flush, &itcheck), EINVAL,
	       "ll_flush_funcreturn",
	       "ll_flush() returning flush function return value", 0);
  check_list(&list[0], 4, &elem[1], &elem[4], "ll_flush_funcreturn",
	     "Test ll_flush() element removal (function return non-zero)");

  /* Now flush the list completely */
  check_result(ll_flush(&list[0], check_flush, &itcheck), 0,
	       "ll_flush_function", "ll_flush() flush", 0);
  check_list(&list[0], 0, 0, 0, "ll_flush_function",
	     "Test ll_flush() element removal (function return zero)");

  /* Did it check them all? */
  if (itcheck.elem_idx == 5)
    printf("PASS/ll_flush_func_count:ll_flush() visited all items\n");
  else
    printf("PASS/ll_flush_func_count:ll_flush() visited only %d items\n",
	   itcheck.elem_idx);

  return 0;
}
