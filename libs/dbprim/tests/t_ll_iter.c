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

#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

struct itercheck {
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
check_iter(link_head_t *head, link_elem_t *elem, void *extra)
{
  struct itercheck *itcheck;

  itcheck = extra;

  /* If we were told to return an error, return one */
  if (!itcheck->elem_array)
    return EINVAL;

  /* OK, verify that the list head is the same as the one we expect */
  if (head != le_head(&itcheck->elem_array[0]))
    printf("FAIL/ll_iter_funchead_e%d:List heads do not match\n",
	   itcheck->elem_idx);
  else
    printf("PASS/ll_iter_funchead_e%d:List heads match\n", itcheck->elem_idx);

  /* Now verify that the element is what we expect. */
  if (elem != &itcheck->elem_array[itcheck->elem_idx])
    printf("FAIL/ll_iter_funcelem_e%d:Elements do not match\n",
	   itcheck->elem_idx);
  else
    printf("PASS/ll_iter_funcelem_e%d:Elements match\n", itcheck->elem_idx);

  /* Finally, increment the index */
  itcheck->elem_idx++;

  return 0;
}

int
main(int argc, char **argv)
{
  int i;
  link_head_t list[] = { /* some lists to operate on */
    LINK_HEAD_INIT(0),
    { DEADINT, DEADINT, DEADPTR, DEADPTR, 0 } /* list[1] is a bad list */
  };
  link_elem_t elem[] = { /* some elements to operate on */
    LINK_ELEM_INIT(OBJECT0),
    LINK_ELEM_INIT(OBJECT1),
    LINK_ELEM_INIT(OBJECT2),
    LINK_ELEM_INIT(OBJECT3),
    LINK_ELEM_INIT(OBJECT4),
    LINK_ELEM_INIT(OBJECT5),
  };
  struct itercheck itcheck = { 0, 0 };

  /* First, build the lists */
  for (i = 0; i < 5; i++)
    if (ll_add(&list[0], &elem[i], LINK_LOC_TAIL, 0))
      return -1; /* failed to initialize test */

  /* Baseline checks */
  check_list(&list[0], 5, &elem[0], &elem[4], "ll_iter_baseline",
	     "Verify baseline list");

  /* Check to see if ll_iter() verifies its arguments correctly */
  check_result(ll_iter(0, 0, 0), DB_ERR_BADARGS, "ll_iter_noargs",
	       "ll_iter() with no arguments", 0);
  check_result(ll_iter(&list[1], check_iter, &itcheck), DB_ERR_BADARGS,
	       "ll_iter_badlist", "ll_iter() with bad list", 0);
  check_result(ll_iter(&list[0], 0, &itcheck), DB_ERR_BADARGS,
	       "ll_iter_badfunc", "ll_iter() with bad function", 0);

  /* Now check to see if ll_iter() returns what the iter function returns */
  check_result(ll_iter(&list[0], check_iter, &itcheck), EINVAL,
	       "ll_iter_funcreturn",
	       "ll_iter() returning iteration function return value", 0);

  /* Now iterate through the list */
  itcheck.elem_array = elem;
  itcheck.elem_idx = 0;
  check_result(ll_iter(&list[0], check_iter, &itcheck), 0, "ll_iter_function",
	       "ll_iter() iteration", 0);

  /* Did it check them all? */
  if (itcheck.elem_idx == 5)
    printf("PASS/ll_iter_func_count:ll_iter() visited all items\n");
  else
    printf("FAIL/ll_iter_func_count:ll_iter() visited only %d items\n",
	   itcheck.elem_idx);

  return 0;
}
