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

#include "dbprim.h"

#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

static void
check_init(link_head_t *head, char *how)
{
  if (head->lh_magic != LINK_HEAD_MAGIC) /* Verify magic was set */
    printf("FAIL/%s_magic:Initialization failed to set magic number\n", how);
  else
    printf("PASS/%s_magic:Initialization set magic number properly\n", how);

  if (head->lh_count != 0) /* verify count was set */
    printf("FAIL/%s_count:Initialization failed to clear count\n", how);
  else
    printf("PASS/%s_count:Initialization set count to 0\n", how);

  if (head->lh_first != 0) /* verify first was set */
    printf("FAIL/%s_first:Initialization failed to clear first pointer\n",
	   how);
  else
    printf("PASS/%s_first:Initialization set first pointer to 0\n", how);

  if (head->lh_last != 0) /* verify last was set */
    printf("FAIL/%s_last:Initialization failed to clear last pointer\n", how);
  else
    printf("PASS/%s_last:Initialization set last pointer to 0\n", how);
}

int
main(int argc, char **argv)
{
  unsigned long errcode;
  link_head_t head = LINK_HEAD_INIT(0);

  /* Check that the static initializer produces a passable structure */
  check_init(&head, "ll_static");

  /* now, check what ll_init does with bad arguments */
  if ((errcode = ll_init(0, 0)) == DB_ERR_BADARGS)
    printf("PASS/ll_init_nohead:ll_init(0, 0) returns DB_ERR_BADARGS\n");
  else
    printf("FAIL/ll_init_nohead:ll_init(0, 0) returned %lu instead of "
	   "DB_ERR_BADARGS\n", errcode);

  /* Scramble the structure */
  head.lh_magic = DEADINT;
  head.lh_count = DEADINT;
  head.lh_first = DEADPTR;
  head.lh_last = DEADPTR;
  head.lh_extra = DEADPTR;

  /* Now try to initialize our structure and see what happens */
  if ((errcode = ll_init(&head, 0))) {
    printf("FAIL/ll_dynamic:ll_init(&head, 0) returned failure (%lu)\n",
	   errcode);
    return 0;
  } else
    printf("PASS/ll_dynamic:ll_init(&head, 0) returned success\n");

  /* Finally, verify initialization */
  check_init(&head, "ll_dynamic");

  return 0;
}
