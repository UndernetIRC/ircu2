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

#define OBJECT	(void *)0x91827364
#define DEADINT	0xdeadbeef
#define DEADPTR	(void *)0xdeadbeef

static void
check_init(link_elem_t *elem, char *how)
{
  if (elem->le_magic != LINK_ELEM_MAGIC) /* Verify magic was set */
    printf("FAIL/%s_magic:Initialization failed to set magic number\n", how);
  else
    printf("PASS/%s_magic:Initialization set magic number properly\n", how);

  if (elem->le_next != 0) /* verify next was set properly */
    printf("FAIL/%s_next:Initialization failed to clear next\n", how);
  else
    printf("PASS/%s_next:Initialization set next to 0\n", how);

  if (elem->le_prev != 0) /* verify prev was set properly */
    printf("FAIL/%s_prev:Initialization failed to clear prev\n", how);
  else
    printf("PASS/%s_prev:Initialization set prev to 0\n", how);

  if (elem->le_object != OBJECT) /* verify object was set properly */
    printf("FAIL/%s_object:Initialization failed to set object\n", how);
  else
    printf("PASS/%s_object:Initialization set object properly\n", how);

  if (elem->le_head != 0) /* verify head was set properly */
    printf("FAIL/%s_head:Initialization failed to clear head\n", how);
  else
    printf("PASS/%s_head:Initialization set head to 0\n", how);

  if (elem->le_flags != 0) /* verify flags were set properly */
    printf("FAIL/%s_flags:Initialization failed to clear flags\n", how);
  else
    printf("PASS/%s_flags:Initialization set flags to 0\n", how);
}

int
main(int argc, char **argv)
{
  unsigned long errcode;
  link_elem_t elem = LINK_ELEM_INIT(OBJECT);

  /* Check that the static initializer produces a passable structure */
  check_init(&elem, "le_static");

  /* now, check what le_init does with bad arguments */
  if ((errcode = le_init(0, 0)) == DB_ERR_BADARGS)
    printf("PASS/le_init_nothing:le_init(0, 0) returns "
	   "DB_ERR_BADARGS\n");
  else
    printf("FAIL/le_init_nothing:le_init(0, 0) returned "
	   "%lu instead of DB_ERR_BADARGS\n", errcode);
  if ((errcode = le_init(0, OBJECT)) == DB_ERR_BADARGS)
    printf("PASS/le_init_objectonly:le_init(0, OBJECT) returns "
	   "DB_ERR_BADARGS\n");
  else
    printf("FAIL/le_init_objectonly:le_init(0, OBJECT) returned "
	   "%lu instead of DB_ERR_BADARGS\n", errcode);
  if ((errcode = le_init(&elem, 0)) == DB_ERR_BADARGS)
    printf("PASS/le_init_elemonly:le_init(&elem, 0) returns "
	   "DB_ERR_BADARGS\n");
  else
    printf("FAIL/le_init_elemonly:le_init(&elem, 0) returned "
	   "%lu instead of DB_ERR_BADARGS\n", errcode);

  /* Scramble the structure */
  elem.le_magic = DEADINT;
  elem.le_next = DEADPTR;
  elem.le_prev = DEADPTR;
  elem.le_object = DEADPTR;
  elem.le_head = DEADPTR;
  elem.le_flags = DEADINT;

  /* Now try to initialize our structure and see what happens */
  if ((errcode = le_init(&elem, OBJECT))) {
    printf("FAIL/le_dynamic:le_init(&elem) returned failure (%lu)\n",
	   errcode);
    return 0;
  } else
    printf("PASS/le_dynamic:le_init(&elem) returned success\n");

  /* Finally, verify initialization */
  check_init(&elem, "le_dynamic");

  return 0;
}
