/************************************************************************
 *   IRC - Internet Relay Chat, src/ircd_log.c
 *   Copyright (C) 1999 Thomas Helvey (BleepSoft)
 *                     
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers. 
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   $Id$
 */
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "s_debug.h"

#include <assert.h>

#if defined(NDEBUG)
/*
 * RELEASE: allocation functions
 */

static void nomem_handler(void)
{
  Debug((DEBUG_FATAL, "Out of memory, exiting"));
  exit(2);
}

static OutOfMemoryHandler noMemHandler = nomem_handler;

void set_nomem_handler(OutOfMemoryHandler handler)
{
  noMemHandler = handler;
}

void* MyMalloc(size_t size)
{
  void* p = malloc(size);
  if (!p)
    (*noMemHandler)();
  return p;
}

void* MyRealloc(void* p, size_t size)
{
  void* x = realloc(p, size);
  if (!x)
    (*noMemHandler)();
  return x;
}

void* MyCalloc(size_t nelem, size_t size)
{
  void* p = calloc(nelem, size);
  if (!p)
    (*noMemHandler)();
  return p;
}

#else /* !defined(NDEBUG) */
/*
 * DEBUG: allocation functions
 */
void set_nomem_handler(OutOfMemoryHandler handler)
{
  assert(0 != handler);
  fda_set_nomem_handler(handler);
}

#endif /* !defined(NDEBUG) */

