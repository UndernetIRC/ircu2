/************************************************************************
 *   IRC - Internet Relay Chat, ircd/ircd_alloc.c
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
#include "config.h"

#include "ircd_alloc.h"
#include "ircd_string.h"
#include "s_debug.h"
#include <string.h>

#include <assert.h>

#if !defined(MDEBUG)
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

#if defined(FROBONFREE) || defined(FROBONMALLOC)
static void
memfrob(void *ptr, size_t size)
{
  unsigned char *p = ptr, *ep = p + size - 4;
  while (p <= ep)
  {
    *(unsigned long*)p = 0xDEADBEEF;
    p += 4;
  }
  switch (ep - p)
  {
  case 3:
    *(unsigned short*)p = 0xDEAD;
    p[2] = 0xBE;
    return;
  case 2:
    *(unsigned short*)p = 0xDEAD;
    return;
  case 1:
    *p++ = 0xDE;
    return;
  }
  return;
}
#endif

void* MyMalloc(size_t size)
{
  void* p = 
#ifdef FROBONFREE
    malloc(size + sizeof(size_t));
#else
    malloc(size);
#endif
  if (!p)
    (*noMemHandler)();
#ifdef FROBONFREE
  *(size_t*)p = size;
  p =  ((size_t*)p) + 1;
#endif
#ifdef FROBONMALLOC
  memfrob(p, size);
#endif
  return p;
}

void* MyRealloc(void* x, size_t size)
{
#ifdef FROBONFREE
   size_t old_size = ((size_t*)x)[-1];
   if (old_size > size)
     memfrob(((char*)x) + size, old_size - size);
   x = realloc(((size_t*)x) - 1, size + sizeof(size_t));
#else
  x = realloc(x, size);
#endif
  if (!x)
    (*noMemHandler)();
  /* Both are needed in all cases to work with realloc... */
#if defined(FROBONMALLOC) && defined(FROBONFREE)
  if (old_size < size)
    memfrob(((char*)x) + old_size, size - old_size);
#endif
#ifdef FROBONFREE
  *(size_t*)x = size;
  x =  ((size_t*)x) + 1;
#endif
  return x;
}

void* MyCalloc(size_t nelem, size_t size)
{
  void* p =
#ifdef FROBONFREE
    malloc(nelem * size + sizeof(size_t));
#else
    malloc(nelem * size);
#endif
  if (!p)
    (*noMemHandler)();
#ifdef FROBONFREE
  *((size_t*)p) = nelem * size;
  p = ((size_t*)p) + 1;
#endif
  memset(p, 0, size * nelem);
  return p;
}

#ifdef FROBONFREE
void
MyFrobulatingFree(void *p)
{
  size_t *stp = (size_t*)p;
  if (p == NULL)
    return;
  memfrob(p, stp[-1]);
  free(stp - 1);
}
#endif

#else /* defined(MDEBUG) */
/*
 * DEBUG: allocation functions
 */
void set_nomem_handler(OutOfMemoryHandler handler)
{
  assert(0 != handler);
  fda_set_nomem_handler(handler);
}

#endif /* defined(MDEBUG) */

