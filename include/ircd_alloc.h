/*
 * IRC - Internet Relay Chat, include/ircd_alloc.h
 * Copyright (C) 1999 Thomas Helvey <tomh@inxpress.net>
 *                   
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Commentary by Bleep (Thomas Helvey)
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_alloc_h
#define INCLUDED_ircd_alloc_h

/*
 * memory resource allocation and test functions
 */
typedef void (*OutOfMemoryHandler)(void);
extern void set_nomem_handler(OutOfMemoryHandler handler);

/* The mappings for the My* functions... */
#define MyMalloc(size) \
  DoMalloc(size, "malloc", __FILE__, __LINE__)

#define MyCalloc(nelem, size) \
  DoMallocZero(size * nelem, "calloc", __FILE__, __LINE__)

#define MyFree(p) \
  DoFree(p, __FILE__, __LINE__)

/* No realloc because it is not currently used, and it is not really the
 * nicest function to be using anyway(i.e. its evil if you want it
 * go ahead and write it).
 */

extern void *malloc_tmp;

/* First version: fast non-debugging macros... */
#ifndef MDEBUG
#ifndef INCLUDED_stdlib_h
#include <stdlib.h> /* free */
#define INCLUDED_stdlib_h
#endif

extern OutOfMemoryHandler noMemHandler;

#define DoFree(x, file, line) do { free((x)); (x) = 0; } while(0)
#define DoMalloc(size, type, file, line) \
  (\
     (malloc_tmp = malloc(size), \
     (malloc_tmp == NULL) ? noMemHandler() : 0), \
  malloc_tmp)

#define DoMallocZero(size, type, file, line) \
  (\
    (DoMalloc(size, type, file, line), \
    memset(malloc_tmp, 0, size)), \
  malloc_tmp)

/* Second version: slower debugging versions... */
#else /* defined(MDEBUG) */
#include <sys/types.h>
#include "memdebug.h"

#define DoMalloc(size, type, file, line) \
  dbg_malloc(size, type, file, line)
#define DoMallocZero(size, type, file, line) \
  dbg_malloc_zero(size, type, file, line)
#define DoFree(p, file, line) \
  dbg_free(p, file, line)
#endif /* defined(MDEBUG) */

#endif /* INCLUDED_ircd_alloc_h */
