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

#undef FROBONMALLOC
#undef FROBONFREE

/*
 * memory resource allocation and test functions
 */
typedef void (*OutOfMemoryHandler)(void);
extern void set_nomem_handler(OutOfMemoryHandler handler);

#if !defined(MDEBUG)
/* 
 * RELEASE: allocation functions
 */
#ifndef INCLUDED_stdlib_h
#include <stdlib.h>       /* free */
#define INCLUDED_stdlib_h
#endif

#ifdef FROBONFREE
extern void MyFrobulatingFree(void *x);
#define MyFree(x) do { MyFrobulatingFree((x)); (x) = 0; } while(0)
#else
#define MyFree(x) do { free((x)); (x) = 0; } while(0)
#endif

extern void* MyMalloc(size_t size);
extern void* MyCalloc(size_t nelem, size_t size);
extern void* MyRealloc(void* p, size_t size);

#else /* defined(MDEBUG) */
/*
 * DEBUG: allocation functions
 */
#ifndef INCLUDED_fda_h
#include "fda.h"
#endif

#define MyMalloc(s)     fda_malloc((s), __FILE__, __LINE__)
#define MyCalloc(n, s)  fda_calloc((n), (s), __FILE__, __LINE__)
#define MyFree(p)       fda_free((p))
#define MyRealloc(p, s) fda_realloc((p), (s), __FILE__, __LINE__)

#endif /* defined(MDEBUG) */

#endif /* INCLUDED_ircd_alloc_h */

