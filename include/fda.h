/*
 * fda.c - Free Debug Allocator
 * Copyright (C) 1997 Thomas Helvey <tomh@inxpress.net>
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
 * $Id$
 */
#ifndef INCLUDED_fda_h
#define INCLUDED_fda_h

#if defined(MDEBUG)
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>      /* size_t */
#define INCLUDED_sys_types_h
#endif


extern size_t fda_get_byte_count(void);
extern size_t fda_get_block_count(void);
extern size_t fda_sizeof(const void* p);
extern void   fda_clear_refs(void);
extern void   fda_set_ref(const void* p);
extern void   fda_assert_refs(void);
extern int    fda_enum_locations(void (*enumfn)(const char*, int, int));
extern int    fda_enum_leaks(void (*enumfn)(const char*, int, size_t, void*));
extern void   fda_dump_hash(void (*enumfn)(int, int));
extern void   fda_set_byte_limit(size_t nbytes);
extern int    valid_ptr(const void* p, size_t size);

extern void* fda_malloc(size_t size, const char* file, int line);
extern void* fda_realloc(void* p, size_t size, const char* file, int line);
extern void* fda_calloc(size_t nelems, size_t size, const char* file, int line);
extern char* fda_strdup(const char* src, const char* file, int line);
extern void  fda_free(void* p);

#if defined(FDA_REDEFINE_MALLOC)
#define malloc(s)     fda_malloc((s), __FILE__, __LINE__)
#define realloc(p, s) fda_realloc((p), (s), __FILE__, __LINE__)
#define calloc(n, s)  fda_calloc((n), (s), __FILE__, __LINE__)
#define strdup(s)     fda_strdup((s), __FILE__, __LINE__)
#define free(p)       fda_free((p))
#endif

extern void fda_set_lowmem_handler(void (*fn)(void));
extern void fda_set_nomem_handler(void (*fn)(void));


#endif /* defined(MDEBUG) */
#endif /* INCLUDED_fda_h */
