/*
 * runmalloc.h
 *
 * (C) Copyright 1996 - 1997, Carlo Wood (carlo@runaway.xs4all.nl)
 *
 * Headerfile of runmalloc.c
 *
 * $Id$
 */
#ifndef INCLUDED_runmalloc_h
#define INCLUDED_runmalloc_h
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* size_t */
#define INCLUDED_sys_types_h
#endif

typedef void (*OutOfMemoryHandler)(void);

extern void set_nomem_handler(OutOfMemoryHandler handler);

#if 0
/* 
 * we want to be able to test in DEBUGMODE without turning
 * DEBUGMALLOC on, change in the config not in the code
 */
#if defined(DEBUGMODE) && !defined(DEBUGMALLOC)
#define DEBUGMALLOC
#endif
#endif

#ifdef DEBUGMALLOC

#if defined(MEMMAGICNUMS) && !defined(MEMSIZESTATS)
#define MEMSIZESTATS
#endif

#ifndef MEMLEAKSTATS
#undef MEMTIMESTATS
#endif

/*
 * Proto types
 */

#ifdef MEMLEAKSTATS
extern void *RunMalloc_memleak(size_t size, int line, const char *filename);
extern void *RunCalloc_memleak(size_t nmemb, size_t size,
    int line, const char *filename);
extern void *RunRealloc_memleak(void *ptr, size_t size,
    int line, const char *filename);
struct Client;
extern void report_memleak_stats(struct Client *sptr, int parc, char *parv[]);
#define MyMalloc(x) RunMalloc_memleak(x, __LINE__, __FILE__)
#define MyCalloc(x,y) RunCalloc_memleak(x,y, __LINE__, __FILE__)
#define MyRealloc(x,y) RunRealloc_memleak(x,y, __LINE__, __FILE__)

#else /* !MEMLEAKSTATS */
extern void *MyMalloc(size_t size);
extern void *MyCalloc(size_t nmemb, size_t size);
extern void *MyRealloc(void *ptr, size_t size);
#endif /* MEMLEAKSTATS */

extern int MyFree_test(void *ptr);
extern void MyFree(void *ptr);

#ifdef MEMSIZESTATS
extern unsigned int get_alloc_cnt(void);
extern size_t get_mem_size(void);
#endif

#else /* !DEBUGMALLOC */

#ifndef INCLUDED_stdlib_h
#include <stdlib.h>
#define INCLUDED_stdlib_h
#endif

#undef MEMSIZESTATS
#undef MEMMAGICNUMS
#undef MEMLEAKSTATS
#undef MEMTIMESTATS

#define MyFree(x) do { free((x)); (x) = 0; } while(0)
#define Debug_malloc(x)
extern void* MyMalloc(size_t size);
extern void* MyCalloc(size_t nelem, size_t size);
extern void* MyRealloc(void* x, size_t size);

#endif /* DEBUGMALLOC */

#endif /* INCLUDED_runmalloc_h */
