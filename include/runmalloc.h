/*
 * runmalloc.h
 *
 * (C) Copyright 1996 - 1997, Carlo Wood (carlo@runaway.xs4all.nl)
 *
 * Headerfile of runmalloc.c
 *
 */

#ifndef RUNMALLOC_H
#define RUNMALLOC_H

#ifdef DEBUGMALLOC

#if defined(MEMMAGICNUMS) && !defined(MEMSIZESTATS)
#define MEMSIZESTATS
#endif
#ifndef MEMLEAKSTATS
#undef MEMTIMESTATS
#endif

/*=============================================================================
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
#define RunMalloc(x) RunMalloc_memleak(x, __LINE__, __FILE__)
#define RunCalloc(x,y) RunCalloc_memleak(x,y, __LINE__, __FILE__)
#define RunRealloc(x,y) RunRealloc_memleak(x,y, __LINE__, __FILE__)
#else
extern void *RunMalloc(size_t size);
extern void *RunCalloc(size_t nmemb, size_t size);
extern void *RunRealloc(void *ptr, size_t size);
#endif
extern int RunFree_test(void *ptr);
extern void RunFree(void *ptr);
#ifdef MEMSIZESTATS
extern unsigned int get_alloc_cnt(void);
extern size_t get_mem_size(void);
#endif

#else /* !DEBUGMALLOC */

#include <stdlib.h>

#undef MEMSIZESTATS
#undef MEMMAGICNUMS
#undef MEMLEAKSTATS
#undef MEMTIMESTATS

#define Debug_malloc(x)
#define RunMalloc(x) malloc(x)
#define RunCalloc(x,y) calloc(x,y)
#define RunRealloc(x,y) realloc(x,y)
#define RunFree(x) free(x)

#endif /* DEBUGMALLOC */

#endif /* RUNMALLOC_H */
