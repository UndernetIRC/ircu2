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
 */
/*
 * NOTE: Do not include fda.h here
 */
#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(MDEBUG)

#ifndef HTABLE_SIZE
#define HTABLE_SIZE 65539
/* #define HTABLE_SIZE 16339 */ /* prime around 16K */
/* #define HTABLE_SIZE 251 */
#endif

#define SHRED_BYTE 0xcd
#if 0
#if defined(_i386)
#define SHRED_BYTE 0xcd
#else
#define SHRED_BYTE 0xa3
#endif /* !_i386 */
#endif /* 0 */

#define SHRED_MEM(a,s)  memset((a), SHRED_BYTE, (s))

#define S_SIZE sizeof(size_t)
#define BYTE_PTR(x) (unsigned char*)((x))

#define BASE_PTR(p) (BYTE_PTR(p) - S_SIZE)
#define BASE_SIZE(s) ((((s) + (S_SIZE - 1) + 2 * S_SIZE) / S_SIZE) * S_SIZE)

struct Location {
  struct Location* next;     /* list next pointer */
  struct Location* prev;     /* list prev pointer */
  const char* file;          /* file name for allocation */
  int         line;          /* line allocated on */
  int         count;         /* number of allocations for this location */
};

struct BlkHdr {
  struct BlkHdr*   next;       /* Next block in list */
  void*            buf;        /* Allocated buffer */
  size_t           size;       /* Size of allocated buffer */
  int              ref;        /* Buffer referenced flag */
  time_t           timestamp;  /* Time memory was allocated */
  struct Location* location;   /* Where the allocation took place */
}; 

typedef struct BlkHdr   BlkHdr;
typedef struct Location Location;

/*
 * lowmem_fn - default low memory handler
 */
static void lowmem_fn(void)
{
  return;
}

/*
 * nomem_fn - default no memory handler
 */
static void nomem_fn(void)
{
  exit(2);
}

static void (*lowMemFn)(void) = lowmem_fn;  /* default low memory handler */
static void (*noMemFn)(void)  = nomem_fn;   /* default no memory handler */

/* begin/end marker signature */
static const size_t DEADBEEF = 0xdeadbeef; 
static size_t  byteCount = 0;          /* count of currently allocated bytes */
static size_t  blockCount = 0;         /* count of allocated blocks */
static size_t  byteLimit = 0xffffffff; /* memory size limiter */
static BlkHdr* bhTab[HTABLE_SIZE];     /* hash table for allocated blocks */
static Location* locationList = 0;     /* linked list of memory locations */

/*
 * fda_set_lowmem_handler - set handler for low memory conditions 
 *  this will be called if malloc fails once
 */
void fda_set_lowmem_handler(void (*fn)(void))
{
  lowMemFn = (fn) ? fn : lowmem_fn;
}

/*
 * set_nomem_handler - set handler for no memory conditions
 * The nomem_handler is called if lowMemFn returns and malloc fails a second
 * time, the library will assert if lowMemFn is allowed to return
 */
void fda_set_nomem_handler(void (*fn)(void))
{
  noMemFn = (fn) ? fn : nomem_fn;
}

/*
 * fda_get_byte_count - returns the client memory allocated in bytes
 */
size_t fda_get_byte_count(void)
{
  return byteCount;
}

/*
 * fda_get_block_count - returns the number of blocks allocated
 */
size_t fda_get_block_count(void)
{
  return blockCount;
}

/*
 * findLocation - finds a location on the list, this
 * only compares pointers so it should only be used with
 * ANSI __FILE__ and __LINE__ macros.
 */
static Location* findLocation(const char* file, int line)
{
  Location* location = locationList;
  for ( ; location; location = location->next) {
    if (file == location->file && line == location->line)
      return location;
  }
  return 0;
}

/*
 * addLocation - adds a allocation location to the list
 * returns a pointer to the new location
 */
static Location* addLocation(const char* file, int line)
{
  Location* location;
  assert(0 != file);
  if ((location = (Location*) malloc(sizeof(Location))) != 0) {
    location->next = locationList;
    location->prev = 0;
    location->file = file;
    location->line = line;
    location->count = 0;
    if (location->next)
      location->next->prev = location;
    locationList = location;
  }
  return location;
}

/*
 * freeLocation - frees a file/line info location
 */
static void freeLocation(Location* location)
{
  assert(0 != location);
  assert(0 == location->count);

  if (0 != location->next)
    location->next->prev = location->prev;
  if (0 != location->prev)
    location->prev->next = location->next;
  else
    locationList = location->next;
  free(location);
}

/*
 * hash_ptr - simple pointer hash function
 */
static unsigned long hash_ptr(const void* p)
{
  return ((unsigned long) p >> 3) % HTABLE_SIZE;
#if 0
  return (((unsigned long) p >> 3) ^ ~((unsigned long) p)) % HTABLE_SIZE;
  return (((unsigned long) p >> 3) | ((unsigned long) p) << 3) % HTABLE_SIZE;
#endif
}

/*
 * find_blk_exhaustive - find a block by scanning the
 * entire hash table. This function finds blocks that do not
 * start at the pointer returned from Malloc.
 */
static BlkHdr* find_blk_exhaustive(const void* p)
{
  int i;
  BlkHdr* bh;

  for (i = 0; i < HTABLE_SIZE; ++i) {
    for (bh = bhTab[i]; bh; bh = bh->next) {
      if (bh->buf <= p && BYTE_PTR(p) < (BYTE_PTR(bh->buf) + bh->size))
        return bh;
    }
  }
  return 0;
}

/*
 * fda_dump_hash - enumerate hash table link counts
 */
void fda_dump_hash(void (*enumfn)(int, int))
{
  int i = 0;
  BlkHdr* bh;
  for (i = 0; i < HTABLE_SIZE; ++i) {
    int count = 0;
    for (bh = bhTab[i]; bh; bh = bh->next)
      ++count;
    (*enumfn)(i, count);
  }
}
 
/*
 * find_blk - return the block struct associated with the
 * pointer p.
 */
static BlkHdr* find_blk(const void* p)
{
  BlkHdr* bh = bhTab[hash_ptr(p)];
  for ( ; bh; bh = bh->next) {
    if (p == bh->buf)
      return bh;
  }
  return find_blk_exhaustive(p);
}

/*
 * make_blk - create a block header and add it to the hash table
 */
static int make_blk(unsigned char* p, size_t size, Location* loc)
{
  BlkHdr* bh;

  assert(0 != p);
  assert(0 < size);
  assert(0 != loc);

  if ((bh = (BlkHdr*) malloc(sizeof(BlkHdr))) != 0) {
    unsigned long h = hash_ptr(p);
    bh->ref       = 0;
    bh->buf       = p;
    bh->size      = size;
    bh->location  = loc;
    bh->timestamp = time(0);
    bh->next      = bhTab[h];
    bhTab[h]      = bh;
    ++bh->location->count;
    byteCount += size;
    ++blockCount;
  }
  return (0 != bh);
}

/*
 * free_blk - remove a block header and free it
 */
static void free_blk(const void* p)
{
  BlkHdr* bh_prev = 0;
  BlkHdr* bh;
  unsigned long h = hash_ptr(p);

  for (bh = bhTab[h]; bh; bh = bh->next) {
    if (p == bh->buf) {
      if (0 == bh_prev)
        bhTab[h] = bh->next;
      else
        bh_prev->next = bh->next;
      break;
    }
    bh_prev = bh;
  }
  /* 
   * if bh is NULL p was not allocated here 
   */
  assert(0 != bh);
  assert(bh->location->count > 0);
  if (--bh->location->count == 0)
    freeLocation(bh->location);

  byteCount -= bh->size;
  --blockCount;

  SHRED_MEM(bh, sizeof(BlkHdr));
  free(bh);
}

/*
 * update_blk - update block info, rehash if pointers are different,
 * update location info if needed
 */
static void update_blk(void* p, void* np, size_t size, const char* file, int line)
{
  BlkHdr* bh;
  if (p != np) {
    BlkHdr* bh_prev = 0;
    unsigned long h = hash_ptr(p);

    /* 
     * remove the old entry from the hash table 
     */
    for (bh = bhTab[h]; bh; bh = bh->next) {
      if (p == bh->buf) {
        if (0 == bh_prev)
          bhTab[h] = bh->next;
        else
          bh_prev->next = bh->next;
        /* 
         * put it back in the hash table at hash(np) 
         */
        h = hash_ptr(np);
        bh->next = bhTab[h];
        bhTab[h] = bh;
        break;
      }
      bh_prev = bh;
    }
  }
  else
    bh = find_blk(p);
  /*
   * invalid ptr? 
   */
  assert(0 != bh);
  byteCount -= bh->size;
  byteCount += size;
  bh->buf = np;
  bh->size = size;
  /* 
   * update location info 
   */
  if (bh->location->file != file || bh->location->line != line) {
    if (--bh->location->count == 0)
      freeLocation(bh->location);
    if ((bh->location = findLocation(file, line)) == 0) {
      if ((bh->location = addLocation(file, line)) == 0)
        noMemFn();
    }
    assert(0 != bh->location);
    ++bh->location->count;
  }
}

/*
 * fda_sizeof - returns the size of block of memory pointed to by p
 */
size_t fda_sizeof(const void* p)
{
  BlkHdr* bh = find_blk(p);
  assert(0 != bh);
  assert(p == bh->buf);
  return bh->size;
}

void fda_set_byte_limit(size_t limit)
{
  byteLimit = limit;
}

/*
 * fda_clear_refs - clear referenced markers on all blocks
 */
void fda_clear_refs(void)
{
  int i;
  BlkHdr* bh;

  for (i = 0; i < HTABLE_SIZE; ++i) {
    for (bh = bhTab[i]; bh; bh = bh->next)
      bh->ref = 0;
  }
}

/*
 * fda_set_ref - mark block as referenced
 */
void fda_set_ref(const void* p)
{
  BlkHdr* bh = find_blk(p);
  assert(0 != bh);
  bh->ref = 1;
}

/*
 * fda_assert_refs - scan for all blocks and check for null
 * ptrs and unreferenced (lost) blocks
 */
void fda_assert_refs(void)
{
  int i;
  BlkHdr* bh;

  for (i = 0; i < HTABLE_SIZE; ++i) {
    for (bh = bhTab[i]; bh; bh = bh->next) {
      assert(0 != bh->buf && 0 < bh->size);
      assert(1 == bh->ref);
    }
  }
}

/*
 * valid_ptr - returns true if p points to allocated memory and
 * has at least size available
 */
int valid_ptr(const void* p, size_t size)
{
  BlkHdr* bh;
  assert(0 != p);
  assert(0 < size);

  bh = find_blk(p);
  /*
   * check that there are at least size bytes available from p
   */
  assert((BYTE_PTR(p) + size) <= (BYTE_PTR(bh->buf) + bh->size));
  return 1;
}

/*
 * fda_enum_locations - calls enumfn to list file, line, and count
 * info for allocations, returns the number of locations found
 */
int fda_enum_locations(void (*enumfn)(const char*, int, int))
{
  int count = 0;
  Location* location;
  assert(0 != enumfn);
  for (location = locationList; location; location = location->next) {
    (*enumfn)(location->file, location->line, location->count);
    ++count;
  }
  return count;
}

/*
 * fda_enum_leaks - scan hash table for leaks and call enumfn to
 * report them.
 */
int fda_enum_leaks(void (*enumfn)(const char*, int, size_t, void*))
{
  int count = 0;
  BlkHdr* bh;
  int i;
  for (i = 0; i < HTABLE_SIZE; ++i) {
    for (bh = bhTab[i]; bh; bh = bh->next) {
      if (0 == bh->ref) {
        (*enumfn)(bh->location->file, bh->location->line, bh->size, bh->buf);
        ++count;
      }
    }
  }
  return count;
}

/*
 * fda_malloc - allocate size chunk of memory and create debug
 * records for it.
 */
void* fda_malloc(size_t size, const char* file, int line)
{
  void* p;
  size_t blk_size;
  Location* location;

  assert(0 < size);
  assert(0 != file);
  assert(sizeof(void*) == sizeof(size_t));

  /*
   * memory limiter do not allocate more than byteLimit
   */
  if ((size + byteCount) > byteLimit)
    return 0;

  /* 
   * Make sure that there is enough room for prefix/postfix 
   * and we get an aligned buffer 
   */
  blk_size = BASE_SIZE(size);

  if ((p = malloc(blk_size)) == 0) {
    lowMemFn();
    if ((p = malloc(blk_size)) == 0)
      noMemFn();
  }
  /* 
   * don't allow malloc to fail 
   */
  assert(0 != p);
  /* 
   * shred the memory and set bounds markers 
   */
  SHRED_MEM(p, blk_size);
  *((size_t*) p) = DEADBEEF;
  *((size_t*) (BYTE_PTR(p) + blk_size - S_SIZE)) = DEADBEEF;

  /* 
   * find the location or create a new one 
   */
  if (0 == (location = findLocation(file, line))) {
    if (0 == (location = addLocation(file, line))) {
      free(p);
      noMemFn();
    }
  }
  /* 
   * don't allow noMemFn to return 
   */
  assert(0 != location);
  if (!make_blk(BYTE_PTR(p) + S_SIZE, size, location)) {
    if (0 == location->count)
      freeLocation(location);
    free(p);
    p = 0;
    noMemFn();
  }
  /* 
   * don't allow noMemFn to return 
   */
  assert(0 != p);
  return (BYTE_PTR(p) + S_SIZE);
}

/*
 * fda_free - check chunk of memory for overruns and free it
 */
void fda_free(void* p)
{
  if (p) {
    size_t size;
    BlkHdr* bh = find_blk(p);
    void*   bp;

    /* p already freed or not allocated? */
    assert(0 != bh);
    assert(p == bh->buf);

    bp = BASE_PTR(p);
    /* buffer underflow? */
    assert(DEADBEEF == *((size_t*) bp));
    /* 
     * buffer overflow?
     * Note: it's possible to have up to 3 bytes of unchecked space 
     * between size and DEADBEEF
     */
    size = BASE_SIZE(bh->size);
    assert(DEADBEEF == *((size_t*)(BYTE_PTR(bp) + size - S_SIZE)));
    SHRED_MEM(bp, size);

    free_blk(p);
    free(bp);
  }
}

/*
 * fda_realloc - resize a buffer, force reallocation if new size is
 * larger than old size
 */
void* fda_realloc(void* p, size_t size, const char* file, int line)
{
  void* np;
  size_t old_size;
  size_t blk_size;
  /* 
   * don't allow malloc or free through realloc 
   */
  assert(0 != p);
  assert(0 < size);
  old_size = fda_sizeof(p);
  
  if (size < old_size)
    SHRED_MEM(BYTE_PTR(p) + size, old_size - size);
  else if (size > old_size) {
    void* t = fda_malloc(size, __FILE__, __LINE__);
    memmove(t, p, old_size);
    fda_free(p);
    p = t;
  }
  blk_size = BASE_SIZE(size);

  if ((np = realloc(BASE_PTR(p), blk_size)) == 0) {
    lowMemFn();
    if ((np = realloc(BASE_PTR(p), blk_size)) == 0)
      noMemFn();
  }
  /* 
   * don't allow noMemFn to return 
   */
  assert(0 != np);

  *((size_t*)(BYTE_PTR(np) + blk_size - S_SIZE)) = DEADBEEF;

  np = BYTE_PTR(np) + S_SIZE;
  update_blk(p, np, size, file, line);
  /* 
   * shred tail 
   */
  if (size > old_size)
    SHRED_MEM(BYTE_PTR(np) + old_size, size - old_size);

  return np;
}

/*
 * fda_calloc - allocate 0 initialized buffer nelems * size length
 */
void* fda_calloc(size_t nelems, size_t size, const char* file, int line)
{
  void* p;
  assert(0 < nelems);
  assert(0 < size);
  assert(0 != file);
  size *= nelems;
  p = fda_malloc(size, file, line);
  memset(p, 0, size);
  return p;
}

/*
 * fda_strdup - duplicates a string returns newly allocated string
 */
char* fda_strdup(const char* src, const char* file, int line)
{
  char* p;
  assert(0 != src);
  p = (char*) fda_malloc(strlen(src) + 1, file, line);
  strcpy(p, src);
  return p;
}

#endif /* defined(MDEBUG) */

