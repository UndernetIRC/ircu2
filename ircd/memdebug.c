#include <sys/types.h>
#include "ircd.h"
#include "ircd_alloc.h"
#include "client.h"
#include "s_debug.h"
#include <stdlib.h>

#include <assert.h>

#ifdef MDEBUG

/* To use this you need to get gc6.0 from:
 * http://www.hpl.hp.com/personal/Hans_Boehm/gc/
 * and you need to apply the patch in
 * doc/debug_memleak_gc.patch to your gc6.0 tree, and reconfigure your ircd using
 --with-leak-detect=path-to-gc6.0/.lib/
 * You should only do this for debugging builds as it can slow things down
 * a bit.
 */

#include "ircd_string.h"

void *GC_malloc(size_t size);
void GC_free(void *ptr);
void GC_set_leak_handler(void (*)(void*, int));
void GC_gcollect(void);
extern int GC_find_leak;

struct MemHeader
{
  uint32_t magic;
  char type[32];
  char file[32];
  int line;
  size_t length;
  time_t since;
};

void
memfrob(void *p, size_t len)
{
  /* deadbeef */
  int i = 0;
  const char *pat = "\xde\xad\xbe\xef";
  char *s, *se;

  for (s = (char*)p, se = s + (len & ~3) - 4;
       s <= se;
       s += 4)
    *(uint32_t*)s = *(uint32_t*)pat;
  for (se = s; se < s; s++)
    *s = pat[i++];
}

static size_t mdbg_bytes_allocated = 0, mdbg_blocks_allocated = 0;
static time_t last_gcollect = 0;

#define GC_FREQ 5

void
dbg_check_gcollect(void)
{
  if (CurrentTime - last_gcollect < GC_FREQ)
    return;
  GC_gcollect();
  last_gcollect = CurrentTime;
}

void*
dbg_malloc(size_t size, const char *type, const char *file, int line)
{
  struct MemHeader *mh = GC_malloc(size + sizeof(*mh));
  if (mh == NULL)
    return mh;
  memfrob((void*)(mh + 1), size);
  mh->magic = 0xA110CA7E;
  ircd_strncpy(mh->type, type, sizeof(mh->type) - 1)[sizeof(mh->type) - 1] = 0;
  ircd_strncpy(mh->file, file, sizeof(mh->file) - 1)[sizeof(mh->file) - 1] = 0;
  mh->line = line;
  mh->length = size;
  mh->since = CurrentTime;
  mdbg_bytes_allocated += size;
  mdbg_blocks_allocated++;
  dbg_check_gcollect();
  return (void*)(mh + 1);
}

void*
dbg_malloc_zero(size_t size, const char *type, const char *file, int line)
{
  struct MemHeader *mh = GC_malloc(size + sizeof(*mh));
  if (mh == NULL)
    return mh;
  memset((void*)(mh + 1), 0, size);
  mh->magic = 0xA110CA7E;
  ircd_strncpy(mh->type, type, sizeof(mh->type) - 1)[sizeof(mh->type) - 1] = 0;
  ircd_strncpy(mh->file, file, sizeof(mh->file) - 1)[sizeof(mh->file) - 1] = 0;
  mh->line = line;
  mh->length = size;
  mdbg_bytes_allocated += size;
  mdbg_blocks_allocated++;
  dbg_check_gcollect();
  return (void*)(mh + 1);
}

void*
dbg_realloc(void *ptr, size_t size, const char *file, int line)
{
  struct MemHeader *mh, *mh2;
  if (ptr == NULL)
    return dbg_malloc(size, "realloc", file, line);
  mh = (struct MemHeader*)ptr - 1;
  assert(mh->magic == 0xA110CA7E);
  if (mh->length >= size)
    return mh;
  mh2 = dbg_malloc(size, "realloc", file, line);
  if (mh2 == NULL)
  {
    dbg_free(mh+1, file, line);
    return NULL;
  }
  memcpy(mh2+1, mh+1, mh->length);
  dbg_free(mh+1, file, line);
  return (void*)(mh2+1);
}

void
dbg_free(void *ptr, const char *file, int line)
{
  struct MemHeader *mh = (struct MemHeader*)ptr - 1;
  /* XXX but bison gives us NULLs */
  if (ptr == NULL)
    return;
  assert(mh->magic == 0xA110CA7E);
  /* XXX can we get boehmgc to check for references to it? */
  memfrob(mh, mh->length + sizeof(*mh));
  mdbg_bytes_allocated -= mh->length;
  mdbg_blocks_allocated--;
  GC_free(mh);
  dbg_check_gcollect();
}

size_t
fda_get_byte_count(void)
{
  dbg_check_gcollect();
  return mdbg_bytes_allocated;
}

size_t
fda_get_block_count(void)
{
  return mdbg_blocks_allocated;
}

#include <stdio.h>

void
dbg_memory_leaked(void *p, int sz)
{
  struct MemHeader *mh;
  /* We have to return because the gc "leaks". */
  mh = p;
  if (mh->magic != 0xA110CA7E)
    return;
  sendto_opmask_butone(NULL, SNO_OLDSNO,
                       "%s leak at %s:%u(%u bytes for %u seconds)",
                       mh->type, mh->file, mh->line, mh->length,
                       CurrentTime - mh->since);
  Debug((DEBUG_ERROR,
         "%s leak at %s:%u(%u bytes for %u seconds)",
         mh->type, mh->file, mh->line, mh->length,
         CurrentTime - mh->since));
}

void
mem_dbg_initialise(void)
{
  GC_find_leak = 1;
  GC_set_leak_handler(dbg_memory_leaked);
}

#endif
