/*
 * IRC - Internet Relay Chat, common/dbuf.c
 * Copyright (C) 1990 Markku Savela
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
#include "config.h"

#include "dbuf.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "send.h"
#include "sys.h"       /* MIN */

#include <assert.h>
#include <string.h>

/*
 * dbuf is a collection of functions which can be used to
 * maintain a dynamic buffering of a byte stream.
 * Functions allocate and release memory dynamically as
 * required [Actually, there is nothing that prevents
 * this package maintaining the buffer on disk, either]
 */

int DBufAllocCount = 0;
int DBufUsedCount = 0;

static struct DBufBuffer *dbufFreeList = 0;

#define DBUF_SIZE 2048

struct DBufBuffer {
  struct DBufBuffer *next;      /* Next data buffer, NULL if last */
  char *start;                  /* data starts here */
  char *end;                    /* data ends here */
  char data[DBUF_SIZE];         /* Actual data stored here */
};

void dbuf_count_memory(size_t *allocated, size_t *used)
{
  assert(0 != allocated);
  assert(0 != used);
  *allocated = DBufAllocCount * sizeof(struct DBufBuffer);
  *used = DBufUsedCount * sizeof(struct DBufBuffer);
}

/*
 * dbuf_alloc - allocates a DBufBuffer structure from the free list or
 * creates a new one.
 */
static struct DBufBuffer *dbuf_alloc(void)
{
  struct DBufBuffer* db = dbufFreeList;

  if (db) {
    dbufFreeList = db->next;
    ++DBufUsedCount;
  }
  else if (DBufAllocCount * DBUF_SIZE < feature_int(FEAT_BUFFERPOOL)) {
    db = (struct DBufBuffer*) MyMalloc(sizeof(struct DBufBuffer));
    assert(0 != db);
    ++DBufAllocCount;
    ++DBufUsedCount;
  }
  return db;
}

/*
 * dbuf_free - return a struct DBufBuffer structure to the freelist
 */
static void dbuf_free(struct DBufBuffer *db)
{
  assert(0 != db);
  --DBufUsedCount;
  db->next = dbufFreeList;
  dbufFreeList = db;
}

/*
 * This is called when malloc fails. Scrap the whole content
 * of dynamic buffer. (malloc errors are FATAL, there is no
 * reason to continue this buffer...).
 * After this the "dbuf" has consistent EMPTY status.
 */
static int dbuf_malloc_error(struct DBuf *dyn)
{
  struct DBufBuffer *db;
  struct DBufBuffer *next;

  for (db = dyn->head; db; db = next)
  {
    next = db->next;
    dbuf_free(db);
  }
  dyn->tail = dyn->head = 0;
  dyn->length = 0;
  return 0;
}

/*
 * dbuf_put - Append the number of bytes to the buffer, allocating memory 
 * as needed. Bytes are copied into internal buffers from users buffer.
 *
 * Returns > 0, if operation successful
 *         < 0, if failed (due memory allocation problem)
 *
 * dyn:         Dynamic buffer header
 * buf:         Pointer to data to be stored
 * length:      Number of bytes to store
 */
int dbuf_put(struct DBuf *dyn, const char *buf, unsigned int length)
{
  struct DBufBuffer** h;
  struct DBufBuffer*  db;
  unsigned int chunk;

  assert(0 != dyn);
  assert(0 != buf);
  /*
   * Locate the last non-empty buffer. If the last buffer is full,
   * the loop will terminate with 'db==NULL'.
   * This loop assumes that the 'dyn->length' field is correctly
   * maintained, as it should--no other check really needed.
   */
  if (!dyn->length)
    h = &(dyn->head);
  else
    h = &(dyn->tail);
  /*
   * Append users data to buffer, allocating buffers as needed
   */
  dyn->length += length;

  for (; length > 0; h = &(db->next)) {
    if (0 == (db = *h)) {
      if (0 == (db = dbuf_alloc())) {
	if (feature_bool(FEAT_HAS_FERGUSON_FLUSHER)) {
	  /*
	   * from "Married With Children" episode were Al bought a REAL toilet
	   * on the black market because he was tired of the wimpy water
	   * conserving toilets they make these days --Bleep
	   */
	  /*
	   * Apparently this doesn't work, the server _has_ to
	   * dump a few clients to handle the load. A fully loaded
	   * server cannot handle a net break without dumping some
	   * clients. If we flush the connections here under a full
	   * load we may end up starving the kernel for mbufs and
	   * crash the machine
	   */
	  /*
	   * attempt to recover from buffer starvation before
	   * bailing this may help servers running out of memory
	   */
	  flush_connections(0);
	  db = dbuf_alloc();
	}

        if (0 == db)
          return dbuf_malloc_error(dyn);
      }
      dyn->tail = db;
      *h = db;
      db->next = 0;
      db->start = db->end = db->data;
    }
    chunk = (db->data + DBUF_SIZE) - db->end;
    if (chunk) {
      if (chunk > length)
        chunk = length;

      memcpy(db->end, buf, chunk);

      length -= chunk;
      buf += chunk;
      db->end += chunk;
    }
  }
  return 1;
}

/*
 * dbuf_map, dbuf_delete
 *
 * These functions are meant to be used in pairs and offer a more efficient
 * way of emptying the buffer than the normal 'dbuf_get' would allow--less
 * copying needed.
 *
 *    map     returns a pointer to a largest contiguous section
 *            of bytes in front of the buffer, the length of the
 *            section is placed into the indicated "long int"
 *            variable. Returns NULL *and* zero length, if the
 *            buffer is empty.
 *
 *    delete  removes the specified number of bytes from the
 *            front of the buffer releasing any memory used for them.
 *
 *    Example use (ignoring empty condition here ;)
 *
 *            buf = dbuf_map(&dyn, &count);
 *            <process N bytes (N <= count) of data pointed by 'buf'>
 *            dbuf_delete(&dyn, N);
 *
 *    Note:   delete can be used alone, there is no real binding
 *            between map and delete functions...
 *
 * dyn:         Dynamic buffer header
 * length:      Return number of bytes accessible
 */
const char *dbuf_map(const struct DBuf* dyn, unsigned int* length)
{
  assert(0 != dyn);
  assert(0 != length);

  if (0 == dyn->length)
  {
    *length = 0;
    return 0;
  }
  assert(0 != dyn->head);

  *length = dyn->head->end - dyn->head->start;
  return dyn->head->start;
}

/*
 * dbuf_delete - delete length bytes from DBuf
 *
 * dyn:         Dynamic buffer header
 * length:      Number of bytes to delete
 */
void dbuf_delete(struct DBuf *dyn, unsigned int length)
{
  struct DBufBuffer *db;
  unsigned int chunk;

  if (length > dyn->length)
    length = dyn->length;

  while (length > 0)
  {
    if (0 == (db = dyn->head))
      break;
    chunk = db->end - db->start;
    if (chunk > length)
      chunk = length;

    length -= chunk;
    dyn->length -= chunk;
    db->start += chunk;

    if (db->start == db->end)
    {
      dyn->head = db->next;
      dbuf_free(db);
    }
  }
  if (0 == dyn->head)
  {
    dyn->length = 0;
    dyn->tail = 0;
  }
}

/*
 * dbuf_get
 *
 * Remove number of bytes from the buffer, releasing dynamic memory,
 * if applicaple. Bytes are copied from internal buffers to users buffer.
 *
 * Returns the number of bytes actually copied to users buffer,
 * if >= 0, any value less than the size of the users
 * buffer indicates the dbuf became empty by this operation.
 *
 * Return 0 indicates that buffer was already empty.
 *
 * dyn:         Dynamic buffer header
 * buf:         Pointer to buffer to receive the data
 * length:      Max amount of bytes that can be received
 */
unsigned int dbuf_get(struct DBuf *dyn, char *buf, unsigned int length)
{
  unsigned int moved = 0;
  unsigned int chunk;
  const char *b;

  assert(0 != dyn);
  assert(0 != buf);

  while (length > 0 && (b = dbuf_map(dyn, &chunk)) != 0)
  {
    if (chunk > length)
      chunk = length;

    memcpy(buf, b, chunk);
    dbuf_delete(dyn, chunk);

    buf += chunk;
    length -= chunk;
    moved += chunk;
  }
  return moved;
}

static unsigned int dbuf_flush(struct DBuf *dyn)
{
  struct DBufBuffer *db = dyn->head;

  if (0 == db)
    return 0;

  assert(db->start < db->end);
  /*
   * flush extra line terms
   */
  while (IsEol(*db->start))
  {
    if (++db->start == db->end)
    {
      dyn->head = db->next;
      dbuf_free(db);
      if (0 == (db = dyn->head))
      {
        dyn->tail = 0;
        dyn->length = 0;
        break;
      }
    }
    --dyn->length;
  }
  return dyn->length;
}


/*
 * dbuf_getmsg - Check the buffers to see if there is a string which is
 * terminated with either a \r or \n present.  If so, copy as much as 
 * possible (determined by length) into buf and return the amount copied 
 * else return 0.
 */
unsigned int dbuf_getmsg(struct DBuf *dyn, char *buf, unsigned int length)
{
  struct DBufBuffer *db;
  char *start;
  char *end;
  unsigned int count;
  unsigned int copied = 0;

  assert(0 != dyn);
  assert(0 != buf);

  if (0 == dbuf_flush(dyn))
    return 0;

  assert(0 != dyn->head);

  db = dyn->head;
  start = db->start;

  assert(start < db->end);

  if (length > dyn->length)
    length = dyn->length;
  /*
   * might as well copy it while we're here
   */
  while (length > 0)
  {
    end = IRCD_MIN(db->end, (start + length));
    while (start < end && !IsEol(*start))
      *buf++ = *start++;

    count = start - db->start;
    if (start < end)
    {
      *buf = '\0';
      copied += count;
      dbuf_delete(dyn, copied);
      dbuf_flush(dyn);
      return copied;
    }
    if (0 == (db = db->next))
      break;
    copied += count;
    length -= count;
    start = db->start;
  }
  return 0;
}
