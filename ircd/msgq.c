/*
 * IRC - Internet Relay Chat, ircd/msgq.c
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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

#include "msgq.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "numeric.h"
#include "send.h"
#include "s_debug.h"
#include "s_stats.h"

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>	/* struct iovec */

#define MB_BASE_SHIFT	5
#define MB_MAX_SHIFT	9

struct MsgBuf {
  struct MsgBuf *next;		/* next msg in global queue */
  struct MsgBuf **prev_p;	/* what points to us in linked list */
  struct MsgBuf *real;		/* the actual MsgBuf we're attaching */
  unsigned int ref;		/* reference count */
  unsigned int length;		/* length of message */
  unsigned int power;		/* size of buffer (power of 2) */
  char msg[1];			/* the message */
};

#define bufsize(buf)	(1 << (buf)->power)

struct Msg {
  struct Msg *next;		/* next msg */
  unsigned int sent;		/* bytes in msg that have already been sent */
  struct MsgBuf *msg;		/* actual message in queue */
};

struct MsgSizes {
  unsigned int msgs;		/* total number of messages */
  unsigned int sizes[BUFSIZE];	/* histogram of message sizes */
};

static struct {
  struct MsgBuf *msglist;	/* list of in-use MsgBuf's */
  struct {
    unsigned int alloc;		/* number of Msg's allocated */
    unsigned int used;		/* number of Msg's in use */
    struct Msg *free;		/* freelist of Msg's */
  } msgs;
  size_t tot_bufsize;		/* total amount of memory in buffers */
  struct {
    unsigned int alloc;		/* total MsgBuf's of this size */
    unsigned int used;		/* number of MsgBuf's of this size in use */
    struct MsgBuf *free;	/* list of free MsgBuf's */
  } msgBufs[MB_MAX_SHIFT - MB_BASE_SHIFT + 1];
  struct MsgSizes sizes;	/* histogram of message sizes */
} MQData;

/*
 * This routine is used to remove a certain amount of data from a given
 * queue and release the Msg (and MsgBuf) structure if needed
 */
static void
msgq_delmsg(struct MsgQ *mq, struct MsgQList *qlist, unsigned int *length_p)
{
  struct Msg *m;
  unsigned int msglen;

  assert(0 != mq);
  assert(0 != qlist);
  assert(0 != qlist->head);
  assert(0 != length_p);

  m = qlist->head; /* find the msg we're deleting from */

  msglen = m->msg->length - m->sent; /* calculate how much is left */

  if (*length_p >= msglen) { /* deleted it all? */
    mq->length -= msglen; /* decrement length */
    mq->count--; /* decrement the message count */
    *length_p -= msglen;

    msgq_clean(m->msg); /* free up the struct MsgBuf */
    m->msg = 0; /* don't let it point anywhere nasty, please */

    if (qlist->head == qlist->tail) /* figure out if we emptied the queue */
      qlist->head = qlist->tail = 0;
    else
      qlist->head = m->next; /* just shift the list down some */

    MQData.msgs.used--; /* struct Msg is not in use anymore */

    m->next = MQData.msgs.free; /* throw it onto the free list */
    MQData.msgs.free = m;
  } else {
    mq->length -= *length_p; /* decrement queue length */
    m->sent += *length_p; /* this much of the message has been sent */
    *length_p = 0; /* we've dealt with it all */
  }
}

/*
 * This just initializes a struct MsgQ.
 */
void
msgq_init(struct MsgQ *mq)
{
  assert(0 != mq);

  mq->length = 0;
  mq->count = 0;
  mq->queue.head = 0;
  mq->queue.tail = 0;
  mq->prio.head = 0;
  mq->prio.tail = 0;
}

/*
 * This routine is used to delete the specified number of bytes off
 * of the queue.  We only really need to worry about one struct Msg*,
 * but this allows us to retain the flexibility to deal with more,
 * which means we could do something fancy involving writev...
 */
void
msgq_delete(struct MsgQ *mq, unsigned int length)
{
  assert(0 != mq);

  while (length > 0) {
    if (mq->queue.head && mq->queue.head->sent > 0) /* partial msg on norm q */
      msgq_delmsg(mq, &mq->queue, &length);
    else if (mq->prio.head) /* message (partial or complete) on prio queue */
      msgq_delmsg(mq, &mq->prio, &length);
    else if (mq->queue.head) /* message on normal queue */
      msgq_delmsg(mq, &mq->queue, &length);
    else
      break;
  }
}

/*
 * This is the more intelligent routine that can fill in an array of
 * struct iovec's.
 */
int
msgq_mapiov(const struct MsgQ *mq, struct iovec *iov, int count,
	    unsigned int *len)
{
  struct Msg *queue;
  struct Msg *prio;
  int i = 0;

  assert(0 != mq);
  assert(0 != iov);
  assert(0 != count);
  assert(0 != len);

  if (mq->length <= 0) /* no data to map */
    return 0;

  if (mq->queue.head && mq->queue.head->sent > 0) { /* partial msg on norm q */
    iov[i].iov_base = mq->queue.head->msg->msg + mq->queue.head->sent;
    iov[i].iov_len = mq->queue.head->msg->length - mq->queue.head->sent;
    *len += iov[i].iov_len;

    queue = mq->queue.head->next; /* where we start later... */

    i++; /* filled an iovec... */
    if (!--count) /* check for space */
      return i;
  } else
    queue = mq->queue.head; /* start at head of queue */

  if (mq->prio.head && mq->prio.head->sent > 0) { /* partial msg on prio q */
    iov[i].iov_base = mq->prio.head->msg->msg + mq->prio.head->sent;
    iov[i].iov_len = mq->prio.head->msg->length - mq->prio.head->sent;
    *len += iov[i].iov_len;

    prio = mq->prio.head->next; /* where we start later... */

    i++; /* filled an iovec... */
    if (!--count) /* check for space */
      return i;
  } else
    prio = mq->prio.head; /* start at head of prio */

  for (; prio; prio = prio->next) { /* go through prio queue */
    iov[i].iov_base = prio->msg->msg; /* store message */
    iov[i].iov_len = prio->msg->length;
    *len += iov[i].iov_len;

    i++; /* filled an iovec... */
    if (!--count) /* check for space */
      return i;
  }

  for (; queue; queue = queue->next) { /* go through normal queue */
    iov[i].iov_base = queue->msg->msg;
    iov[i].iov_len = queue->msg->length;
    *len += iov[i].iov_len;

    i++; /* filled an iovec... */
    if (!--count) /* check for space */
      return i;
  }

  return i;
}

/*
 * This is a helper routine to allocate a buffer
 */
static struct MsgBuf *
msgq_alloc(struct MsgBuf *in_mb, int length)
{
  struct MsgBuf *mb;
  int power;

  /* Find the power of two size that will accomodate the message */
  for (power = MB_BASE_SHIFT; power < MB_MAX_SHIFT + 1; power++)
    if ((length - 1) >> power == 0)
      break;
  assert((1 << power) >= length);
  assert((1 << power) <= 512);
  length = 1 << power; /* reset the length */

  /* If the message needs a buffer of exactly the existing size, just use it */
  if (in_mb && in_mb->power == power) {
    in_mb->real = in_mb; /* real buffer is this buffer */
    return in_mb;
  }

  /* Try popping one off the freelist first */
  if ((mb = MQData.msgBufs[power - MB_BASE_SHIFT].free)) {
    MQData.msgBufs[power - MB_BASE_SHIFT].free = mb->next;
  } else if (MQData.tot_bufsize < feature_int(FEAT_BUFFERPOOL)) {
    /* Allocate another if we won't bust the BUFFERPOOL */
    Debug((DEBUG_MALLOC, "Allocating MsgBuf of length %d (total size %zu)",
	   length, sizeof(struct MsgBuf) + length));
    mb = (struct MsgBuf *)MyMalloc(sizeof(struct MsgBuf) + length);
    MQData.msgBufs[power - MB_BASE_SHIFT].alloc++;
    mb->power = power; /* remember size */
    MQData.tot_bufsize += length;
  }

  if (mb) {
    MQData.msgBufs[power - MB_BASE_SHIFT].used++; /* how many are we using? */

    mb->real = 0; /* essential initializations */
    mb->ref = 1;

    if (in_mb) /* remember who's the *real* buffer */
      in_mb->real = mb;
  } else if (in_mb) /* just use the input buffer */
    mb = in_mb->real = in_mb;

  return mb; /* return the buffer */
}

/*
 * This routine simply empties the free list
 */
static void
msgq_clear_freembs(void)
{
  struct MsgBuf *mb;
  int i;

  /* Walk through the various size classes */
  for (i = MB_BASE_SHIFT; i < MB_MAX_SHIFT + 1; i++)
    /* walk down the free list */
    while ((mb = MQData.msgBufs[i - MB_BASE_SHIFT].free)) {
      MQData.msgBufs[i - MB_BASE_SHIFT].free = mb->next; /* shift free list */
      MQData.msgBufs[i - MB_BASE_SHIFT].alloc--; /* reduce allocation count */
      MQData.tot_bufsize -= 1 << i; /* reduce total buffer allocation count */
      MyFree(mb); /* and free the buffer */
    }
}

/*
 * This routine builds a struct MsgBuf with the appropriate contents
 * and returns it; this saves us from having to worry about the contents
 * of struct MsgBuf in anything other than this module
 */
struct MsgBuf *
msgq_vmake(struct Client *dest, const char *format, va_list vl)
{
  struct MsgBuf *mb;

  assert(0 != format);

  if (!(mb = msgq_alloc(0, BUFSIZE))) {
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
      mb = msgq_alloc(0, BUFSIZE);
    }
    if (!mb) { /* OK, try clearing the buffer free list */
      msgq_clear_freembs();
      mb = msgq_alloc(0, BUFSIZE);
    }
    if (!mb) { /* OK, try killing a client */
      kill_highest_sendq(0); /* Don't kill any server connections */
      mb = msgq_alloc(0, BUFSIZE);
    }
    if (!mb) { /* hmmm... */
      kill_highest_sendq(1); /* Try killing a server connection now */
      mb = msgq_alloc(0, BUFSIZE);
    }
    if (!mb) /* AIEEEE! */
      server_panic("Unable to allocate buffers!");
  }

  mb->next = MQData.msglist; /* initialize the msgbuf */
  mb->prev_p = &MQData.msglist;

  /* fill the buffer */
  mb->length = ircd_vsnprintf(dest, mb->msg, bufsize(mb) - 1, format, vl);

  if (mb->length > bufsize(mb) - 2)
    mb->length = bufsize(mb) - 2;

  mb->msg[mb->length++] = '\r'; /* add \r\n to buffer */
  mb->msg[mb->length++] = '\n';
  mb->msg[mb->length] = '\0'; /* not strictly necessary */

  assert(mb->length <= bufsize(mb));

  if (MQData.msglist) /* link it into the list */
    MQData.msglist->prev_p = &mb->next;
  MQData.msglist = mb;

  return mb;
}

struct MsgBuf *
msgq_make(struct Client *dest, const char *format, ...)
{
  va_list vl;
  struct MsgBuf *mb;

  va_start(vl, format);
  mb = msgq_vmake(dest, format, vl);
  va_end(vl);

  return mb;
}

/*
 * This routine is used to append a formatted string to a struct MsgBuf.
 */
void
msgq_append(struct Client *dest, struct MsgBuf *mb, const char *format, ...)
{
  va_list vl;

  assert(0 != mb);
  assert(0 != format);
  assert(0 == mb->real);

  assert(2 < mb->length);
  assert(bufsize(mb) >= mb->length);

  mb->length -= 2; /* back up to before \r\n */

  va_start(vl, format); /* append to the buffer */
  mb->length += ircd_vsnprintf(dest, mb->msg + mb->length,
			       bufsize(mb) - mb->length - 1, format, vl);
  va_end(vl);

  if (mb->length > bufsize(mb) - 2)
    mb->length = bufsize(mb) - 2;

  mb->msg[mb->length++] = '\r'; /* add \r\n to buffer */
  mb->msg[mb->length++] = '\n';
  mb->msg[mb->length] = '\0'; /* not strictly necessary */

  assert(mb->length <= bufsize(mb));
}

/*
 * This routine is called to decrement the reference count on a
 * struct MsgBuf and delete it if necessary.
 */
void
msgq_clean(struct MsgBuf *mb)
{
  assert(0 != mb);
  assert(0 < mb->ref);

  if (!--mb->ref) { /* deallocate the message */
    if (mb->prev_p) {
      *mb->prev_p = mb->next; /* clip it out of active MsgBuf's list */
      if (mb->next)
	mb->next->prev_p = mb->prev_p;
    }

    if (mb->real && mb->real != mb) /* clean up the real buffer */
      msgq_clean(mb->real);

    mb->next = MQData.msgBufs[mb->power - MB_BASE_SHIFT].free;
    MQData.msgBufs[mb->power - MB_BASE_SHIFT].free = mb;
    MQData.msgBufs[mb->power - MB_BASE_SHIFT].used--;

    mb->prev_p = 0;
  }
}

/*
 * This routine simply adds a struct Msg to the end of a user's MsgQ.
 */
void
msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio)
{
  struct MsgQList *qlist;
  struct Msg *msg;

  assert(0 != mq);
  assert(0 != mb);
  assert(0 < mb->ref);
  assert(0 < mb->length);

  Debug((DEBUG_SEND, "Adding buffer %p [%.*s] length %u to %s queue", mb,
	 mb->length - 2, mb->msg, mb->length, prio ? "priority" : "normal"));

  qlist = prio ? &mq->prio : &mq->queue;

  if (!(msg = MQData.msgs.free)) { /* do I need to allocate one? */
    msg = (struct Msg *)MyMalloc(sizeof(struct Msg));
    MQData.msgs.alloc++; /* we allocated another */
  } else /* shift the free list */
    MQData.msgs.free = MQData.msgs.free->next;

  MQData.msgs.used++; /* we're using another */

  msg->next = 0; /* initialize the msg */
  msg->sent = 0;

  /* Get the real buffer, allocating one if necessary */
  if (!mb->real) {
    struct MsgBuf *tmp;

    MQData.sizes.msgs++; /* update histogram counts */
    MQData.sizes.sizes[mb->length - 1]++;

    tmp = msgq_alloc(mb, mb->length); /* allocate a close-fitting buffer */

    if (tmp != mb) { /* OK, prepare the new "real" buffer */
      Debug((DEBUG_SEND, "Copying old buffer %p [%.*s] length %u into new "
	     "buffer %p size %u", mb, mb->length - 2, mb->msg, mb->length,
	     tmp, bufsize(tmp)));
      memcpy(tmp->msg, mb->msg, mb->length + 1); /* copy string over */
      tmp->length = mb->length;

      tmp->next = mb->next; /* replace it in the list, now */
      if (tmp->next)
	tmp->next->prev_p = &tmp->next;
      tmp->prev_p = mb->prev_p;
      *tmp->prev_p = tmp;

      mb->next = 0; /* this one's no longer in the list */
      mb->prev_p = 0;
    }
  }

  mb = mb->real; /* work with the real buffer */
  mb->ref++; /* increment the ref count on the buffer */

  msg->msg = mb; /* point at the real message buffer now */

  if (!qlist->head) /* queue list was empty; head and tail point to msg */
    qlist->head = qlist->tail = msg;
  else {
    assert(0 != qlist->tail);

    qlist->tail->next = msg; /* queue had something in it; add to end */
    qlist->tail = msg;
  }

  mq->length += mb->length; /* update the queue length */
  mq->count++; /* and the queue count */
}

/*
 * This is for reporting memory usage by the msgq system.
 */
void
msgq_count_memory(struct Client *cptr, size_t *msg_alloc, size_t *msgbuf_alloc)
{
  int i;
  size_t total = 0, size;

  assert(0 != cptr);
  assert(0 != msg_alloc);
  assert(0 != msgbuf_alloc);

  /* Data for Msg's is simple, so just send it */
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Msgs allocated %d(%zu) used %d(%zu)", MQData.msgs.alloc,
	     MQData.msgs.alloc * sizeof(struct Msg), MQData.msgs.used,
	     MQData.msgs.used * sizeof(struct Msg));
  /* count_memory() wants to know the total */
  *msg_alloc = MQData.msgs.alloc * sizeof(struct Msg);

  /* Ok, now walk through each size class */
  for (i = MB_BASE_SHIFT; i < MB_MAX_SHIFT + 1; i++) {
    size = sizeof(struct MsgBuf) + (1 << i); /* total size of a buffer */

    /* Send information for this buffer size class */
    send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	       ":MsgBufs of size %zu allocated %d(%zu) used %d(%zu)", 1 << i,
	       MQData.msgBufs[i - MB_BASE_SHIFT].alloc,
	       MQData.msgBufs[i - MB_BASE_SHIFT].alloc * size,
	       MQData.msgBufs[i - MB_BASE_SHIFT].used,
	       MQData.msgBufs[i - MB_BASE_SHIFT].used * size);

    /* count_memory() wants to know the total */
    total += MQData.msgBufs[i - MB_BASE_SHIFT].alloc * size;
  }
  *msgbuf_alloc = total;
}

/*
 * This routine is used simply to report how much bufferspace is left.
 */
unsigned int
msgq_bufleft(struct MsgBuf *mb)
{
  assert(0 != mb);

  return bufsize(mb) - mb->length; /* \r\n counted in mb->length */
}

/*
 * This just generates and sends a histogram of message lengths to the
 * requesting client
 */
void
msgq_histogram(struct Client *cptr, struct StatDesc *sd, int stat, char *param)
{
  struct MsgSizes tmp = MQData.sizes; /* All hail structure copy! */
  int i;

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Histogram of message lengths (%lu messages)", tmp.msgs);
  for (i = 0; i + 16 <= BUFSIZE; i += 16)
    send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":% 4d: %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", i + 1,
	       tmp.sizes[i +  0], tmp.sizes[i +  1], tmp.sizes[i +  2],
	       tmp.sizes[i +  3], tmp.sizes[i +  4], tmp.sizes[i +  5],
	       tmp.sizes[i +  6], tmp.sizes[i +  7], tmp.sizes[i +  8],
	       tmp.sizes[i +  9], tmp.sizes[i + 10], tmp.sizes[i + 11],
	       tmp.sizes[i + 12], tmp.sizes[i + 13], tmp.sizes[i + 14],
	       tmp.sizes[i + 15]);
}
