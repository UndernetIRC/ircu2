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

#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/uio.h>	/* struct iovec */

struct MsgBuf {
  struct MsgBuf *next;		/* next msg in global queue */
  struct MsgBuf **prev_p;	/* what points to us in linked list */
  unsigned int ref;		/* reference count */
  unsigned int length;		/* length of message */
  char msg[BUFSIZE + 1];	/* the message */
};

struct Msg {
  struct Msg *next;		/* next msg */
  unsigned int sent;		/* bytes in msg that have already been sent */
  struct MsgBuf *msg;		/* actual message in queue */
};

static struct {
  struct MsgBuf *msgs;
  struct MsgBuf *free_mbs;
  struct Msg *free_msgs;
} MQData = { 0, 0, 0 };

static struct MsgSizes {
  unsigned int msgs;
  unsigned int sizes[BUFSIZE];
} msgSizes = { 0 };

struct MsgCounts msgBufCounts = { 0, 0 };
struct MsgCounts msgCounts = { 0, 0 };

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

    msgCounts.used--; /* struct Msg is not in use anymore */

    m->next = MQData.free_msgs; /* throw it onto the free list */
    MQData.free_msgs = m;
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
msgq_alloc(void)
{
  struct MsgBuf *mb = MQData.free_mbs; /* start with freelist */

  if (mb) /* if the freelist is non-empty, allocate one */
    MQData.free_mbs = MQData.free_mbs->next;
  /* Only malloc() another if we won't blow the top off the bufferpool */
  else if (msgBufCounts.alloc * sizeof(struct MsgBuf) <
	   feature_int(FEAT_BUFFERPOOL)) {
    mb = (struct MsgBuf *)MyMalloc(sizeof(struct MsgBuf));
    msgBufCounts.alloc++; /* we allocated another */
  }

  return mb;
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

/*    if (!(mb = MQData.free_mbs)) { / * do I need to allocate one? * / */
/*      if (msgBufCounts.alloc * sizeof(struct MsgBuf) >= */
/*  	feature_int(FEAT_BUFFERPOOL)) { */
/*        return 0; */
/*      } */
/*      mb = (struct MsgBuf *)MyMalloc(sizeof(struct MsgBuf)); */
/*      msgBufCounts.alloc++; / * we allocated another * / */
/*    } else / * shift the free list * / */
/*      MQData.free_mbs = MQData.free_mbs->next; */

  if (!(mb = msgq_alloc())) {
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
      mb = msgq_alloc();
    }
    if (!mb) { /* OK, try killing a client */
      kill_highest_sendq(0); /* Don't kill any server connections */
      mb = msgq_alloc();
    }
    if (!mb) { /* hmmm... */
      kill_highest_sendq(1); /* Try killing a server connection now */
      mb = msgq_alloc();
    }
    if (!mb) /* AIEEEE! */
      server_die("Unable to allocate a buffer!");
  }


  msgBufCounts.used++; /* we're using another */

  mb->next = MQData.msgs; /* initialize the msgbuf */
  mb->prev_p = &MQData.msgs;
  mb->ref = 1;

  /* fill the buffer */
  mb->length = ircd_vsnprintf(dest, mb->msg, sizeof(mb->msg) - 2, format, vl);

  if (mb->length > sizeof(mb->msg) - 3)
    mb->length = sizeof(mb->msg) - 3;

  mb->msg[mb->length++] = '\r'; /* add \r\n to buffer */
  mb->msg[mb->length++] = '\n';
  mb->msg[mb->length] = '\0'; /* not strictly necessary */

  assert(mb->length < sizeof(mb->msg));

  if (MQData.msgs) /* link it into the list */
    MQData.msgs->prev_p = &mb->next;
  MQData.msgs = mb;

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

  assert(2 < mb->length);
  assert(sizeof(mb->msg) > mb->length);

  mb->length -= 2; /* back up to before \r\n */

  va_start(vl, format); /* append to the buffer */
  mb->length += ircd_vsnprintf(dest, mb->msg + mb->length,
			       sizeof(mb->msg) - 2 - mb->length, format, vl);
  va_end(vl);

  if (mb->length > sizeof(mb->msg) - 3)
    mb->length = sizeof(mb->msg) - 3;

  mb->msg[mb->length++] = '\r'; /* add \r\n to buffer */
  mb->msg[mb->length++] = '\n';
  mb->msg[mb->length] = '\0'; /* not strictly necessary */

  assert(mb->length < sizeof(mb->msg));
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
  assert(0 != mb->prev_p);

  if (!--mb->ref) { /* deallocate the message */
    *mb->prev_p = mb->next; /* clip it out of active MsgBuf's list */
    if (mb->next)
      mb->next->prev_p = mb->prev_p;

    mb->next = MQData.free_mbs; /* add it to free list */
    MQData.free_mbs = mb;

    mb->prev_p = 0;

    msgBufCounts.used--; /* decrement the usage count */
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

  Debug((DEBUG_SEND, "Adding buffer %p [%.*s] to %s queue", mb,
	 mb->length - 2, mb->msg, prio ? "priority" : "normal"));

  qlist = prio ? &mq->prio : &mq->queue;

  if (!(msg = MQData.free_msgs)) { /* do I need to allocate one? */
    msg = (struct Msg *)MyMalloc(sizeof(struct Msg));
    msgCounts.alloc++; /* we allocated another */
  } else /* shift the free list */
    MQData.free_msgs = MQData.free_msgs->next;

  msgCounts.used++; /* we're using another */

  msg->next = 0; /* initialize the msg */
  msg->sent = 0;
  msg->msg = mb;

  /* increment the ref count on the buffer */
  if (mb->ref++ == 1) {
    /* Keep a histogram of message sizes */
    msgSizes.msgs++;
    msgSizes.sizes[mb->length]++;
  }

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
msgq_count_memory(size_t *msg_alloc, size_t *msg_used, size_t *msgbuf_alloc,
		  size_t *msgbuf_used)
{
  assert(0 != msg_alloc);
  assert(0 != msg_used);
  assert(0 != msgbuf_alloc);
  assert(0 != msgbuf_used);

  *msg_alloc = msgCounts.alloc * sizeof(struct Msg);
  *msg_used = msgCounts.used * sizeof(struct Msg);
  *msgbuf_alloc = msgBufCounts.alloc * sizeof(struct MsgBuf);
  *msgbuf_used = msgBufCounts.used * sizeof(struct MsgBuf);
}

/*
 * This routine is used simply to report how much bufferspace is left.
 */
unsigned int
msgq_bufleft(struct MsgBuf *mb)
{
  assert(0 != mb);

  return sizeof(mb->msg) - mb->length - 1; /* \r\n counted in mb->length */
}

/*
 * This just generates and sends a histogram of message lengths to the
 * requesting client
 */
void
msgq_histogram(struct Client *cptr)
{
  struct MsgSizes tmp = msgSizes; /* All hail structure copy! */
  int i;

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Histogram of message lengths (%lu messages)", tmp.msgs);
  for (i = 0; i + 16 < BUFSIZE; i += 16)
    send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":% 4d: %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", i,
	       tmp.sizes[i +  0], tmp.sizes[i +  1], tmp.sizes[i +  2],
	       tmp.sizes[i +  3], tmp.sizes[i +  4], tmp.sizes[i +  5],
	       tmp.sizes[i +  6], tmp.sizes[i +  7], tmp.sizes[i +  8],
	       tmp.sizes[i +  9], tmp.sizes[i + 10], tmp.sizes[i + 11],
	       tmp.sizes[i + 12], tmp.sizes[i + 13], tmp.sizes[i + 14],
	       tmp.sizes[i + 15]);
}
