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
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_snprintf.h"
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
 * This routine builds a struct MsgBuf with the appropriate contents
 * and returns it; this saves us from having to worry about the contents
 * of struct MsgBuf in anything other than this module
 */
struct MsgBuf *
msgq_vmake(struct Client *dest, const char *format, va_list vl)
{
  struct MsgBuf *mb;

  assert(0 != format);

  if (!(mb = MQData.free_mbs)) { /* do I need to allocate one? */
    mb = (struct MsgBuf *)MyMalloc(sizeof(struct MsgBuf));
    msgBufCounts.alloc++; /* we allocated another */
  } else /* shift the free list */
    MQData.free_mbs = MQData.free_mbs->next;

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

  mb->ref++; /* increment the ref count on the buffer */

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
