#ifndef INCLUDED_msgq_h
#define INCLUDED_msgq_h
/*
 * IRC - Internet Relay Chat, include/msgq.h
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"	/* BUFSIZE */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>
#define INCLUDED_stdarg_h
#endif

struct iovec;

struct Client;
struct StatDesc;

struct Msg;
struct MsgBuf;

struct MsgQList {
  struct Msg *head;		/* First Msg in queue list */
  struct Msg *tail;		/* Last Msg in queue list */
};

struct MsgQ {
  unsigned int length;		/* Current number of bytes stored */
  unsigned int count;		/* Current number of messages stored */
  struct MsgQList queue;	/* Normal Msg queue */
  struct MsgQList prio;		/* Priority Msg queue */
};

/*
 * MsgQLength - Returns the current number of bytes stored in the buffer.
 */
#define MsgQLength(mq) ((mq)->length)

/*
 * MsgQCount - Returns the current number of messages stored in the buffer
 */
#define MsgQCount(mq) ((mq)->count)

/*
 * MsgQClear - Scratch the current content of the buffer.
 * Release all allocated buffers and make it empty.
 */
#define MsgQClear(mq) msgq_delete((mq), MsgQLength(mq))

/*
 * Prototypes
 */
extern void msgq_init(struct MsgQ *mq);
extern void msgq_delete(struct MsgQ *mq, unsigned int length);
extern int msgq_mapiov(const struct MsgQ *mq, struct iovec *iov, int count,
		       unsigned int *len);
extern struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...);
extern struct MsgBuf *msgq_vmake(struct Client *dest, const char *format,
				 va_list args);
extern void msgq_append(struct Client *dest, struct MsgBuf *mb,
			const char *format, ...);
extern void msgq_clean(struct MsgBuf *mb);
extern void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio);
extern void msgq_count_memory(struct Client *cptr, size_t *msg_alloc,
			      size_t *msgbuf_alloc);
extern unsigned int msgq_bufleft(struct MsgBuf *mb);
extern void msgq_histogram(struct Client *cptr, struct StatDesc *sd, int stat,
			   char *param);

#endif /* INCLUDED_msgq_h */
