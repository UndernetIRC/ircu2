/*
 * IRC - Internet Relay Chat, include/uping.h
 * Copyright (C) 1995 Carlo Wood
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
#ifndef INCLUDED_uping_h
#define INCLUDED_uping_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>
#define INCLUDED_netinet_in_h
#endif
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif

struct Client;
struct ConfItem;

struct UPing
{
  struct UPing*      next;     /* next ping in list, usually null */
  int                fd;       /* socket file descriptor */
  struct sockaddr_in sin;      /* socket name (ip addr, port, family ) */
  char               count;    /* number of pings requested */
  char               sent;     /* pings sent */
  char               received; /* pings received */
  char               active;   /* ping active flag */
  struct Client*     client;   /* who requested the pings */
  time_t             lastsent; /* when last ping was sent */
  int                ms_min;   /* minimum time in milliseconds */
  int                ms_ave;   /* average time in milliseconds */
  int                ms_max;   /* maximum time in milliseconds */
  int                index;    /* index into poll array */
  struct Socket      socket;   /* socket structure */
  struct Timer       sender;   /* timer telling when next to send a ping */
  struct Timer       killer;   /* timer to kill us */
  unsigned int       freeable; /* zero when structure can be free()'d */
  char               name[HOSTLEN + 1]; /* server name to poing */
  char               buf[BUFSIZE];      /* buffer to hold ping times */
};

#define UPING_PENDING_SOCKET	0x01 /* pending socket destruction event */
#define UPING_PENDING_SENDER	0x02 /* pending sender destruction event */
#define UPING_PENDING_KILLER	0x04 /* pending killer destruction event */

extern int UPingFileDescriptor;

extern int  uping_init(void);
extern void uping_send(struct UPing* pptr);
extern void uping_read(struct UPing* pptr);
extern void uping_end(struct UPing* pptr);
extern void uping_cancel(struct Client *sptr, struct Client *acptr);
extern void uping_echo(void);
extern struct UPing* uping_begin(void);
extern int uping_server(struct Client* sptr, struct ConfItem* aconf, int port, int count);


#endif /* INCLUDED_uping_h */
