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

struct Client;

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
  time_t             timeout;  /* current ping timeout time */
  int                ms_min;   /* minimum time in milliseconds */
  int                ms_ave;   /* average time in milliseconds */
  int                ms_max;   /* maximum time in milliseconds */
  int                index;    /* index into poll array */
  char               name[HOSTLEN + 1]; /* server name to poing */
  char               buf[BUFSIZE];      /* buffer to hold ping times */
};


/*=============================================================================
 * Proto types
 */

extern int  setup_ping(void);
extern void polludp(int fd);
extern void send_ping(struct UPing* pptr);
extern void read_ping(struct UPing* pptr);
extern int  m_uping(struct Client *cptr, struct Client *sptr, int parc, char* parv[]);
extern void end_ping(struct UPing* pptr);
extern void cancel_ping(struct Client *sptr, struct Client *acptr);
extern struct UPing* pings_begin(void);

#ifdef DEBUG
extern void uping_mark_blocks(void);
#endif

#endif /* INCLUDED_uping_h */
