#ifndef INCLUDED_motd_h
#define INCLUDED_motd_h
/*
 * IRC - Internet Relay Chat, include/motd.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
#ifndef INCLUDED_time_h
#include <time.h>		/* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif


struct Client;
struct StatDesc;
struct TRecord;

struct Motd {
  struct Motd*		next;
  int			type;
  union {
    char*		hostmask;
    int			class;
  }			id;
  char*			path;
  int			maxcount;
  struct MotdCache*	cache;
};

#define MOTD_UNIVERSAL	0	/* MOTD selected by no criteria */
#define MOTD_HOSTMASK	1	/* MOTD selected by hostmask */
#define MOTD_CLASS	2	/* MOTD selected by connection class */

#define MOTD_LINESIZE	81	/* 80 chars + '\0' */
#define MOTD_MAXLINES	100
#define MOTD_MAXREMOTE	3

struct MotdCache {
  struct MotdCache*	next; /* these fields let us read MOTDs only once */
  struct MotdCache**	prev_p;
  int			ref;
  char*			path;
  int			maxcount;
  struct tm		modtime;
  int			count;
  char			motd[1][MOTD_LINESIZE];
};

/* motd_send sends a MOTD off to a user */
int motd_send(struct Client* cptr);

/* motd_signon sends a MOTD off to a newly-registered user */
void motd_signon(struct Client* cptr);

/* motd_recache causes all the MOTD caches to be cleared */
void motd_recache(void);

/* motd_init initializes the MOTD routines, including reading the
 * ircd.motd and remote.motd files into cache
 */
void motd_init(void);

/* This routine adds a MOTD */
void motd_add(const char *hostmask, const char *path);

/* This routine clears the list of MOTDs */
void motd_clear(void);

/* This is called to report T-lines */
void motd_report(struct Client *to, struct StatDesc *sd, int stat,
		 char *param);
void motd_memory_count(struct Client *cptr);

#endif /* INCLUDED_motd_h */
