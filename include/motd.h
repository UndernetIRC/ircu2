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
 */
/** @file
 * @brief Message-of-the-day manipulation interface and declarations.
 * @version $Id$
 */

#ifndef INCLUDED_time_h
#include <time.h>		/* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_res_H
#include "res.h"
#endif

struct Client;
struct TRecord;
struct StatDesc;

/** Type of MOTD. */
enum MotdType {
    MOTD_UNIVERSAL, /**< MOTD for all users */
    MOTD_HOSTMASK,  /**< MOTD selected by hostmask */
    MOTD_IPMASK,    /**< MOTD selected by IP mask */
    MOTD_CLASS      /**< MOTD selected by connection class */
};

/** Entry for a single Message Of The Day (MOTD). */
struct Motd {
  struct Motd*		next;     /**< Next MOTD in the linked list. */
  enum MotdType		type;     /**< Type of MOTD. */
  char*			hostmask; /**< Hostmask if type==MOTD_HOSTMASK,
                                     class name if type==MOTD_CLASS,
                                     text IP mask if type==MOTD_IPMASK. */
  struct irc_in_addr    address;  /**< Address if type==MOTD_IPMASK. */
  unsigned char         addrbits; /**< Number of bits checked in Motd::address. */
  char*			path;     /**< Pathname of MOTD file. */
  int			maxcount; /**< Number of lines for MOTD. */
  struct MotdCache*	cache;    /**< MOTD cache entry. */
};

/** Length of one MOTD line(80 chars + '\\0'). */
#define MOTD_LINESIZE	81
/** Maximum number of lines for local MOTD */
#define MOTD_MAXLINES	100
/** Maximum number of lines for remote MOTD */
#define MOTD_MAXREMOTE	3

/** Cache entry for the contents of a MOTD file. */
struct MotdCache {
  struct MotdCache*	next;     /**< Next MotdCache in list. */
  struct MotdCache**	prev_p;   /**< Pointer to previous node's next pointer. */
  int			ref;      /**< Number of references to this entry. */
  char*			path;     /**< Pathname of file. */
  int			maxcount; /**< Number of lines allocated for message. */
  struct tm		modtime;  /**< Last modification time from file. */
  int			count;    /**< Actual number of lines used in message. */
  char			motd[1][MOTD_LINESIZE]; /**< Message body. */
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
void motd_report(struct Client *to, const struct StatDesc *sd,
                 char *param);
void motd_memory_count(struct Client *cptr);

#endif /* INCLUDED_motd_h */
