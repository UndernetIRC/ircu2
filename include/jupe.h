#ifndef INCLUDED_jupe_h
#define INCLUDED_jupe_h
/*
 * IRC - Internet Relay Chat, include/jupe.h
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
 * @brief  Interface and declarations for juped server handling.
 * @version $Id$
 */
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif


struct Client;

#define JUPE_MAX_EXPIRE	604800	/**< Maximum jupe expiration time (7 days). */

/** Describes a juped server.
 * A hub will not accept new connections from a juped server.
 */
struct Jupe {
  struct Jupe*   ju_next;    /**< Pointer to next Jupe. */
  struct Jupe**  ju_prev_p;  /**< Pointer to previous next pointer. */
  char*          ju_server;  /**< Name of server to jupe. */
  char*          ju_reason;  /**< Reason for the jupe. */
  time_t         ju_expire;  /**< Expiration time of the jupe. */
  time_t         ju_lastmod; /**< Last modification time (if any) for the jupe. */
  unsigned int   ju_flags;   /**< Status flags for the jupe. */
};

#define JUPE_ACTIVE	0x0001  /**< Jupe is globally active. */
#define JUPE_LOCAL	0x0002  /**< Jupe only applies to this server. */
#define JUPE_LDEACT	0x0004	/**< Jupe is locally deactivated */

#define JUPE_MASK	(JUPE_ACTIVE | JUPE_LOCAL)
#define JUPE_ACTMASK	(JUPE_ACTIVE | JUPE_LDEACT)

/** Test whether \a j is active. */
#define JupeIsActive(j)		(((j)->ju_flags & JUPE_ACTMASK) == JUPE_ACTIVE)
/** Test whether \a j is globally (remotely) active. */
#define JupeIsRemActive(j)	((j)->ju_flags & JUPE_ACTIVE)
/** Test whether \a j is local. */
#define JupeIsLocal(j)		((j)->ju_flags & JUPE_LOCAL)

/** Get the server name for \a j. */
#define JupeServer(j)		((j)->ju_server)
/** Get the reason fro \a j. */
#define JupeReason(j)		((j)->ju_reason)
/** Get the last modification time for \a j. */
#define JupeLastMod(j)		((j)->ju_lastmod)

extern int jupe_add(struct Client *cptr, struct Client *sptr, char *server,
		    char *reason, time_t expire, time_t lastmod,
		    unsigned int flags);
extern int jupe_activate(struct Client *cptr, struct Client *sptr,
			 struct Jupe *jupe, time_t lastmod,
			 unsigned int flags);
extern int jupe_deactivate(struct Client *cptr, struct Client *sptr,
			   struct Jupe *jupe, time_t lastmod,
			   unsigned int flags);
extern struct Jupe* jupe_find(char *server);
extern void jupe_free(struct Jupe *jupe);
extern void jupe_burst(struct Client *cptr);
extern int jupe_resend(struct Client *cptr, struct Jupe *jupe);
extern int jupe_list(struct Client *sptr, char *server);
extern int jupe_memory_count(size_t *ju_size);

#endif /* INCLUDED_jupe_h */
