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
 *
 * $Id$
 */
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif


struct Client;

#define JUPE_MAX_EXPIRE	604800	/* max expire: 7 days */

struct Jupe {
  struct Jupe*   ju_next;
  struct Jupe**  ju_prev_p;
  char*          ju_server;
  char*          ju_reason;
  time_t         ju_expire;
  time_t         ju_lastmod;
  unsigned int   ju_flags;
};

#define JUPE_ACTIVE	0x0001
#define JUPE_LOCAL	0x0002
#define JUPE_LDEACT	0x0004	/* locally deactivated */

#define JUPE_MASK	(JUPE_ACTIVE | JUPE_LOCAL)
#define JUPE_ACTMASK	(JUPE_ACTIVE | JUPE_LDEACT)

#define JupeIsActive(j)		(((j)->ju_flags & JUPE_ACTMASK) == JUPE_ACTIVE)
#define JupeIsRemActive(j)	((j)->ju_flags & JUPE_ACTIVE)
#define JupeIsLocal(j)		((j)->ju_flags & JUPE_LOCAL)

#define JupeServer(j)		((j)->ju_server)
#define JupeReason(j)		((j)->ju_reason)
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
