#ifndef INCLUDED_gline_h
#define INCLUDED_gline_h
/*
 * IRC - Internet Relay Chat, include/gline.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
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

#include <netinet/in.h>

struct Client;
struct StatDesc;

#define GLINE_MAX_EXPIRE 604800	/* max expire: 7 days */

struct Gline {
  struct Gline *gl_next;
  struct Gline**gl_prev_p;
  char	       *gl_user;
  char	       *gl_host;
  char	       *gl_reason;
  time_t	gl_expire;
  time_t	gl_lastmod;
  struct in_addr ipnum;  /* We store the IP in binary for ip glines */
  char 		bits;
  unsigned int	gl_flags;
};

#define GLINE_ACTIVE	0x0001
#define GLINE_IPMASK	0x0002
#define GLINE_BADCHAN	0x0004
#define GLINE_LOCAL	0x0008
#define GLINE_ANY	0x0010
#define GLINE_FORCE	0x0020
#define GLINE_EXACT	0x0040
#define GLINE_LDEACT	0x0080	/* locally deactivated */
#define GLINE_GLOBAL	0x0100	/* find only global glines */
#define GLINE_LASTMOD	0x0200	/* find only glines with non-zero lastmod */
#define GLINE_OPERFORCE	0x0400	/* oper forcing gline to be set */
#define GLINE_REALNAME	0x0800	/* gline matches only the realname field */

#define GLINE_MASK	(GLINE_ACTIVE | GLINE_BADCHAN | GLINE_LOCAL | GLINE_REALNAME )
#define GLINE_ACTMASK	(GLINE_ACTIVE | GLINE_LDEACT)

#define GlineIsActive(g)	(((g)->gl_flags & GLINE_ACTMASK) == \
				 GLINE_ACTIVE)
#define GlineIsRemActive(g)	((g)->gl_flags & GLINE_ACTIVE)
#define GlineIsIpMask(g)	((g)->gl_flags & GLINE_IPMASK)
#define GlineIsRealName(g)	((g)->gl_flags & GLINE_REALNAME)
#define GlineIsBadChan(g)	((g)->gl_flags & GLINE_BADCHAN)
#define GlineIsLocal(g)		((g)->gl_flags & GLINE_LOCAL)

#define GlineUser(g)		((g)->gl_user)
#define GlineHost(g)		((g)->gl_host)
#define GlineReason(g)		((g)->gl_reason)
#define GlineLastMod(g)		((g)->gl_lastmod)

extern int gline_propagate(struct Client *cptr, struct Client *sptr,
			   struct Gline *gline);
extern int gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
		     char *reason, time_t expire, time_t lastmod,
		     unsigned int flags);
extern int gline_activate(struct Client *cptr, struct Client *sptr,
			  struct Gline *gline, time_t lastmod,
			  unsigned int flags);
extern int gline_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Gline *gline, time_t lastmod,
			    unsigned int flags);
extern struct Gline *gline_find(char *userhost, unsigned int flags);
extern struct Gline *gline_lookup(struct Client *cptr, unsigned int flags);
extern void gline_free(struct Gline *gline);
extern void gline_burst(struct Client *cptr);
extern int gline_resend(struct Client *cptr, struct Gline *gline);
extern int gline_list(struct Client *sptr, char *userhost);
extern void gline_stats(struct Client *sptr, struct StatDesc *sd, int stat,
			char *param);
extern int gline_memory_count(size_t *gl_size);

#endif /* INCLUDED_gline_h */
