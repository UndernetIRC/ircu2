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
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif


struct Client;

#define GLINE_MAX_EXPIRE 604800	/* max expire: 7 days */

struct Gline {
  struct Gline *gl_next;
  struct Gline**gl_prev_p;
  char	       *gl_user;
  char	       *gl_host;
  char	       *gl_reason;
  time_t	gl_expire;
  time_t	gl_lastmod;
  unsigned int	gl_flags;
};

#define GLINE_ACTIVE	0x0001
#define GLINE_IPMASK	0x0002
#define GLINE_BADCHAN	0x0004
#define GLINE_LOCAL	0x0008
#define GLINE_ANY	0x0010
#define GLINE_FORCE	0x0020

#define GLINE_MASK	(GLINE_ACTIVE | GLINE_BADCHAN | GLINE_LOCAL)

#define GlineIsActive(g)	((g)->gl_flags & GLINE_ACTIVE)
#define GlineIsIpMask(g)	((g)->gl_flags & GLINE_IPMASK)
#define GlineIsBadChan(g)	((g)->gl_flags & GLINE_BADCHAN)
#define GlineIsLocal(g)		((g)->gl_flags & GLINE_LOCAL)

#define GlineUser(g)		((g)->gl_user)
#define GlineHost(g)		((g)->gl_host)
#define GlineReason(g)		((g)->gl_reason)
#define GlineLastMod(g)		((g)->gl_lastmod)

extern int gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
		     char *reason, time_t expire, time_t lastmod,
		     unsigned int flags);
extern int gline_activate(struct Client *cptr, struct Client *sptr,
			  struct Gline *gline, time_t lastmod);
extern int gline_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Gline *gline, time_t lastmod);
extern struct Gline *gline_find(char *userhost, unsigned int flags);
extern struct Gline *gline_lookup(struct Client *cptr);
extern void gline_free(struct Gline *gline);
extern void gline_burst(struct Client *cptr);
extern int gline_resend(struct Client *cptr, struct Gline *gline);
extern int gline_list(struct Client *sptr, char *userhost);
extern void gline_stats(struct Client *sptr);

#if 0 /* forget it! */
#define SetActive(g)        ((g)->gl_flags |= GLINE_ACTIVE)
#define ClearActive(g)      ((g)->gl_flags &= ~GLINE_ACTIVE)
#define SetGlineIsIpMask(g) ((g)->gl_flags |= GLINE_IPMASK)
#define SetGlineIsLocal(g)  ((g)->gl_flags |= GLINE_LOCAL)

extern struct Gline* GlobalGlineList;
extern struct Gline* BadChanGlineList;

extern void gline_remove_expired(time_t now);

extern void add_gline(struct Client *sptr, int ip_mask,
                      char *host, char *comment, char *user,
                      time_t expire, int local);
extern struct Gline* make_gline(int is_ipmask, char *host, char *reason,
                                char *name, time_t expire);
extern struct Gline* find_gline(struct Client *cptr, struct Gline **pgline);
extern void free_gline(struct Gline *gline, struct Gline *prev);

#ifdef BADCHAN
extern int bad_channel(const char* name);
extern void bad_channel_remove_expired(time_t now);
#endif
#endif /* 0 */

#endif /* INCLUDED_gline_h */
