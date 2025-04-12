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
 */
/** @file
 * @brief Structures and APIs for G-line manipulation.
 * @version $Id$
 */
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_res_h
#include "res.h"
#endif

struct Client;
struct StatDesc;

#define GLINE_MAX_EXPIRE 604800	/**< max expire: 7 days */

/** Local state of a G-line. */
enum GlineLocalState {
  GLOCAL_GLOBAL,		/**< G-line state unmodified locally. */
  GLOCAL_ACTIVATED,		/**< G-line state locally activated. */
  GLOCAL_DEACTIVATED		/**< G-line state locally deactivated. */
};

/** Description of a G-line. */
struct Gline {
  struct Gline *gl_next;	/**< Next G-line in linked list. */
  struct Gline**gl_prev_p;	/**< Previous pointer to this G-line. */
  char	       *gl_user;	/**< Username mask (or channel/realname mask). */
  char	       *gl_host;	/**< Host portion of mask. */
  char	       *gl_reason;	/**< Reason for G-line. */
  time_t	gl_expire;	/**< Expiration timestamp. */
  time_t	gl_lastmod;	/**< Last modification timestamp. */
  time_t	gl_lifetime;	/**< Record expiration timestamp. */
  struct irc_in_addr gl_addr;	/**< IP address (for IP-based G-lines). */
  unsigned char gl_bits;	/**< Bits in gl_addr used in the mask. */
  unsigned int	gl_flags;	/**< G-line status flags. */
  enum GlineLocalState gl_state;/**< G-line local state. */
};

/** Action to perform on a G-line. */
enum GlineAction {
  GLINE_ACTIVATE,		/**< G-line should be activated. */
  GLINE_DEACTIVATE,		/**< G-line should be deactivated. */
  GLINE_LOCAL_ACTIVATE,		/**< G-line should be locally activated. */
  GLINE_LOCAL_DEACTIVATE,	/**< G-line should be locally deactivated. */
  GLINE_MODIFY			/**< G-line should be modified. */
};

#define GLINE_ACTIVE	0x0001  /**< G-line is active. */
#define GLINE_IPMASK	0x0002  /**< gl_addr and gl_bits fields are valid. */
#define GLINE_BADCHAN	0x0004  /**< G-line prohibits users from joining a channel. */
#define GLINE_LOCAL	0x0008  /**< G-line only applies to this server. */
#define GLINE_ANY	0x0010  /**< Search flag: Find any G-line. */
#define GLINE_FORCE	0x0020  /**< Override normal limits on G-lines. */
#define GLINE_EXACT	0x0040  /**< Exact match only (no wildcards). */
#define GLINE_LDEACT	0x0080	/**< Locally deactivated. */
#define GLINE_GLOBAL	0x0100	/**< Find only global G-lines. */
#define GLINE_LASTMOD	0x0200	/**< Find only G-lines with non-zero lastmod. */
#define GLINE_OPERFORCE	0x0400	/**< Oper forcing G-line to be set. */
#define GLINE_REALNAME  0x0800  /**< G-line matches only the realname field. */

#define GLINE_EXPIRE	0x1000	/**< Expiration time update */
#define GLINE_LIFETIME	0x2000	/**< Record lifetime update */
#define GLINE_REASON	0x4000	/**< Reason update */

/** Controllable flags that can be set on an actual G-line. */
#define GLINE_MASK	(GLINE_ACTIVE | GLINE_BADCHAN | GLINE_LOCAL | GLINE_REALNAME)
/** Mask for G-line activity flags. */
#define GLINE_ACTMASK	(GLINE_ACTIVE | GLINE_LDEACT)

/** Mask for G-line update flags. */
#define GLINE_UPDATE	(GLINE_EXPIRE | GLINE_LIFETIME | GLINE_REASON)

/** Test whether \a g is active. */
#define GlineIsActive(g)	((((g)->gl_flags & GLINE_ACTIVE) &&	  \
				  (g)->gl_state != GLOCAL_DEACTIVATED) || \
				 (g)->gl_state == GLOCAL_ACTIVATED)
/** Test whether \a g is remotely (globally) active. */
#define GlineIsRemActive(g)	((g)->gl_flags & GLINE_ACTIVE)
/** Test whether \a g is an IP-based G-line. */
#define GlineIsIpMask(g)	((g)->gl_flags & GLINE_IPMASK)
/** Test whether \a g is a realname-based G-line. */
#define GlineIsRealName(g)      ((g)->gl_flags & GLINE_REALNAME)
/** Test whether \a g is a BADCHAN. */
#define GlineIsBadChan(g)	((g)->gl_flags & GLINE_BADCHAN)
/** Test whether \a g is local to this server. */
#define GlineIsLocal(g)		((g)->gl_flags & GLINE_LOCAL)

/** Return user mask of a G-line. */
#define GlineUser(g)		((g)->gl_user)
/** Return host mask of a G-line. */
#define GlineHost(g)		((g)->gl_host)
/** Return reason/message of a G-line. */
#define GlineReason(g)		((g)->gl_reason)
/** Return last modification time of a G-line. */
#define GlineLastMod(g)		((g)->gl_lastmod)

extern int gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
		     char *reason, time_t expire, time_t lastmod,
		     time_t lifetime, unsigned int flags);
extern int gline_activate(struct Client *cptr, struct Client *sptr,
			  struct Gline *gline, time_t lastmod,
			  unsigned int flags);
extern int gline_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Gline *gline, time_t lastmod,
			    unsigned int flags);
extern int gline_modify(struct Client *cptr, struct Client *sptr,
			struct Gline *gline, enum GlineAction action,
			char *reason, time_t expire, time_t lastmod,
			time_t lifetime, unsigned int flags);
extern int gline_destroy(struct Client *cptr, struct Client *sptr,
			 struct Gline *gline);
extern struct Gline *gline_find(char *userhost, unsigned int flags);
extern struct Gline *gline_lookup(struct Client *cptr, unsigned int flags);
extern void gline_free(struct Gline *gline);
extern void gline_burst(struct Client *cptr);
extern int gline_resend(struct Client *cptr, struct Gline *gline);
extern int gline_list(struct Client *sptr, char *userhost);
extern void gline_stats(struct Client *sptr, const struct StatDesc *sd,
                        char *param);
extern int gline_memory_count(size_t *gl_size);

#endif /* INCLUDED_gline_h */
