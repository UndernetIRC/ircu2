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

/*
 * gflags
 */
#define GLINE_ACTIVE    1
#define GLINE_IPMASK    2
#define GLINE_LOCAL     4

#define GlineIsActive(g)    ((g)->gflags & GLINE_ACTIVE)
#define GlineIsIpMask(g)    ((g)->gflags & GLINE_IPMASK)
#define GlineIsLocal(g)     ((g)->gflags & GLINE_LOCAL)

#define SetActive(g)        ((g)->gflags |= GLINE_ACTIVE)
#define ClearActive(g)      ((g)->gflags &= ~GLINE_ACTIVE)
#define SetGlineIsIpMask(g) ((g)->gflags |= GLINE_IPMASK)
#define SetGlineIsLocal(g)  ((g)->gflags |= GLINE_LOCAL)

struct Gline {
  struct Gline*  next;
  struct Gline*  prev;
  char*          host;
  char*          reason;
  char*          name;
  time_t         expire;
  unsigned int   gflags;
};

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

#endif /* INCLUDED_gline_h */
