/*
 * IRC - Internet Relay Chat, include/s_stats.h
 * Copyright (C) 2000 Joseph Bongaarts
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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

#ifndef INCLUDED_s_stats_h
#define INCLUDED_s_stats_h
#ifndef INCLUDED_features_h
#include "ircd_features.h"
#endif

struct Client;

struct StatDesc;

/* Source of /stats, stats descriptor, stats char, extra param (might be 0) */
typedef void (*StatFunc)(struct Client *, struct StatDesc *, int, char *);

struct StatDesc {
  char		sd_c;		/* stats character */
  unsigned int	sd_flags;	/* flags to control the stats */
  enum Feature	sd_control;	/* feature controlling stats */
  StatFunc	sd_func;	/* function to dispatch to */
  int		sd_funcdata;	/* extra data for the function */
  char	       *sd_desc;	/* descriptive text */
};

#define STAT_FLAG_OPERONLY	0x01	/* Oper-only stat */
#define STAT_FLAG_OPERFEAT	0x02	/* Oper-only if the feature is true */
#define STAT_FLAG_CASESENS	0x04	/* Flag is case-sensitive */
#define STAT_FLAG_VARPARAM	0x08	/* may have an extra parameter */

extern struct StatDesc statsinfo[];
extern struct StatDesc *statsmap[];

extern void stats_init(void);

#endif /* INCLUDED_s_stats_h */
