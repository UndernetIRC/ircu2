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

struct Client;

extern const char *statsinfo[];
extern void report_stats(struct Client *sptr, char stat);
extern void report_configured_links(struct Client *sptr, int mask);
extern int hunt_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[], char stat, int MustBeOper);

extern void report_crule_list(struct Client* to, int mask);
extern void report_motd_list(struct Client* to);
extern void report_deny_list(struct Client* to);

#endif /* INCLUDED_s_stats_h */
