/*
 * Userload module by Michael L. VanLoon (mlv) <michaelv@iastate.edu>
 * Written 2/93.  Originally grafted into irc2.7.2g 4/93.
 * Rewritten 9/97 by Carlo Wood for ircu2.10.01.
 *
 * IRC - Internet Relay Chat, ircd/userload.h
 * Copyright (C) 1990 University of Oulu, Computing Center
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
 */
/** @file
 * @brief Userload tracking and statistics.
 * @version $Id$
 */
#ifndef INCLUDED_userload_h
#define INCLUDED_userload_h

struct Client;
struct StatDesc;

/*
 * Structures
 */

/** Tracks load of various types of users. */
struct current_load_st {
  unsigned int client_count; /**< Count of locally connected clients. */
  unsigned int local_count; /**< This field is updated but apparently meaningless. */
  unsigned int conn_count; /**< Locally connected clients plus servers. */
};

/*
 * Proto types
 */

extern void update_load(void);
extern void calc_load(struct Client *sptr, const struct StatDesc *sd,
                      char *param);
extern void initload(void);

extern struct current_load_st current_load;

#endif /* INCLUDED_userload_h */
