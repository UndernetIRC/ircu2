/*
 * IRC - Internet Relay Chat, include/ircd_policy.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
#ifndef INCLUDED_ircd_policy_h
#define INCLUDED_ircd_policy_h

/* This file contains undernet admin policy decisions, even if they are
 * braindead and silly.  These aren't configurable as they are network
 * policy, and should not be changed (depending on what network your 
 * on different ones of these should be defined
 */

/* CFV-165 - Hiding Nonessential information from non-opers
 *
 * 1) Removal of server notices from users
 *
 * This is implemented as disallowing users from setting +s
 */
#define HEAD_IN_SAND_SNOTICES
#define SERVNOTICE_OPER_ONLY

/* CFV-165 - Hiding Nonessential information from non-opers
 * 
 * 2) Removal of server wallops from users
 *
 * This is implemented by making all server wallops DESYNC's, and removing
 * +g from normal users.
 */
#define HEAD_IN_SAND_DESYNCS
#define DEBUG_OPER_ONLY

/* CFV-165 - Hiding Nonessential information from non-opers
 * 
 * 3) Removal of operator wallops from users
 *
 * This is implemented as disallowing users from setting +w
 */
#define HEAD_IN_SAND_WALLOPS
/* #define WALLOPS_OPER_ONLY */

/* CFV-165 - Hiding Nonessential information from non-opers
 *
 * 5) Removal of /MAP from users.
 *
 */
#define HEAD_IN_SAND_MAP

/* CFV-165 - Hiding Nonessential information from non-opers
 * 
 * 6) Removal of links from users
 */
#define HEAD_IN_SAND_LINKS

/* CFV-165 - Hiding Nonessential information from non-opers
 *
 * 7) Restrict the output of LINKS to only display known leaves.
 */

/* CFV-165 - Hiding Nonessential information from non-opers
 *
 * 8) Removal of /TRACE from users.
 */
#define HEAD_IN_SAND_TRACE

/* CFV-165 - Hiding Nonessential information from non-opers
 *
 * 9-13) Removal of various stats from non users
 */
#define HEAD_IN_SAND_STATS_L
#define HEAD_IN_SAND_STATS_C
#define HEAD_IN_SAND_STATS_G
#define HEAD_IN_SAND_STATS_H
#define HEAD_IN_SAND_STATS_K
#define HEAD_IN_SAND_STATS_F
#define HEAD_IN_SAND_STATS_I
#define HEAD_IN_SAND_STATS_M
#define HEAD_IN_SAND_STATS_m
#define HEAD_IN_SAND_STATS_O
#undef  HEAD_IN_SAND_STATS_P
#define HEAD_IN_SAND_STATS_R
#define HEAD_IN_SAND_STATS_D
#define HEAD_IN_SAND_STATS_d
#define HEAD_IN_SAND_STATS_t
#define HEAD_IN_SAND_STATS_T
#define HEAD_IN_SAND_STATS_U
#define HEAD_IN_SAND_STATS_u
#define HEAD_IN_SAND_STATS_W
#define HEAD_IN_SAND_STATS_X
#define HEAD_IN_SAND_STATS_Y
#define HEAD_IN_SAND_STATS_Z

/* CFV-165 - Hiding Nonessential information from non-opers
 *
 * 14) Removal of server names in net break sign-offs.
 */

#define HEAD_IN_SAND_NETSPLIT

/* CFV-165 - Hiding Nonessential information from non-opers
 * 
 * 15) Removal of server names in replies to /WHOIS
 */

#define HEAD_IN_SAND_WHOIS_SERVERNAME

#endif /* INCLUDED_ircd_policy_h */
