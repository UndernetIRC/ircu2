/*
 * IRC - Internet Relay Chat, include/sys.h
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
 *
 * $Id$
 */
#ifndef INCLUDED_sys_h
#define INCLUDED_sys_h

#if WORDS_BIGENDIAN
# define BIT_ZERO_ON_LEFT
#else
# define BIT_ZERO_ON_RIGHT
#endif

#define HAVE_RELIABLE_SIGNALS

/*
 * safety margin so we can always have one spare fd, for motd/authd or
 * whatever else.  -24 allows "safety" margin of 10 listen ports, 8 servers
 * and space reserved for logfiles, DNS sockets and identd sockets etc.
 */
#define MAXCLIENTS      (MAXCONNECTIONS-24)

#ifdef HAVECURSES
#define DOCURSES
#else
#undef DOCURSES
#endif

#ifdef HAVETERMCAP
#define DOTERMCAP
#else
#undef DOTERMCAP
#endif

#ifndef CONFIG_SETUGID
#undef IRC_UID
#undef IRC_GID
#endif

/* Define FD_SETSIZE to what we want before including sys/types.h on BSD */
#if  defined(__FreeBSD__) || defined(__NetBSD__) || defined(__bsdi__)
#if ((!defined(USE_POLL)) && (!defined(FD_SETSIZE)))
#define FD_SETSIZE ((MAXCONNECTIONS)+4)
#endif
#endif

#define LIMIT_FMT "%d"

#define IRCD_MAX(a, b)  ((a) > (b) ? (a) : (b))
#define IRCD_MIN(a, b)  ((a) < (b) ? (a) : (b))

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif

#endif /* INCLUDED_sys_h */
