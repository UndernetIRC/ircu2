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

/*
 * safety margin so we can always have one spare fd, for motd/authd or
 * whatever else.  -24 allows "safety" margin of 10 listen ports, 8 servers
 * and space reserved for logfiles, DNS sockets and identd sockets etc.
 */
#define MAXCLIENTS      (MAXCONNECTIONS-24)

#define IRCD_MAX(a, b)  ((a) > (b) ? (a) : (b))
#define IRCD_MIN(a, b)  ((a) < (b) ? (a) : (b))

#endif /* INCLUDED_sys_h */
