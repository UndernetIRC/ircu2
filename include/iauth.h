/* - Internet Relay Chat, include/iauth.h
 *   Copyright (C) 2001 Perry Lorier <Isomer@coders.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 * $Id$
 */
#ifndef INCLUDED_iauth_h
#define INCLUDED_iauth_h

struct Iauth {
  struct Iauth*    next;               /* list node pointer */
  int              fd;                 /* file descriptor */
  char*		   service;	       /* service name */
  int              ref_count;          /* number of connection references */
  unsigned char    active;             /* current state of iauth */
};

extern struct Iauth* IauthPollList; /* GLOBAL - iauth list */


#endif /* INCLUDED_iauth_h */

