#ifndef INCLUDED_map_h
#define INCLUDED_map_h
/*
 * IRC - Internet Relay Chat, include/map.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2002 Joseph Bongaarts <foxxe@wtfs.net>
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
#ifndef INCLUDED_time_h
#include <time.h>		/* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifdef HEAD_IN_SAND_MAP

struct Map {
  time_t lasttime;
  unsigned int maxclients;
  char name[HOSTLEN+1];
  struct Map *next;
  struct Map *prev;
};

extern void map_update(struct Client *server);
extern void map_dump_head_in_sand(struct Client *cptr);

#endif /* HEAD_IN_SAND_MAP */

extern void map_dump(struct Client *cptr, struct Client *server, char *mask, int prompt_length);

#endif /* INCLUDED_motd_h */

