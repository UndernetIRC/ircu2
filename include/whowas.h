/*
 * IRC - Internet Relay Chat, include/whowas.h
 * Copyright (C) 1990 Markku Savela
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
#ifndef INCLUDED_whowas_h
#define INCLUDED_whowas_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t */
#define INCLUDED_sys_types_h
#endif

struct Client;

/*
 * General defines
 */

#define BITS_PER_COL            3
#define BITS_PER_COL_MASK       0x7
#define WW_MAX_INITIAL          16

#define MAX_SUB (1 << BITS_PER_COL)
#define WW_MAX_INITIAL_MASK (WW_MAX_INITIAL - 1)
#define WW_MAX (WW_MAX_INITIAL * MAX_SUB)

/*
 * Structures
 */

struct Whowas {
  unsigned int hashv;
  char *name;
  char *username;
  char *hostname;
  char *realhost;
  char *servername;
  char *realname;
  char *away;
  time_t logoff;
  struct Client *online;        /* Needed for get_history() (nick chasing) */
  struct Whowas *hnext;         /* Next entry with the same hash value */
  struct Whowas **hprevnextp;   /* Pointer to previous next pointer */
  struct Whowas *cnext;         /* Next entry with the same 'online' pointer */
  struct Whowas **cprevnextp;   /* Pointer to previous next pointer */
  struct Whowas *wnext;		/* Next entry in whowas linked list */
  struct Whowas *wprev;		/* Pointer to previous next pointer */
};

/*
 * Proto types
 */
extern struct Whowas* whowashash[];

extern unsigned int hash_whowas_name(const char *name);

extern struct Client *get_history(const char *nick, time_t timelimit);
extern void add_history(struct Client *cptr, int still_on);
extern void off_history(const struct Client *cptr);
extern void initwhowas(void);
extern void count_whowas_memory(int *wwu, size_t *wwm, int *wwa, size_t *wwam);

extern void whowas_realloc(void);

#endif /* INCLUDED_whowas_h */
