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
 */
/** @file
 * @brief Globally visible declarations to manipulate whowas information.
 * @version $Id$
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

#define BITS_PER_COL            3   /**< Magic number used by whowas hash function. */
#define BITS_PER_COL_MASK       0x7 /**< Mask with #BITS_PER_COL least significant bits set. */
#define WW_MAX_INITIAL          16  /**< Magic number used by whowas hash function. */

#define MAX_SUB (1 << BITS_PER_COL) /**< Magic number used by whowas hash function. */
#define WW_MAX_INITIAL_MASK (WW_MAX_INITIAL - 1) /**< Magic number used by whowas hash function. */
#define WW_MAX (WW_MAX_INITIAL * MAX_SUB) /**< Size of whowas hash table. */

/*
 * Structures
 */

/** Tracks previously used nicknames. */
struct Whowas {
  unsigned int hashv;           /**< Hash value for nickname. */
  char *name;                   /**< Client's old nickname. */
  char *username;               /**< Client's username. */
  char *hostname;               /**< Client's hostname. */
  char *realhost;               /**< Client's real hostname. */
  char *servername;             /**< Name of client's server. */
  char *realname;               /**< Client's realname (user info). */
  char *away;                   /**< Client's away message. */
  time_t logoff;                /**< When the client logged off. */
  struct Client *online;        /**< Needed for get_history() (nick chasing). */
  struct Whowas *hnext;         /**< Next entry with the same hash value. */
  struct Whowas **hprevnextp;   /**< Pointer to previous next pointer. */
  struct Whowas *cnext;         /**< Next entry with the same 'online' pointer. */
  struct Whowas **cprevnextp;   /**< Pointer to previous next pointer. */
  struct Whowas *wnext;		/**< Next entry in whowas linked list. */
  struct Whowas *wprev;		/**< Pointer to previous next pointer. */
};

/*
 * Proto types
 */
extern struct Whowas* whowashash[];

extern unsigned int hash_whowas_name(const char *name);

extern struct Client *get_history(const char *nick);
extern void add_history(struct Client *cptr, int still_on);
extern void off_history(const struct Client *cptr);
extern void initwhowas(void);
extern void count_whowas_memory(int *wwu, size_t *wwm, int *wwa, size_t *wwam);

extern void whowas_realloc(void);

#endif /* INCLUDED_whowas_h */
