/*
 * IRC - Internet Relay Chat, include/hash.h 
 * Copyright (C) 1998 by Andrea "Nemesi" Cocito
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

#ifndef INCLUDED_hash_h
#define INCLUDED_hash_h

struct Client;
struct Channel;

/*
 * general defines
 */

/* Now client and channel hash table must be of the same size */
#define HASHSIZE                32000

/*
 * Structures
 */

/*
 * Macros for internal use
 */

/*
 * Externally visible pseudofunctions (macro interface to internal functions)
 */

/* Raw calls, expect a core if you pass a NULL or zero-length name */
#define SeekChannel(name)       hSeekChannel((name))
#define SeekClient(name)        hSeekClient((name), ~0)
#define SeekUser(name)          hSeekClient((name), (STAT_USER))
#define SeekServer(name)        hSeekClient((name), (STAT_ME | STAT_SERVER))

/* Safer macros with sanity check on name, WARNING: these are _macros_,
   no side effects allowed on <name> ! */
#define FindChannel(name)       (BadPtr((name)) ? 0 : SeekChannel(name))
#define FindClient(name)        (BadPtr((name)) ? 0 : SeekClient(name))
#define FindUser(name)          (BadPtr((name)) ? 0 : SeekUser(name))
#define FindServer(name)        (BadPtr((name)) ? 0 : SeekServer(name))

/*
 * Proto types
 */

extern void init_hash(void);    /* Call me on startup */
extern int hAddClient(struct Client *cptr);
extern int hAddChannel(struct Channel *chptr);
extern int hRemClient(struct Client *cptr);
extern int hChangeClient(struct Client *cptr, const char *newname);
extern int hRemChannel(struct Channel *chptr);
extern struct Client *hSeekClient(const char *name, int TMask);
extern struct Channel *hSeekChannel(const char *name);

extern int m_hash(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);

extern int isNickJuped(const char *nick);
extern int addNickJupes(const char *nicks);
extern void clearNickJupes(void);

#endif /* INCLUDED_hash_h */
