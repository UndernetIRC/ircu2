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
 */

#ifndef HASH_H
#define HASH_H

#include "s_serv.h"		/* For STAT_* values and StatusMask() macro */

/*=============================================================================
 * general defines
 */

/* Now client and channel hash table must be of the same size */
#define HASHSIZE		32000

/*=============================================================================
 * Structures
 */

/*=============================================================================
 * Macros for internal use
 */

/*=============================================================================
 * Externally visible pseudofunctions (macro interface to internal functions)
 */

/* Raw calls, expect a core if you pass a NULL or zero-length name */
#define SeekChannel(name)	hSeekChannel((name))
#define SeekClient(name)	hSeekClient((name), ~StatusMask(STAT_PING))
#define SeekUser(name)   	hSeekClient((name), StatusMask(STAT_USER))
#define SeekServer(name)	hSeekClient((name), StatusMask(STAT_ME) | \
                                                    StatusMask(STAT_SERVER) )

/* Safer macros with sanity check on name, WARNING: these are _macros_,
   no side effects allowed on <name> ! */
#define FindChannel(name)	(BadPtr((name))?NULL:SeekChannel(name))
#define FindClient(name)	(BadPtr((name))?NULL:SeekClient(name))
#define FindUser(name)		(BadPtr((name))?NULL:SeekUser(name))
#define FindServer(name)	(BadPtr((name))?NULL:SeekServer(name))

/*=============================================================================
 * Proto types
 */

extern void hash_init(void);	/* Call me on startup */
extern int hAddClient(aClient *cptr);
extern int hAddChannel(aChannel *chptr);
extern int hRemClient(aClient *cptr);
extern int hChangeClient(aClient *cptr, char *newname);
extern int hRemChannel(aChannel *chptr);
extern aClient *hSeekClient(char *name, int TMask);
extern aChannel *hSeekChannel(char *name);

extern int m_hash(aClient *cptr, aClient *sptr, int parc, char *parv[]);

extern int isNickJuped(char *nick);
extern int addNickJupes(char *nicks);
extern void clearNickJupes(void);

#endif /* HASH_H */
