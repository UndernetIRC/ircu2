/*
 * IRC - Internet Relay Chat, include/h.h
 * Copyright (C) 1996 - 1997 Carlo Wood
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
#ifndef INCLUDED_numnicks_h
#define INCLUDED_numnicks_h
#ifndef INCLUDED_client_h
#include "client.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

/*
 * General defines
 */

/*
 * used for buffer size calculations in channel.c
 */
#define NUMNICKLEN 5            /* strlen("YYXXX") */

/*
 * Macros
 */

/*
 * Use this macro as follows: sprintf(buf, "%s%s ...", NumNick(cptr), ...);
 */
#define NumNick(c) cli_yxx((cli_user(c))->server), cli_yxx(c)

/*
 * Use this macro as follows: sprintf(buf, "%s ...", NumServ(cptr), ...);
 */
#define NumServ(c) cli_yxx(c)

/*
 * Use this macro as follows: sprintf(buf, "%s%s ...", NumServCap(cptr), ...);
 */
#define NumServCap(c) cli_yxx(c), (cli_serv(c))->nn_capacity

/*
 * Structures
 */
struct Client;

/*
 * Proto types
 */
extern void SetRemoteNumNick(struct Client* cptr, const char* yxx);
extern int  SetLocalNumNick(struct Client* cptr);
extern void RemoveYXXClient(struct Client* server, const char* yxx);
extern void SetServerYXX(struct Client* cptr, 
                         struct Client* server, const char* yxx);
extern void ClearServerYXX(const struct Client* server);

extern void SetYXXCapacity(struct Client* myself, unsigned int max_clients);
extern void SetYXXServerName(struct Client* myself, unsigned int numeric);

extern int            markMatchexServer(const char* cmask, int minlen);
extern struct Client* find_match_server(char* mask);
extern struct Client* findNUser(const char* yxx);
extern struct Client* FindNServer(const char* numeric);

extern unsigned int   base64toint(const char* str);
extern const char*    inttobase64(char* buf, unsigned int v, unsigned int count);

#endif /* INCLUDED_numnicks_h */

