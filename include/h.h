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
 */

#ifndef H_H
#define H_H

/* Typedefs */

typedef struct Client aClient;
typedef struct Server aServer;
typedef struct User anUser;
typedef struct Channel aChannel;
typedef struct SMode Mode;
typedef struct ConfItem aConfItem;
typedef struct Message aMessage;
typedef struct MessageTree aMessageTree;
typedef struct Gline aGline;
typedef struct ListingArgs aListingArgs;
typedef struct MotdItem aMotdItem;
typedef struct trecord atrecord;
typedef unsigned int snomask_t;
typedef struct ConfClass aConfClass;
typedef struct hashentry aHashEntry;
typedef struct SLink Link;
typedef struct DSlink Dlink;
typedef struct Whowas aWhowas;

#include "s_debug.h"

#endif /* H_H */
