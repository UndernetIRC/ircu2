#ifndef INCLUDED_motd_h
#define INCLUDED_motd_h
/*
 * IRC - Internet Relay Chat, include/motd.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif


struct Client;
struct TRecord;

/* motd_find is used to find a matching T-line if any */
struct TRecord *motd_find(struct Client* cptr);

/* motd_send sends a MOTD off to a user */
int motd_send(struct Client* cptr, struct TRecord* trec);

/* motd_signon sends a MOTD off to a newly-registered user */
void motd_signon(struct Client* cptr);

#endif /* INCLUDED_motd_h */
