#ifndef INCLUDED_ircd_auth_h
#define INCLUDED_ircd_auth_h

/*
 * IRC - Internet Relay Chat, ircd/ircd_auth.h
 * Copyright 2004 Michael Poole <mdpoole@troilus.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id$
 */

#ifndef INCLUDED_config_h
#include "config.h"
#endif

struct IAuth;
extern struct IAuth *iauth_active;

struct IAuth *iauth_connect(char *host, unsigned short port, char *passwd, time_t reconnect, time_t timeout);
int iauth_start_client(struct IAuth *iauth, struct Client *cptr);
void iauth_exit_client(struct Client *cptr);

void iauth_mark_closing(void);
void iauth_close_unused(void);

#endif
