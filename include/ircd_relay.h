#ifndef INCLUDED_IRCD_RELAY_H
#define INCLUDED_IRCD_RELAY_H
/*
 * IRC - Internet Relay Chat, include/ircd_relay.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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

struct Client;

extern void relay_channel_message(struct Client* sptr, const char* name, const char* text);
extern void relay_channel_notice(struct Client* sptr, const char* name, const char* text);
extern void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text);
extern void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text);
extern void relay_masked_message(struct Client* sptr, const char* mask, const char* text);
extern void relay_masked_notice(struct Client* sptr, const char* mask, const char* text);
extern void relay_private_message(struct Client* sptr, const char* name, const char* text);
extern void relay_private_notice(struct Client* sptr, const char* name, const char* text);

extern void server_relay_channel_message(struct Client* sptr, const char* name, const char* text);
extern void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text);
extern void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text);
extern void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text);
extern void server_relay_private_message(struct Client* sptr, const char* name, const char* text);
extern void server_relay_private_notice(struct Client* sptr, const char* name, const char* text);

#endif /* INCLUDED_IRCD_RELAY_H */
