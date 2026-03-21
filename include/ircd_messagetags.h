#ifndef INCLUDED_IRCD_MESSAGETAGS_H
#define INCLUDED_IRCD_MESSAGETAGS_H
/*
 * IRC - Internet Relay Chat, include/ircd_messagetags.h
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
 */
/** @file
 * @brief Shared helpers for IRCv3 message-tags handling.
 * @version $Id$
 */

struct Client;

extern int ircd_parse_message_tags(struct Client* sptr, int parc, char* parv[],
                                   char** tags, char** target, int* target_index,
                                   int require_tags, int filter_local_sender);
extern int ircd_sanitize_message_tags(char** tags,
                                      int enforce_client_data_limit,
                                      int filter_relayable_client_tags,
                                      int drop_on_invalid,
                                      int* too_long);

#endif /* INCLUDED_IRCD_MESSAGETAGS_H */