#ifndef INCLUDED_msg_tag_h
#define INCLUDED_msg_tag_h
/*
 * IRC - Internet Relay Chat, include/msg_tag.h
 * Copyright (C) 2024
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
 * @brief IRCv3 message tag support
 * @version $Id$
 */

struct Client;

/** A single message tag (key-value pair). */
struct MsgTag {
  struct MsgTag *next;  /**< Next tag in the list. */
  const char *key;      /**< Tag key (e.g., "batch", "account"). */
  const char *value;    /**< Tag value (e.g., batch ID, account name). */
};

/** Build a tag list with a batch tag.
 * @param[in] batch_id Batch ID to add (can be NULL).
 * @return Head of tag list, or NULL if batch_id is NULL.
 */
struct MsgTag *msg_tag_build_batch(const char *batch_id);

/** Add a tag to an existing tag list.
 * @param[in,out] head Head of tag list (may be NULL).
 * @param[in] key Tag key (must not be NULL).
 * @param[in] value Tag value (can be NULL for tags without values).
 * @return New head of tag list.
 */
struct MsgTag *msg_tag_add(struct MsgTag *head, const char *key, const char *value);

/** Add an account tag to an existing tag list if the client has an account.
 * @param[in,out] head Head of tag list (may be NULL).
 * @param[in] from Client to get account from (can be NULL).
 * @return New head of tag list (unchanged if no account).
 */
struct MsgTag *msg_tag_add_account(struct MsgTag *head, struct Client *from);

/** Build a tag list from a client (for account tag) and batch ID.
 * This is a convenience function that combines account and batch tags.
 * @param[in] from Client to get account from (can be NULL).
 * @param[in] batch_id Batch ID to add (can be NULL).
 * @return Head of tag list, or NULL if no tags needed.
 */
struct MsgTag *msg_tag_build(struct Client *from, const char *batch_id);

/** Free a tag list.
 * @param[in] head Head of tag list to free.
 */
void msg_tag_free(struct MsgTag *head);

#endif /* INCLUDED_msg_tag_h */

