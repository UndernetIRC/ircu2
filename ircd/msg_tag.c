/*
 * IRC - Internet Relay Chat, ircd/msg_tag.c
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

#include "msg_tag.h"
#include "client.h"
#include "struct.h"
#include "ircd_alloc.h"
#include "ircd_features.h"

/** Build a tag list with a batch tag.
 * @param[in] batch_id Batch ID to add (can be NULL).
 * @return Head of tag list, or NULL if batch_id is NULL.
 */
struct MsgTag *msg_tag_build_batch(const char *batch_id)
{
  if (!batch_id)
    return NULL;

  struct MsgTag *tag = MyMalloc(sizeof(struct MsgTag));
  tag->next = NULL;
  tag->key = "batch";
  tag->value = batch_id;
  return tag;
}

/** Add a tag to an existing tag list.
 * @param[in,out] head Head of tag list (may be NULL).
 * @param[in] key Tag key (must not be NULL).
 * @param[in] value Tag value (can be NULL for tags without values).
 * @return New head of tag list.
 */
struct MsgTag *msg_tag_add(struct MsgTag *head, const char *key, const char *value)
{
  if (!key)
    return head;

  struct MsgTag *tag = MyMalloc(sizeof(struct MsgTag));
  tag->next = head;
  tag->key = key;
  tag->value = value;
  return tag;
}

/** Add an account tag to an existing tag list if the client has an account.
 * @param[in,out] head Head of tag list (may be NULL).
 * @param[in] from Client to get account from (can be NULL).
 * @return New head of tag list (unchanged if no account).
 */
struct MsgTag *msg_tag_add_account(struct MsgTag *head, struct Client *from)
{
  if (!from || !IsUser(from) || !cli_user(from) || !IsAccount(from))
    return head;

  return msg_tag_add(head, "account", cli_user(from)->account);
}

/** Build a tag list from a client (for account tag) and batch ID.
 * This is a convenience function that combines account and batch tags.
 * @param[in] from Client to get account from (can be NULL).
 * @param[in] batch_id Batch ID to add (can be NULL).
 * @return Head of tag list, or NULL if no tags needed.
 */
struct MsgTag *msg_tag_build(struct Client *from, const char *batch_id)
{
  struct MsgTag *head = NULL;

  if (batch_id) {
    head = msg_tag_build_batch(batch_id);
  }

  if (from) {
    head = msg_tag_add_account(head, from);
  }

  return head;
}

/** Free a tag list.
 * @param[in] head Head of tag list to free.
 */
void msg_tag_free(struct MsgTag *head)
{
  while (head) {
    struct MsgTag *next = head->next;
    MyFree(head);
    head = next;
  }
}

