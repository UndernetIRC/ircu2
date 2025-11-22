#ifndef INCLUDED_batch_h
#define INCLUDED_batch_h
/*
 * IRC - Internet Relay Chat, include/batch.h
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
 * @brief IRCv3 batch capability support
 * @version $Id$
 */

#ifndef INCLUDED_client_h
#include "client.h"
#endif

/* Batch types - stored as enum for efficiency */
enum BatchType {
  BATCH_TYPE_NETSPLIT = 0,
  BATCH_TYPE_NETJOIN,
  BATCH_TYPE_MAX
};

/* Generate unique batch ID */
char *batch_generate_id(void);

/* Register batch metadata (type and param) for a batch_id.
 * This must be called before sending any messages with this batch_id.
 * @param[in] batch_id Batch ID to register.
 * @param[in] type Batch type.
 * @param[in] param Batch parameter (can be NULL).
 */
void batch_register(const char *batch_id, enum BatchType type, const char *param);

/* Unregister batch metadata when batch is complete.
 * @param[in] batch_id Batch ID to unregister.
 */
void batch_unregister(const char *batch_id);

/* Get batch metadata for a batch_id (internal use by send_tags).
 * @param[in] batch_id Batch ID to look up.
 * @param[out] type Batch type (if found).
 * @param[out] param Batch parameter (if found, can be NULL).
 * @return 1 if found, 0 if not found.
 */
int batch_get_meta(const char *batch_id, enum BatchType *type, const char **param);

/* Send batch start to a client */
void batch_send_start(struct Client *cptr, enum BatchType type, 
                      const char *param, const char *batch_id);

/* Send batch end to a client */
void batch_send_end(struct Client *cptr, const char *batch_id);

/* Complete batch cleanup: send batch end to all affected clients, unregister, and free batch_id.
 * @param[in] batch_id Batch ID to complete (will be freed by this function).
 */
void batch_complete(char *batch_id);

/* Remove a client from all batch lists (called on client exit).
 * @param[in] cptr Client being removed.
 */
void batch_remove_client(struct Client *cptr);

#endif /* INCLUDED_batch_h */

