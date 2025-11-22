/*
 * IRC - Internet Relay Chat, ircd/batch.c
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

#include <stdlib.h>
#include <string.h>
 
#include "batch.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "send.h"

static unsigned int batch_counter = 0;

/* Client entry in a batch's client list */
struct BatchClient {
  struct BatchClient *next;
  struct Client *client;  /* Client that received batch start */
};

/* Batch metadata structure */
struct BatchMeta {
  struct BatchMeta *next;
  char *batch_id;
  enum BatchType type;
  char *param;  /* Can be NULL */
  struct BatchClient *clients;  /* Linked list of clients that received batch start */
};

/* Linked list of active batch metadata */
static struct BatchMeta *batch_meta_list = NULL;

/* Convert batch type enum to string for protocol */
static const char *batch_type_to_string(enum BatchType type)
{
  static const char *type_strings[] = {
    "netsplit",
    "netjoin"
  };
  if (type >= 0 && type < BATCH_TYPE_MAX)
    return type_strings[type];
  return "unknown";
}

/* Generate unique batch ID */
char *batch_generate_id(void)
{
  char *batch_id = MyMalloc(BATCHLEN + 1);
  ircd_snprintf(0, batch_id, BATCHLEN + 1, "%08x%04x", 
                (unsigned int)CurrentTime,
                (unsigned int)(++batch_counter));
  return batch_id;
}

/* Register batch metadata (type and param) for a batch_id.
 * This must be called before sending any messages with this batch_id.
 */
void batch_register(const char *batch_id, enum BatchType type, const char *param)
{
  struct BatchMeta *meta;
  
  if (!batch_id)
    return;
  
  /* Check if already registered */
  for (meta = batch_meta_list; meta; meta = meta->next) {
    if (strcmp(meta->batch_id, batch_id) == 0)
      return; /* Already registered */
  }
  
  /* Create new metadata entry */
  meta = MyMalloc(sizeof(struct BatchMeta));
  meta->batch_id = (char *)batch_id; /* We don't copy - caller owns it */
  meta->type = type;
  if (param && param[0]) {
    meta->param = MyMalloc(strlen(param) + 1);
    strcpy(meta->param, param);
  } else {
    meta->param = NULL;
  }
  meta->clients = NULL;  /* Initialize client list */
  meta->next = batch_meta_list;
  batch_meta_list = meta;
}

/* Unregister batch metadata when batch is complete. */
void batch_unregister(const char *batch_id)
{
  struct BatchMeta *meta, *prev = NULL;
  struct BatchClient *client, *next_client;
  
  if (!batch_id)
    return;
  
  for (meta = batch_meta_list; meta; prev = meta, meta = meta->next) {
    if (strcmp(meta->batch_id, batch_id) == 0) {
      /* Free client list */
      for (client = meta->clients; client; client = next_client) {
        next_client = client->next;
        MyFree(client);
      }
      
      /* Remove from list */
      if (prev)
	      prev->next = meta->next;
      else
	      batch_meta_list = meta->next;
      
      /* Free param if allocated */
      if (meta->param)
	      MyFree(meta->param);
      
      /* Note: we don't free batch_id - caller owns it */
      MyFree(meta);
      return;
    }
  }
}

/* Get batch metadata for a batch_id */
int batch_get_meta(const char *batch_id, enum BatchType *type, const char **param)
{
  struct BatchMeta *meta;
  
  if (!batch_id || !type || !param)
    return 0;
  
  for (meta = batch_meta_list; meta; meta = meta->next) {
    if (strcmp(meta->batch_id, batch_id) == 0) {
      *type = meta->type;
      *param = meta->param;
      return 1;
    }
  }
  
  return 0;
}

/* Check if a client has already received batch start for a batch_id */
static int batch_has_client(const char *batch_id, struct Client *cptr)
{
  struct BatchMeta *meta;
  struct BatchClient *client;
  
  if (!batch_id || !cptr)
    return 0;
  
  for (meta = batch_meta_list; meta; meta = meta->next) {
    if (strcmp(meta->batch_id, batch_id) == 0) {
      for (client = meta->clients; client; client = client->next) {
        if (client->client == cptr)
          return 1;
      }
      return 0;
    }
  }
  return 0;
}

/* Add a client to a batch's client list */
static void batch_add_client(const char *batch_id, struct Client *cptr)
{
  struct BatchMeta *meta;
  struct BatchClient *client;
  
  if (!batch_id || !cptr)
    return;
  
  for (meta = batch_meta_list; meta; meta = meta->next) {
    if (strcmp(meta->batch_id, batch_id) == 0) {
      /* Check if already in list */
      for (client = meta->clients; client; client = client->next) {
        if (client->client == cptr)
          return; /* Already in list */
      }
      
      /* Add to list */
      client = MyMalloc(sizeof(struct BatchClient));
      client->client = cptr;
      client->next = meta->clients;
      meta->clients = client;
      return;
    }
  }
}

/* Send batch start to a client and add to batch's client list */
void batch_send_start(struct Client *cptr, enum BatchType type, 
                      const char *param, const char *batch_id)
{
  const char *type_str = batch_type_to_string(type);
  
  if (!cptr || IsServer(cptr) || !MyConnect(cptr))
    return;
    
  /* Only send batches to clients with batch capability */
  if (!CapHas(cli_active(cptr), CAP_BATCH))
    return;
  
  /* Check if we've already sent batch start to this client */
  if (batch_has_client(batch_id, cptr))
    return;
  
  if (param && param[0])
    sendcmdto_one(&me, CMD_BATCH, cptr, "+%s %s %s", batch_id, type_str, param);
  else
    sendcmdto_one(&me, CMD_BATCH, cptr, "+%s %s", batch_id, type_str);
  
  /* Add client to batch's client list */
  batch_add_client(batch_id, cptr);
}

/* Send batch end to a client */
void batch_send_end(struct Client *cptr, const char *batch_id)
{
  if (!cptr || IsServer(cptr) || !MyConnect(cptr))
    return;
    
  /* Only send batches to clients with batch capability */
  if (!CapHas(cli_active(cptr), CAP_BATCH))
    return;
  
  sendcmdto_one(&me, CMD_BATCH, cptr, "-%s", batch_id);
}

/* Complete batch cleanup: send batch end to all affected clients, unregister, and free batch_id */
void batch_complete(char *batch_id)
{
  struct BatchMeta *meta;
  struct BatchClient *client, *next_client;
  
  if (!batch_id)
    return;
  
  /* Find batch metadata */
  for (meta = batch_meta_list; meta; meta = meta->next) {
    if (strcmp(meta->batch_id, batch_id) == 0) {
      /* Send batch end to all clients in this batch */
      for (client = meta->clients; client; client = next_client) {
        next_client = client->next;
        if (client->client && MyConnect(client->client) && IsUser(client->client)) {
          batch_send_end(client->client, batch_id);
        }
        MyFree(client);
      }
      meta->clients = NULL;
      break;
    }
  }
  
  batch_unregister(batch_id);
  MyFree(batch_id);
}

/* Remove a client from all batch lists (called on client exit) */
void batch_remove_client(struct Client *cptr)
{
  struct BatchMeta *meta;
  struct BatchClient *client, *prev, *next;
  
  if (!cptr)
    return;
  
  for (meta = batch_meta_list; meta; meta = meta->next) {
    prev = NULL;
    for (client = meta->clients; client; prev = client, client = next) {
      next = client->next;
      if (client->client == cptr) {
        /* Remove from list */
        if (prev)
          prev->next = next;
        else
          meta->clients = next;
        MyFree(client);
        /* Continue to check for duplicates (shouldn't happen, but be safe) */
      }
    }
  }
}
