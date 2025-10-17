/*
 * IRC - Internet Relay Chat, ircd/ircd_netconf.c
 * Copyright (C) 2025 MrIron <mriron@undernet.org>
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

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_netconf.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "send.h"

#include <string.h>
#include <assert.h>

/** Head of the configuration list */
static struct ConfigEntry *config_list = NULL;

/** Head of the callback list */
static struct ConfigCallback *callback_list = NULL;

/** Find a configuration entry by key
 * @param[in] key Configuration key to find
 * @return Configuration entry or NULL if not found
 */
static struct ConfigEntry *config_find(const char *key)
{
  struct ConfigEntry *entry;
  
  assert(key != NULL);
  
  for (entry = config_list; entry; entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      return entry;
  }
  
  return NULL;
}

/** Call registered callbacks for a key
 * @param[in] key Configuration key that changed
 * @param[in] old_value Previous value (NULL if new)
 * @param[in] new_value New value
 */
static void config_call_callbacks(const char *key, const char *old_value, const char *new_value)
{
  struct ConfigCallback *cb;
  
  for (cb = callback_list; cb; cb = cb->next) {
    if (ircd_strncmp(key, cb->key_prefix, strlen(cb->key_prefix)) == 0) {
      cb->callback(key, old_value, new_value);
    }
  }
}

/** Set a configuration option
 * @param[in] key Configuration key
 * @param[in] value Configuration value  
 * @param[in] timestamp Timestamp when this config was set
 * @return 1 if the value was updated, 0 if it was created, -1 on error
 */
int config_set(const char *key, const char *value, time_t timestamp)
{
  struct ConfigEntry *entry;
  char *old_value = NULL;
  int result;
  
  assert(key != NULL);
  assert(value != NULL);
  
  entry = config_find(key);
  
  if (entry) {
    /* Only update if timestamp is newer */
    if (timestamp <= entry->timestamp)
      return CONFIG_REJECTED;
      
    /* Save old value for callbacks */
    DupString(old_value, entry->value);
    
    /* Check if value actually changed */
    int value_changed = (ircd_strcmp(old_value, value) != 0);
      
    /* Update existing entry */
    MyFree(entry->value);
    DupString(entry->value, value);
    entry->timestamp = timestamp;
    
    result = value_changed ? CONFIG_CHANGED : CONFIG_TIMESTAMP;
  } else {
    /* Create new entry */
    entry = MyMalloc(sizeof(struct ConfigEntry));
    DupString(entry->key, key);
    DupString(entry->value, value);
    entry->timestamp = timestamp;
    entry->next = config_list;
    config_list = entry;
    result = CONFIG_CREATED;
  }
  
  Debug((DEBUG_DEBUG, "Config %s: %s = %s (timestamp: %lu)", 
         (result == CONFIG_CHANGED) ? "changed" : 
         (result == CONFIG_TIMESTAMP) ? "timestamp updated" : "set", 
         key, value, (unsigned long)timestamp));
  
  /* Call callbacks */
  config_call_callbacks(key, old_value, value);
  
  if (old_value)
    MyFree(old_value);
  
  return result;
}

/** Get a configuration value
 * @param[in] key Configuration key
 * @return Configuration value or NULL if not found
 */
const char *config_get(const char *key)
{
  struct ConfigEntry *entry;
  
  assert(key != NULL);
  
  entry = config_find(key);
  return entry ? entry->value : NULL;
}

/** Get the timestamp of a configuration option
 * @param[in] key Configuration key
 * @return Timestamp or 0 if not found
 */
time_t config_get_timestamp(const char *key)
{
  struct ConfigEntry *entry;
  
  assert(key != NULL);
  
  entry = config_find(key);
  return entry ? entry->timestamp : 0;
}

/** Count the number of configuration entries
 * @return Number of configuration entries
 */
static int config_count(void)
{
  struct ConfigEntry *entry;
  int count = 0;
  
  for (entry = config_list; entry; entry = entry->next)
    count++;
    
  return count;
}

/** Register a callback for configuration changes
 * @param[in] key_prefix Key prefix to match (e.g., "sasl.")
 * @param[in] callback Callback function to call
 */
void config_register_callback(const char *key_prefix, config_callback_f callback)
{
  struct ConfigCallback *cb;
  
  assert(key_prefix != NULL);
  assert(callback != NULL);
  
  /* Check if callback already exists */
  for (cb = callback_list; cb; cb = cb->next) {
    if (ircd_strcmp(cb->key_prefix, key_prefix) == 0) {
      cb->callback = callback;
      return;
    }
  }
  
  /* Create new callback */
  cb = MyMalloc(sizeof(struct ConfigCallback));
  DupString(cb->key_prefix, key_prefix);
  cb->callback = callback;
  cb->next = callback_list;
  callback_list = cb;
  
  Debug((DEBUG_DEBUG, "Config callback registered for prefix: %s", key_prefix));
}

/** Unregister a callback for configuration changes  
 * @param[in] key_prefix Key prefix that was registered
 */
void config_unregister_callback(const char *key_prefix)
{
  struct ConfigCallback *cb, *prev = NULL;
  
  assert(key_prefix != NULL);
  
  for (cb = callback_list; cb; prev = cb, cb = cb->next) {
    if (ircd_strcmp(cb->key_prefix, key_prefix) == 0) {
      if (prev)
        prev->next = cb->next;
      else
        callback_list = cb->next;
        
      MyFree(cb->key_prefix);
      MyFree(cb);
      
      Debug((DEBUG_DEBUG, "Config callback unregistered for prefix: %s", key_prefix));
      return;
    }
  }
}

/** Burst all configuration entries to a newly connected server
 * @param[in] cptr Server to send CF messages to
 */
void config_burst(struct Client *cptr)
{
  struct ConfigEntry *entry;
  
  for (entry = config_list; entry; entry = entry->next) {
    sendcmdto_one(&me, CMD_CONFIG, cptr, "%Tu %s %s",
                  entry->timestamp, entry->key, entry->value);
  }
  
  Debug((DEBUG_INFO, "Config burst: %d entries sent to %s", 
         config_count(), cli_name(cptr)));
}

/** Generate configuration statistics for /STATS C
 * @param[in] sptr Client requesting statistics
 * @param[in] sd Stats descriptor (unused)
 * @param[in] param Additional parameter (unused)
 */
void config_stats(struct Client *sptr, const struct StatDesc *sd, char *param)
{
  struct ConfigEntry *entry;
  
  for (entry = config_list; entry; entry = entry->next) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "%Tu %s :%s",
               entry->timestamp, entry->key, entry->value);
  }
}