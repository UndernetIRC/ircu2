/*
 * IRC - Internet Relay Chat, include/ircd_netconf.h
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

#ifndef INCLUDED_ircd_netconf_h
#define INCLUDED_ircd_netconf_h

#include <time.h>

struct Client;
struct StatDesc;

/** Configuration set return values */
#define CONFIG_REJECTED      -1  /**< Rejected - older timestamp */
#define CONFIG_CREATED        0  /**< New entry created */
#define CONFIG_TIMESTAMP      1  /**< Timestamp updated, same value */
#define CONFIG_CHANGED        2  /**< Value actually changed */
#define CONFIG_DELETED        3  /**< Entry deleted */

/** Configuration entry structure */
struct ConfigEntry {
  char *key;                /**< Configuration option key */
  char *value;              /**< Configuration option value */
  time_t timestamp;         /**< Timestamp when this config was set */
  struct ConfigEntry *next; /**< Next configuration entry */
};

/** Configuration change callback function type */
typedef void (*config_callback_f)(const char *key, const char *old_value, const char *new_value);

/** Configuration callback structure */
struct ConfigCallback {
  char *key_prefix;                    /**< Key prefix to match (e.g., "sasl.") */
  config_callback_f callback;          /**< Callback function */
  struct ConfigCallback *next;         /**< Next callback */
};

/** Network configuration options */
enum NetConf {
    /* To be included. This is the implementation only. */
    NETCONF_LAST_NC
};

/*
 * Prototypes
 */

extern int config_set(const char *key, const char *value, time_t timestamp);
extern const char *config_get(const char *key);
extern void config_register_callback(const char *key_prefix, config_callback_f callback);
extern void config_unregister_callback(const char *key_prefix);
extern void config_burst(struct Client *cptr);
extern void config_stats(struct Client *sptr, const struct StatDesc *sd, char *param);
extern int netconf_int(enum NetConf key);
extern int netconf_bool(enum NetConf key);
extern const char *netconf_str(enum NetConf key);

#endif /* INCLUDED_ircd_netconf_h */
