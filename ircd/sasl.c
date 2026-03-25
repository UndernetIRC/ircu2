/*
 * IRC - Internet Relay Chat, ircd/sasl.c
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

/** @file
 * @brief SASL authentication implementation
 */

#include "config.h"

#include "sasl.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_string.h"
#include "ircd_reply.h"
#include "ircd_netconf.h"
#include "send.h"
#include "msg.h"
#include "capab.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_bsd.h"
#include "numeric.h"

#include <string.h>

/** SASL statistics */
struct SaslStats {
  unsigned long auth_success; /**< Number of successful authentications */
  unsigned long auth_failed;  /**< Number of failed authentications */
};

/** Global SASL statistics */
static struct SaslStats sasl_statistics = { 0, 0 };

/** Check if SASL is available
 * @return 1 if SASL server is configured, 0 otherwise
 */
int sasl_available(void)
{
  if (!*netconf_str(NETCONF_SASL_SERVER)
      || !*netconf_str(NETCONF_SASL_MECHANISMS)
      || !find_match_server((char*)netconf_str(NETCONF_SASL_SERVER)))
    return 0;

  return 1;
}

/** Check if a mechanism exists in a mechanism list
 * @param[in] mechanism The mechanism to find
 * @param[in] mechanism_list Comma-delimited list of mechanisms
 * @return 1 if found, 0 if not
 */
static int mechanism_in_list(const char* mechanism, const char* mechanism_list)
{
  char* mech_list;
  char* token;
  int found = 0;

  if (!mechanism_list || !*mechanism_list || !mechanism || !*mechanism)
    return 0;

  DupString(mech_list, mechanism_list);
  if (!mech_list)
    return 0;

  token = strtok(mech_list, ",");
  while (token) {
    /* Trim whitespace */
    while (*token == ' ') token++;
    char* end = token + strlen(token) - 1;
    while (end > token && *end == ' ') *end-- = '\0';
    
    if (ircd_strcmp(token, mechanism) == 0) {
      found = 1;
      break;
    }
    token = strtok(NULL, ",");
  }
  
  MyFree(mech_list);
  return found;
}

/** Check if a SASL mechanism is supported
 * @param[in] mechanism The mechanism to check
 * @return 1 if supported, 0 if not
 */
int sasl_mechanism_supported(const char* mechanism)
{
  return mechanism_in_list(mechanism, netconf_str(NETCONF_SASL_MECHANISMS));
}

/** Check and update SASL capability availability
 * This function should be called when events occur that might change
 * SASL availability (netjoin/netsplit, config changes)
 */
void sasl_check_capability(void)
{
  cap_update_availability(E_CAP_SASL, sasl_available());
}

/** Config change callback for SASL-related configuration
 * @param[in] key Configuration key that changed
 * @param[in] old_value Old value (NULL if new key)
 * @param[in] new_value New value
 */
static void sasl_config_callback(const char *key, const char *old_value, const char *new_value)
{
  Debug((DEBUG_INFO, "SASL config changed: %s = %s (was: %s)", 
         key, new_value, old_value ? old_value : "(unset)"));
  
  /* Update SASL capability value if mechanisms changed */
  if (ircd_strcmp(key, "sasl.mechanisms") == 0) {
    cap_set_value(E_CAP_SASL, new_value);
  }
  
  /* Update SASL capability availability */
  sasl_check_capability();
}

/** Initialize SASL subsystem and register config callbacks */
void sasl_init(void)
{
  config_register_callback("sasl.", sasl_config_callback);
}

/** Find a client by their SASL session cookie
 * @param[in] cookie SASL session cookie to search for
 * @return Client with matching SASL cookie, or NULL if not found
 */
struct Client* find_sasl_client(unsigned long cookie)
{
  struct Client* cptr;
  int i;
  
  if (!cookie)
    return NULL;
    
  /* Search through all local clients */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!(cptr = LocalClientArray[i]))
      continue;
      
    /* Check if this client has the matching SASL cookie */
    if (cli_sasl(cptr) == cookie)
      return cptr;
  }
  
  return NULL;
}

/** Handle SASL extension reply from authentication server
 * @param[in] sptr Server that sent the reply
 * @param[in] routing Routing information (should be SASL cookie)
 * @param[in] reply The SASL reply message
 */
void sasl_send_xreply(struct Client* sptr, const char* routing, const char* reply)
{
  struct Client* cli;
  unsigned long cookie;
  
  if (!routing || !reply)
    return;
    
  /* Parse the routing information to get the SASL cookie */
  cookie = strtoul(routing, NULL, 10);
  if (!cookie) {
    Debug((DEBUG_DEBUG, "sasl_send_xreply: Invalid cookie in routing '%s'", routing));
    return;
  }
  
  /* Find the client with this SASL cookie */
  cli = find_sasl_client(cookie);
  if (!cli) {
    Debug((DEBUG_DEBUG, "sasl_send_xreply: No client found for SASL cookie %lu", cookie));
    return;
  }
  
  if (reply[0] == 'O' && reply[1] == 'K'
               && (reply[2] == '\0' || reply[2] == ' ')) {
    
    const char *account_info = reply + 3; /* Skip "OK " */
    char *account_copy, *username, *id_str, *flags_str, *extra;

    /**
     * We only parse this information if the user is not yet registered (i.e. SASL authentication during auth).
     * If this is a SASL authentication after registration, the username will be set by the service using AC.
     */
    if (!IsUser(cli)) {
      /* Parse account information: username:id:flags */
      DupString(account_copy, account_info);
      if (!account_copy)
        return;
      
      username = strtok(account_copy, ":");
      id_str = strtok(NULL, ":");
      flags_str = strtok(NULL, " ");
      extra = strtok(NULL, "");
         
      /* Copy account name to User structure */
      ircd_strncpy(cli_user(cli)->account, username, ACCOUNTLEN);
      
      /* Parse account ID if provided */
      if (id_str) {
        cli_user(cli)->acc_id = strtoul(id_str, NULL, 10);
      }
      
      /* Parse account flags if provided */
      if (flags_str) {
        cli_user(cli)->acc_flags = strtoul(flags_str, NULL, 10);
      }
      
      SetAccount(cli);
      
      /* Check for +x flag (host hiding) */
      if (extra && strstr(extra, "+x") && feature_bool(FEAT_HOST_HIDING)) {
        SetHiddenHost(cli);
      }

      MyFree(account_copy);

    /**
     * For already registered users, we send RPL_LOGGEDIN. For non-registered users,
     * we send RPL_LOGGEDIN in check_auth_finished().
     */
    } else {
      send_reply(cli, RPL_LOGGEDIN,
        cli_name(cli), cli_user(cli)->username,
        cli_user(cli)->host, cli_user(cli)->account,
        cli_user(cli)->account);
    }

    sasl_stop_timeout(cli);
    cli_sasl(cli) = 0;
    SetFlag(cli, FLAG_SASL);

    send_reply(cli, RPL_SASLSUCCESS);
    sasl_statistics.auth_success++;
  } else if (0 == ircd_strncmp(reply, "NO ", 3)) {
    /* Authentication failed, send failure message to client */
    send_reply(cli, ERR_SASLFAIL, reply + 3);
    
    /* Stop SASL timeout timer and clear session */
    sasl_stop_timeout(cli);
    cli_sasl(cli) = 0;
    
    /* Increment failed authentication counter */
    sasl_statistics.auth_failed++;

  } else if (0 == ircd_strncmp(reply, "SASL ", 5)) {
    /* Send the AUTHENTICATE reply to the client */
    sendcmdto_one(&me, CMD_AUTHENTICATE, cli, "%s", reply + 5);
  }
}

/** Generate SASL statistics for /STATS S
 * @param[in] sptr Client requesting statistics
 * @param[in] sd Stats descriptor (unused)
 * @param[in] param Additional parameter (unused)
 */
void sasl_stats(struct Client* sptr, const struct StatDesc* sd, char* param)
{
  if (sasl_available()) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL server: %s", netconf_str(NETCONF_SASL_SERVER));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL mechanisms: %s", netconf_str(NETCONF_SASL_MECHANISMS));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL timeout: %d", netconf_int(NETCONF_SASL_TIMEOUT));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL successful auths: %lu", sasl_statistics.auth_success);
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL failed auths: %lu", sasl_statistics.auth_failed);
  } else {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL not available");
  }
}