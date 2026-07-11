/*
 * IRC - Internet Relay Chat, ircd/m_config.c
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
#include "send.h"
#include "s_debug.h"

#include <stdlib.h>

/** Handler for server CONFIG messages
 * @param[in] cptr Local client that sent us the message
 * @param[in] sptr Original source of the message  
 * @param[in] parc Number of parameters
 * @param[in] parv Parameter vector (source CF timestamp key value)
 * @return 0 on success
 */
int ms_config(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  time_t timestamp;
  const char *key, *value;
  const char *old_value;
  int result;

  if (parc < 3)
    return need_more_params(sptr, "CF");

  timestamp = atol(parv[1]);
  key = parv[2];
  value = (parc >= 4) ? parv[3] : "";

  /* Get the old value for comparison */
  old_value = config_get(key);
  char *old_value_copy = NULL;
  if (old_value)
    DupString(old_value_copy, old_value);
  
  /* Try to set the configuration */
  result = config_set(key, value, timestamp);

  if (result != CONFIG_REJECTED) {
    /* Propagate to other servers */
    if (value[0] != '\0') {
      sendcmdto_serv_butone(sptr, CMD_CONFIG, cptr, "%Tu %s :%s",
                            timestamp, key, value);
    } else {
      sendcmdto_serv_butone(sptr, CMD_CONFIG, cptr, "%Tu %s",
                            timestamp, key);
    }

    /* Notify operators */
    if (result == CONFIG_CREATED) {
      sendto_opmask_butone(0, SNO_NETWORK,
                          "Network configuration set: %s = %s",
                          key, value);
    } else if (result == CONFIG_CHANGED) {
      sendto_opmask_butone(0, SNO_NETWORK,
                          "Network configuration updated: %s = %s (was: %s)",
                          key, value, old_value_copy ? old_value_copy : "(unset)");
    } else if (result == CONFIG_DELETED) {
      sendto_opmask_butone(0, SNO_NETWORK,
                          "Network configuration deleted: %s (was: %s)",
                          key, old_value_copy ? old_value_copy : "(unset)");
      Debug((DEBUG_DEBUG, "NETCONF: %s deleted %s (timestamp: %Tu)",
             cli_name(sptr), key, timestamp));
    } else {
      Debug((DEBUG_DEBUG, "NETCONF: %s set %s = %s (timestamp: %Tu)",
             cli_name(sptr), key, value, timestamp));
    }
  }
  
  /* Clean up the copied old value */
  if (old_value_copy)
    MyFree(old_value_copy);
  
  return 0;
}
