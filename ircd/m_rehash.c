/*
 * IRC - Internet Relay Chat, ircd/m_rehash.c
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

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a REHASH message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server, or "*" for all.
 * \li \a parv[2] (optional) is a flag indicating what to rehash
 *
 * The following flags are recognized:
 * \li 'm' flushes the MOTD cache
 * \li 'l' reopens the log files
 * \li 'q' reloads the configuration file but does not rehash the DNS
 *   resolver
 * \li the default is to reload the configuration file and restart the
 *   DNS resolver
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_rehash(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int flag = 0;
  const char *target;

  if (parc < 2)
    return need_more_params(sptr, "REHASH");

  target = parv[1];

  /* is it a message we should pay attention to? */
  if (target[0] != '*' || target[1] != '\0') {
    if (hunt_server_cmd(sptr, CMD_REHASH, cptr, 0, parc > 2 ? "%C %s" : "%C",
			1, parc, parv)
	!= HUNTED_ISME)
      return 0;
  } else if (parc > 2) /* must forward the message with flags */
    sendcmdto_serv(sptr, CMD_REHASH, cptr, "* %s", parv[2]);
  else /* just have to forward the message */
    sendcmdto_serv(sptr, CMD_REHASH, cptr, "*");

  /* OK, the message has been forwarded, but before we can act... */
  if (!feature_bool(FEAT_NETWORK_REHASH))
    return 0;

  if (parc > 2) { /* special processing */
    if (*parv[2] == 'm') {
      send_reply(sptr, SND_EXPLICIT | RPL_REHASHING, ":Flushing MOTD cache");
      motd_recache(); /* flush MOTD cache */
      return 0;
    } else if (*parv[2] == 'l') {
      send_reply(sptr, SND_EXPLICIT | RPL_REHASHING, ":Reopening log files");
      log_reopen(); /* reopen log files */
      return 0;
    } else if (*parv[2] == 'q')
      flag = 2;
  }

  send_reply(sptr, RPL_REHASHING, configfile);
  sendto_opmask(0, SNO_OLDSNO, "%C is rehashing Server config file", sptr);
  log_write(LS_SYSTEM, L_INFO, 0, "REHASH From %#C", sptr);

  return rehash(cptr, flag);
}

/** Handle a REHASH message from an operator connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] (optional) is a flag indicating what to rehash
 *
 * The following flags are recognized:
 * \li 'm' flushes the MOTD cache
 * \li 'l' reopens the log files
 * \li 'q' reloads the configuration file but does not rehash the DNS
 *   resolver
 * \li the default is to reload the configuration file and restart the
 *   DNS resolver
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_rehash(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int flag = 0;

  if (!HasPriv(sptr, PRIV_REHASH))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc > 1) { /* special processing */
    if (*parv[1] == 'm') {
      send_reply(sptr, SND_EXPLICIT | RPL_REHASHING, ":Flushing MOTD cache");
      motd_recache(); /* flush MOTD cache */
      return 0;
    } else if (*parv[1] == 'l') {
      send_reply(sptr, SND_EXPLICIT | RPL_REHASHING, ":Reopening log files");
      log_reopen(); /* reopen log files */
      return 0;
    } else if (*parv[1] == 'q')
      flag = 2;
  }

  send_reply(sptr, RPL_REHASHING, configfile);
  sendto_opmask(0, SNO_OLDSNO, "%C is rehashing Server config file", sptr);
  log_write(LS_SYSTEM, L_INFO, 0, "REHASH From %#C", sptr);

  return rehash(cptr, flag);
}

