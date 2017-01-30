/*
 * IRC - Internet Relay Chat, ircd/m_privmsg.c
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
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Handle a PRIVMSG message from a normal client connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the comma-separated list of message targets
 * \li \a parv[\a parc - 1] is the message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_privmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];

  assert(0 != cptr);
  assert(cptr == sptr);
  assert(0 != cli_user(sptr));

  if (feature_bool(FEAT_IDLE_FROM_MSG))
    cli_user(sptr)->last = CurrentTime;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_PRIVATE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name)) {
      relay_channel_message(sptr, name, parv[parc - 1]);
    }
    /*
     * we have to check for the '@' at least once no matter what we do
     * handle it first so we don't have to do it twice
     */
    else if ((server = strchr(name, '@')))
      relay_directed_message(sptr, name, server, parv[parc - 1]);
    else 
      relay_private_message(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/** Handle a PRIVMSG message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the comma-separated list of message targets
 * \li \a parv[\a parc - 1] is the message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_privmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* name;
  char* server;

  if (parc < 3) {
    /*
     * we can't deliver it, sending an error back is pointless
     */
    return 0;
  }
  name = parv[1];
  /*
   * channel msg?
   */
  if (IsChannelPrefix(*name)) {
    server_relay_channel_message(sptr, name, parv[parc - 1]);
  }
  /*
   * coming from another server, we have to check this here
   */
  else if ('$' == *name && IsOper(sptr)) {
    server_relay_masked_message(sptr, name, parv[parc - 1]);
  }
  else if ((server = strchr(name, '@'))) {
    /*
     * XXX - can't get away with not doing everything
     * relay_directed_message has to do
     */
    relay_directed_message(sptr, name, server, parv[parc - 1]);
  }
  else {
    server_relay_private_message(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/** Handle a PRIVMSG message from an operator connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the comma-separated list of message targets
 * \li \a parv[\a parc - 1] is the message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_privmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];
  assert(0 != cptr);
  assert(cptr == sptr);
  assert(0 != cli_user(sptr));

  if (feature_bool(FEAT_IDLE_FROM_MSG))
    cli_user(sptr)->last = CurrentTime;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_PRIVATE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name))
      relay_channel_message(sptr, name, parv[parc - 1]);

    else if (*name == '$')
      relay_masked_message(sptr, name, parv[parc - 1]);

    else if ((server = strchr(name, '@')))
      relay_directed_message(sptr, name, server, parv[parc - 1]);

    else 
      relay_private_message(sptr, name, parv[parc - 1]);
  }
  return 0;
}
