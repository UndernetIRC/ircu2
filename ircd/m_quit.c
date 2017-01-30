/*
 * IRC - Internet Relay Chat, ircd/m_quit.c
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

#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "struct.h"
#include "s_misc.h"
#include "ircd_reply.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Handle a QUIT message from a client connection.
 *
 * \a parv has the following elements:
 * \li \a parv[\a parc - 1] is the quit message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_quit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);

  if (cli_user(sptr)) {
    struct Membership* chan;
    for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel) {
        if (!IsZombie(chan) && !IsDelayedJoin(chan) && !member_can_send_to_channel(chan, 0))
        return exit_client(cptr, sptr, sptr, "Signed off");
    }
  }
  if (parc > 1 && !BadPtr(parv[parc - 1]))
    return exit_client_msg(cptr, sptr, sptr, "Quit: %s", parv[parc - 1]);
  else
    return exit_client(cptr, sptr, sptr, "Quit");
}


/** Handle a QUIT message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[\a parc - 1] is the quit message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_quit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != sptr);
  assert(parc > 0);
  if (IsServer(sptr)) {
  	protocol_violation(sptr,"Server QUIT, not SQUIT?");
  	return 0;
  }
  /*
   * ignore quit from servers
   */
  return exit_client(cptr, sptr, sptr, parv[parc - 1]);
}
