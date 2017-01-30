/*
 * IRC - Internet Relay Chat, ircd/m_end_of_burst.c
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
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle an EOB message from a server.
 *
 * - Added Xorath 6-14-96, rewritten by Run 24-7-96
 * - and fixed by record and Kev 8/1/96
 * - and really fixed by Run 15/8/96 :p
 * This the last message in a net.burst.
 * It clears a flag for the server sending the burst.
 *
 * As of 10.11, to fix a bug in the way BURST is processed, it also
 * makes sure empty channels are deleted
 *
 * \a parv is ignored.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_end_of_burst(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chan, *next_chan;

  assert(0 != cptr);
  assert(0 != sptr);

  sendto_opmask(0, SNO_NETWORK, "Completed net.burst from %C.", sptr);
  sendcmdto_serv(sptr, CMD_END_OF_BURST, cptr, "");
  ClearBurst(sptr);
  SetBurstAck(sptr);
  if (MyConnect(sptr))
    sendcmdto_one(&me, CMD_END_OF_BURST_ACK, sptr, "");

  /* Count through channels... */
  for (chan = GlobalChannelList; chan; chan = next_chan) {
    next_chan = chan->next;
    if (!chan->members && (chan->mode.mode & MODE_BURSTADDED)) {
      /* Newly empty channel, schedule it for removal. */
      chan->mode.mode &= ~MODE_BURSTADDED;
      sub1_from_channel(chan);
   } else
      chan->mode.mode &= ~MODE_BURSTADDED;
  }

  return 0;
}

/** Handle an EOB acknowledgment from a server.
 *
 * This the acknowledge message of the `END_OF_BURST' message.
 * It clears a flag for the server receiving the burst.
 *
 * \a parv is ignored.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_end_of_burst_ack(struct Client *cptr, struct Client *sptr, int parc, char **parv)
{
  if (!IsServer(sptr))
    return 0;

  sendto_opmask(0, SNO_NETWORK, "%C acknowledged end of net.burst.", sptr);
  sendcmdto_serv(sptr, CMD_END_OF_BURST_ACK, cptr, "");
  ClearBurstAck(sptr);

  return 0;
}
