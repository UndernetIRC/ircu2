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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <assert.h>

/*
 * ms_end_of_burst - server message handler
 * - Added Xorath 6-14-96, rewritten by Run 24-7-96
 * - and fixed by record and Kev 8/1/96
 * - and really fixed by Run 15/8/96 :p
 * This the last message in a net.burst.
 * It clears a flag for the server sending the burst.
 *
 * As of 10.11, to fix a bug in the way BURST is processed, it also
 * makes sure empty channels are deleted
 *
 * parv[0] - sender prefix
 */
int ms_end_of_burst(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chan, *next_chan;

  assert(0 != cptr);
  assert(0 != sptr);

  sendto_opmask_butone(0, SNO_NETWORK, "Completed net.burst from %C.", 
  	sptr);
  sendcmdto_serv_butone(sptr, CMD_END_OF_BURST, cptr, "");
  ClearBurst(sptr);
  SetBurstAck(sptr);
  if (MyConnect(sptr))
    sendcmdto_one(&me, CMD_END_OF_BURST_ACK, sptr, "");

  /* Count through channels... */
  for (chan = GlobalChannelList; chan; chan = next_chan) {
    next_chan = chan->next;

    if (!chan->members) { /* empty channel */
      if (!(chan->mode.mode & MODE_BURSTADDED))
	sendto_opmask_butone(0, SNO_OLDSNO, "Empty channel %H not added by "
			     "BURST!", chan);

      sub1_from_channel(chan); /* ok, nuke channel now */
    }

    chan->mode.mode &= ~MODE_BURSTADDED;
  }

  return 0;
}

/*
 * ms_end_of_burst_ack - server message handler
 *
 * This the acknowledge message of the `END_OF_BURST' message.
 * It clears a flag for the server receiving the burst.
 *
 * parv[0] - sender prefix
 */
int ms_end_of_burst_ack(struct Client *cptr, struct Client *sptr, int parc, char **parv)
{
  if (!IsServer(sptr))
    return 0;

  sendto_opmask_butone(0, SNO_NETWORK, "%C acknowledged end of net.burst.",
		       sptr);
  sendcmdto_serv_butone(sptr, CMD_END_OF_BURST_ACK, cptr, "");
  ClearBurstAck(sptr);

  return 0;
}
