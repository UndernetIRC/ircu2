/*
 * IRC - Internet Relay Chat, ircd/m_destruct.c
 * Copyright (C) 1997 Carlo Wood.
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

#include "config.h"

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
#include "channel.h"
#include "destruct_event.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>

/*
 * ms_destruct - server message handler
 *
 * Added 1997 by Run, actually coded and used since 2002.
 *
 * parv[0] = sender prefix
 * parv[1] = channel channelname
 * parv[2] = channel time stamp
 *
 * This message is intended to destruct _empty_ channels.
 *
 * The reason it is needed is to somehow add the notion
 * "I destructed information" to the networks state
 * (also messages that are still propagating are part
 *  of the global state).  Without it the network could
 * easily be desynced as a result of destructing a channel
 * on only a part of the network while keeping the modes
 * and creation time on others.
 * There are three possible ways a DESTRUCT message is
 * handled by remote servers:
 * 1) The channel is empty and has the same timestamp
 *    as on the message.  Conclusion: The channel has
 *    not been destructed and recreated in the meantime,
 *    this means that the normal synchronization rules
 *    account and we react as if we decided to destruct
 *    the channel ourselves: we destruct the channel and
 *    send a DESTRUCT in all directions.
 * 2) The channel is not empty.  In case we cannot remove
 *    it and do not propagate the DESTRUCT message. Instead
 *    a resynchronizing BURST message is sent upstream
 *    in order to restore the channel on that side (which
 *    will have a TS younger than the current channel if
 *    it was recreated and will thus be fully synced, just
 *    like in the case of a real net-junction).
 * 3) The channel is empty, but the creation time of the
 *    channel is older than the timestamp on the message.
 *    This can happen when there is more than one minute
 *    lag and remotely a channel was created slightly
 *    after we created the channel, being abandoned again
 *    and staying empty for a minute without that our
 *    CREATE reached that remote server.  The remote server
 *    then could have generated the DESTRUCT.  In the meantime
 *    our user also left the channel.  We can ignore the
 *    destruct because it comes from an 'area' that will
 *    be overridden by our own CREATE: the state that generated
 *    this DESTRUCT is 'history'.
 */
int ms_destruct(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  time_t chanTS;                /* Creation time of the channel */
  struct Channel* chptr;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if (parc < 3 || EmptyString(parv[2]))
    return need_more_params(sptr,"DESTRUCT");

  chanTS = atoi(parv[2]);

  /* Ignore DESTRUCT messages for non-existing channels. */
  if (!(chptr = FindChannel(parv[1])))
    return 0;

  /* Ignore DESTRUCT when the channel is older than the
     timestamp on the message. */
  if (chanTS > chptr->creationtime)
    return 0;

  /* Don't pass on DESTRUCT messages for channels that
     are not empty, but instead send a BURST msg upstream. */
  if (chptr->users > 0) {
    send_channel_modes(cptr, chptr);
    return 0;
  }

  /* Pass on DESTRUCT message and ALSO bounce it back! */
  sendcmdto_serv_butone(&me, CMD_DESTRUCT, 0, "%s %Tu", parv[1], chanTS);

  /* Remove the empty channel. */
  remove_destruct_event(chptr);
  destruct_channel(chptr);

  return 0;
}
