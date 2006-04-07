/*
 * IRC - Internet Relay Chat, ircd/m_destruct.c
 * Copyright (C) 1997, 2005 Carlo Wood.
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
#if 0	/* Once all servers are 2.10.12, this can be used too.
           Until then we have to use CREATE and MODE to
	   get the message accross, because older server do
	   not accept a BURST outside the net.burst. */
    send_channel_modes(cptr, chptr);
#else
  /* This happens when a JOIN and DESTRUCT crossed, ie:

     server1 ----------------- server2
        DESTRUCT-->   <-- JOIN,MODE

     Where the JOIN and MODE are the result of joining
     the zannel before it expired on server2, or in the
     case of simulateous expiration, a DESTRUCT crossing
     with another DESTRUCT (that will be ignored) and
     a CREATE of a user joining right after that:

     server1 ----------------- server2
        DESTRUCT-->   <-- DESTRUCT <-- CREATE
     
     in both cases, when the DESTRUCT arrives on
     server2 we need to send synchronizing messages
     upstream (to server1).  Since sending two CREATEs
     or JOINs for the same user after another is a
     protocol violation, we first have to send PARTs
     (we can't send a DESTRUCT because 2.10.11 ignores
     DESTRUCT messages (just passes them on) and has
     a bug that causes two JOIN's for the same user to
     result in that user being on the channel twice). */

    struct Membership *member;
    struct ModeBuf mbuf;
    struct Ban *link;

    /* Next, send all PARTs upstream. */
    for (member = chptr->members; member; member = member->next_member)
      sendcmdto_one(member->user, CMD_PART, cptr, "%H", chptr);

    /* Next, send JOINs for all members. */
    for (member = chptr->members; member; member = member->next_member)
      sendcmdto_one(member->user, CMD_JOIN, cptr, "%H", chptr);

    /* Build MODE strings. We use MODEBUF_DEST_BOUNCE with MODE_DEL to assure
       that the resulting MODEs are only sent upstream. */
    modebuf_init(&mbuf, sptr, cptr, chptr, MODEBUF_DEST_SERVER | MODEBUF_DEST_BOUNCE);

    /* Op/voice the users as appropriate. We use MODE_DEL because we fake a bounce. */
    for (member = chptr->members; member; member = member->next_member)
    {
      if (IsChanOp(member))
        modebuf_mode_client(&mbuf, MODE_DEL | MODE_CHANOP, member->user, OpLevel(member));
      if (HasVoice(member))
        modebuf_mode_client(&mbuf, MODE_DEL | MODE_VOICE, member->user, MAXOPLEVEL + 1);
    }

    /* Send other MODEs. */
    modebuf_mode(&mbuf, MODE_DEL | chptr->mode.mode);
    if (*chptr->mode.key)
      modebuf_mode_string(&mbuf, MODE_DEL | MODE_KEY, chptr->mode.key, 0);
    if (chptr->mode.limit)
      modebuf_mode_uint(&mbuf, MODE_DEL | MODE_LIMIT, chptr->mode.limit);
    if (*chptr->mode.upass)
      modebuf_mode_string(&mbuf, MODE_DEL | MODE_UPASS, chptr->mode.upass, 0);
    if (*chptr->mode.apass)
      modebuf_mode_string(&mbuf, MODE_DEL | MODE_APASS, chptr->mode.apass, 0);
    for (link = chptr->banlist; link; link = link->next)
      modebuf_mode_string(&mbuf, MODE_DEL | MODE_BAN, link->banstr, 0);
    modebuf_flush(&mbuf);
#endif

    return 0;
  }

  /* Pass on DESTRUCT message and ALSO bounce it back! */
  sendcmdto_serv_butone(&me, CMD_DESTRUCT, 0, "%s %Tu", parv[1], chanTS);

  /* Remove the empty channel. */
  if (chptr->destruct_event)
    remove_destruct_event(chptr);
  destruct_channel(chptr);

  return 0;
}
