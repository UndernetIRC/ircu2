/*
 * IRC - Internet Relay Chat, ircd/m_invite.c
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
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <assert.h>

/*
 * m_invite - generic message handler
 *
 *   parv[0] - sender prefix
 *   parv[1] - user to invite
 *   parv[2] - channel name
 *
 * - INVITE now is accepted only if who does it is chanop (this of course
 *   implies that channel must exist and he must be on it).
 *
 * - On the other side it IS processed even if channel is NOT invite only
 *   leaving room for other enhancements like inviting banned ppl.  -- Nemesi
 *
 * - Invite with no parameters now lists the channels you are invited to.
 *                                                         - Isomer 23 Oct 99
 */
int m_invite(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  
  if (parc < 2 ) { 
    /*
     * list the channels you have an invite to.
     */
    struct SLink *lp;
    for (lp = cli_user(sptr)->invited; lp; lp = lp->next)
      send_reply(cptr, RPL_INVITELIST, lp->value.chptr->chname);
    send_reply(cptr, RPL_ENDOFINVITELIST);
    return 0;
  }
  
  if (parc < 3 || EmptyString(parv[2]))
    return need_more_params(sptr, "INVITE");

  if (!(acptr = FindUser(parv[1]))) {
    send_reply(sptr, ERR_NOSUCHNICK, parv[1]);
    return 0;
  }

  if (is_silenced(sptr, acptr))
    return 0;

  clean_channelname(parv[2]);

  if (!IsChannelPrefix(*parv[2]))
    return 0;

  if (!(chptr = FindChannel(parv[2]))) {
    if (IsLocalChannel(parv[2])) {
      send_reply(sptr, ERR_NOTONCHANNEL, parv[2]);
      return 0;
    }

    /* Do not disallow to invite to non-existant #channels, otherwise they
       would simply first be created, causing only MORE bandwidth usage. */

    if (check_target_limit(sptr, acptr, cli_name(acptr), 0))
      return 0;

    send_reply(sptr, RPL_INVITING, cli_name(acptr), parv[2]);

    if (cli_user(acptr)->away)
      send_reply(sptr, RPL_AWAY, cli_name(acptr), cli_user(acptr)->away);

    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s :%s", cli_name(acptr), parv[2]);

    return 0;
  }

  if (!find_channel_member(sptr, chptr)) {
    send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
    return 0;
  }

  if (find_channel_member(acptr, chptr)) {
    send_reply(sptr, ERR_USERONCHANNEL, cli_name(acptr), chptr->chname);
    return 0;
  }

  if (!is_chan_op(sptr, chptr)) {
    send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
    return 0;
  }

  /* If we get here, it was a VALID and meaningful INVITE */

  if (check_target_limit(sptr, acptr, cli_name(acptr), 0))
    return 0;

  send_reply(sptr, RPL_INVITING, cli_name(acptr), chptr->chname);

  if (cli_user(acptr)->away)
    send_reply(sptr, RPL_AWAY, cli_name(acptr), cli_user(acptr)->away);

  if (MyConnect(acptr))
    add_invite(acptr, chptr);

  if (!IsLocalChannel(chptr->chname) || MyConnect(acptr))
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s :%H", cli_name(acptr), chptr);

  return 0;
}

/*
 * ms_invite - server message handler
 *
 *   parv[0] - sender prefix
 *   parv[1] - user to invite
 *   parv[2] - channel name
 *
 * - INVITE now is accepted only if who does it is chanop (this of course
 *   implies that channel must exist and he must be on it).
 *
 * - On the other side it IS processed even if channel is NOT invite only
 *   leaving room for other enhancements like inviting banned ppl.  -- Nemesi
 *
 * - Invite with no parameters now lists the channels you are invited to.
 *                                                         - Isomer 23 Oct 99
 */
int ms_invite(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  
  if (IsServer(sptr)) {
    /*
     * this will blow up if we get an invite from a server
     * we look for channel membership in sptr below. 
     */
    return protocol_violation(sptr,"Server attempting to invite");
  }
  if (parc < 3 || EmptyString(parv[2])) {
    /*
     * should have been handled upstream, ignore it.
     */
    protocol_violation(sptr,"Too few arguments to invite");
    return need_more_params(sptr,"INVITE");
  }
  if ('#' != *parv[2]) {
    /*
     * should not be sent
     */
    return protocol_violation(sptr, "Invite to a non-standard channel %s",parv[2]);
  }
  if (!(acptr = FindUser(parv[1]))) {
    send_reply(sptr, ERR_NOSUCHNICK, parv[1]);
    return 0;
  }
  if (!MyUser(acptr)) {
    /*
     * just relay the message
     */
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s :%s", cli_name(acptr), parv[2]);
    return 0;
  }

  if (is_silenced(sptr, acptr))
    return 0;

  if (!(chptr = FindChannel(parv[2]))) {
    /*
     * allow invites to non existant channels, bleah
     * avoid JOIN, INVITE, PART abuse
     */
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%C :%s", acptr, parv[2]);
    return 0;
  }

  if (!find_channel_member(sptr, chptr)) {
    send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
    return 0;
  }
  if (find_channel_member(acptr, chptr)) {
    send_reply(sptr, ERR_USERONCHANNEL, cli_name(acptr), chptr->chname);
    return 0;
  }
  add_invite(acptr, chptr);
  sendcmdto_one(sptr, CMD_INVITE, acptr, "%s :%H", cli_name(acptr), chptr);
  return 0;
}


