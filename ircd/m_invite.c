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
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle an INVITE from a local client.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the nickname of the client to invite
 * \li \a parv[2] is the name of the channel to invite \a parv[1] to
 *
 * - INVITE now is accepted only if who does it is chanop (this of course
 *   implies that channel must exist and he must be on it).
 *
 * - On the other side it IS processed even if channel is NOT invite only
 *   leaving room for other enhancements like inviting banned ppl.  -- Nemesi
 *
 * - Invite with no parameters now lists the channels you are invited to.
 *                                                         - Isomer 23 Oct 99
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_invite(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;

  if (parc < 2 ) {
    /*
     * list the channels you have an invite to.
     */
    struct Invite *ip;
    for (ip = cli_user(sptr)->invited; ip; ip = ip->next_user)
      send_reply(cptr, RPL_INVITELIST, ip->channel->chname);
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

  if (!IsChannelName(parv[2])
      || !strIsIrcCh(parv[2])
      || !(chptr = FindChannel(parv[2]))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, parv[2]);
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

  if (MyConnect(acptr)) {
    add_invite(acptr, chptr, sptr);
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s %H", cli_name(acptr), chptr);
  } else if (!IsLocalChannel(chptr->chname)) {
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s %H %Tu", cli_name(acptr), chptr,
                  chptr->creationtime);
  }

  return 0;
}

/** Handle an INVITE from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the nickname of the client to invite
 * \li \a parv[2] is the name of the channel to invite \a parv[1] to
 * \li \a parv[3] (optional) is the channel's timestamp
 *
 * - INVITE now is accepted only if who does it is chanop (this of course
 *   implies that channel must exist and he must be on it).
 *
 * - On the other side it IS processed even if channel is NOT invite only
 *   leaving room for other enhancements like inviting banned ppl.  -- Nemesi
 *
 * - Invite with no parameters now lists the channels you are invited to.
 *                                                         - Isomer 23 Oct 99
 *
 * - Invite with too-late timestamp, or with no timestamp from a bursting
 *   server, is silently discarded.                   - Entrope 19 Jan 05
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_invite(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  time_t invite_ts;
  
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
  if (!IsGlobalChannel(parv[2])) {
    /*
     * should not be sent
     */
    return protocol_violation(sptr, "Invite to a non-standard channel %s",parv[2]);
  }
  if (!(acptr = FindUser(parv[1]))) {
    send_reply(sptr, ERR_NOSUCHNICK, parv[1]);
    return 0;
  }

  if (!(chptr = FindChannel(parv[2]))) {
    /*
     * allow invites to non existent channels, bleah
     * avoid JOIN, INVITE, PART abuse
     */
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%C :%s", acptr, parv[2]);
    return 0;
  }

  if (parc > 3) {
    invite_ts = atoi(parv[3]);
    if (invite_ts > chptr->creationtime)
      return 0;
  } else if (IsBurstOrBurstAck(cptr))
    return 0;

  if (!IsChannelService(sptr) && !find_channel_member(sptr, chptr)) {
    send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
    return 0;
  }

  if (find_channel_member(acptr, chptr)) {
    send_reply(sptr, ERR_USERONCHANNEL, cli_name(acptr), chptr->chname);
    return 0;
  }

  if (is_silenced(sptr, acptr))
    return 0;

  if (MyConnect(acptr)) {
    add_invite(acptr, chptr, sptr);
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s %H", cli_name(acptr), chptr);
  } else {
    sendcmdto_one(sptr, CMD_INVITE, acptr, "%s %H %Tu", cli_name(acptr), chptr,
                  chptr->creationtime);
  }

  return 0;
}
