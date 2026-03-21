/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
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

/** @file
 * @brief Handlers for TAGMSG command (IRCv3 message-tags).
 * @version $Id$
 */

#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_messagetags.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle TAGMSG from local clients.
 * @param[in] cptr Client that sent the command.
 * @param[in] sptr Original source of the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameter array. parv[1] = tags, parv[2] = target
 */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *tags;
  char *target;
  int too_long;
  struct Channel *chptr;
  struct Client *acptr;

  if (!ircd_parse_message_tags(sptr, parc, parv, &tags, &target, 0, 1, 0))
    return need_more_params(sptr, "TAGMSG");

  /* Check if capability is negotiated */
  if (!feature_bool(FEAT_CAP_MESSAGETAGS) || !CapActive(sptr, CAP_MESSAGETAGS))
    return 0;

  if (!ircd_sanitize_message_tags(&tags, 1, 1, 1, &too_long)) {
    if (too_long)
      return send_reply(sptr, ERR_INPUTTOOLONG);
    return 0;
  }

  /* Apply per-client TAGMSG rate limiting for local users */
  if (MyUser(sptr)) {
    time_t now = CurrentTime;
    int win = feature_int(FEAT_TAGMSG_WINDOW_SECONDS);
    int max = feature_int(FEAT_TAGMSG_MAX_PER_WINDOW);
    
    if (win < 1) win = 1; /* safety */
    if (max < 1) max = 1;
    
    if (cli_tagmsg_window(sptr) + win > now) {
      /* same window */
      if (cli_tagmsg_count(sptr) + 1 > (unsigned int)max) {
        /* Silently drop excess TAGMSG */
        return 0;
      }
      cli_tagmsg_count(sptr)++;
    } else {
      /* start a new window */
      cli_tagmsg_window(sptr) = now;
      cli_tagmsg_count(sptr) = 1;
    }
  }

  /* Find target */
  if (IsChannelName(target)) {
    if (!(chptr = FindChannel(target)))
      return 0; /* No such channel */

    /* Check permissions */
    if (!client_can_send_to_channel(sptr, chptr, 0))
      return 0;

    sendcmdto_capflag_channel_butserv_butone_tagged(sptr, CMD_TAGMSG, chptr,
                                                    cptr, 0,
                                                    CAP_MESSAGETAGS, 0,
                                                    tags, "%H", chptr);
    sendcmdto_channel_servers_butone_tagged(sptr, CMD_TAGMSG, chptr, cptr, 0,
                                            tags, "%H", chptr);
  } else {
    if (!(acptr = FindUser(target)))
      return 0; /* No such nick */

    /* Check if silenced */
    if (is_silenced(sptr, acptr))
      return 0;

    if (!MyConnect(acptr) || CapActive(acptr, CAP_MESSAGETAGS))
      sendcmdto_one_tagged(sptr, CMD_TAGMSG, acptr, tags, "%C", acptr);
  }

  return 0;
}

/** Handle TAGMSG from servers.
 * @param[in] cptr Client that sent the command.
 * @param[in] sptr Original source of the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameter array. parv[1] = tags, parv[2] = target
 */
int ms_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  struct Client *acptr;
  char *tags;
  char *target;
  int too_long;

  if (!ircd_parse_message_tags(sptr, parc, parv, &tags, &target, 0, 1, 0))
    return 0;

  if (!ircd_sanitize_message_tags(&tags, 0, 0, 1, &too_long))
    return 0;

  if (!feature_bool(FEAT_CAP_MESSAGETAGS))
    return 0;

  /* Find target and forward */
  if (IsChannelName(target)) {
    if ((chptr = FindChannel(target)))
    {
      sendcmdto_capflag_channel_butserv_butone_tagged(sptr, CMD_TAGMSG, chptr,
                                                      cptr, 0,
                                                      CAP_MESSAGETAGS, 0,
                                                      tags, "%H", chptr);
      sendcmdto_channel_servers_butone_tagged(sptr, CMD_TAGMSG, chptr, cptr, 0,
                                              tags, "%H", chptr);
    }
  } else {
    if ((acptr = findNUser(target)))
      if (!MyConnect(acptr) || CapActive(acptr, CAP_MESSAGETAGS))
        sendcmdto_one_tagged(sptr, CMD_TAGMSG, acptr, tags, "%C", acptr);
  }

  return 0;
}
