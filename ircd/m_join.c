/*
 * IRC - Internet Relay Chat, ircd/m_join.c
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

#include "config.h"

#include "channel.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Searches for and handles a 0 in a join list.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] chanlist List of channels to join.
 * @return First token in \a chanlist after the final 0 entry, which
 * may be its nul terminator (if the final entry is a 0 entry).
 */
static char *
last0(struct Client *cptr, struct Client *sptr, char *chanlist)
{
  char *p;
  int join0 = 0;

  for (p = chanlist; p[0]; p++) /* find last "JOIN 0" */
    if (p[0] == '0' && (p[1] == ',' || p[1] == '\0' || !IsChannelChar(p[1]))) {
      if (*++p == ',')
        p++;
      chanlist = p;
      join0 = 1;
    } else {
      while (p[0] != ',' && p[0] != '\0') /* skip past channel name */
	p++;

      if (!p[0]) /* hit the end */
	break;
    }

  if (join0) {
    struct JoinBuf part;
    struct Membership *member;

    joinbuf_init(&part, sptr, cptr, JOINBUF_TYPE_PARTALL,
                 "Left all channels", 0);

    joinbuf_join(&part, 0, 0);

    while ((member = cli_user(sptr)->channel))
      joinbuf_join(&part, member->channel,
                   IsZombie(member) ? CHFL_ZOMBIE :
                   IsDelayedJoin(member) ? CHFL_DELAYED :
                   0);

    joinbuf_flush(&part);
  }

  return chanlist;
}

/** Handle a JOIN message from a client connection.
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_join(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct JoinBuf join;
  struct JoinBuf create;
  struct Gline *gline;
  char *p = 0;
  char *chanlist;
  char *name;
  char *keys;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  joinbuf_init(&join, sptr, cptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, sptr, cptr, JOINBUF_TYPE_CREATE, 0, TStime());

  chanlist = last0(cptr, sptr, parv[1]); /* find last "JOIN 0" */

  keys = parv[2]; /* remember where keys are */

  for (name = ircd_strtok(&p, chanlist, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    char *key = 0;

    /* If we have any more keys, take the first for this channel. */
    if (!BadPtr(keys)
        && (keys = strchr(key = keys, ',')))
      *keys++ = '\0';

    /* Empty keys are the same as no keys. */
    if (key && !key[0])
      key = 0;

    if (!IsChannelName(name) || !strIsIrcCh(name))
    {
      /* bad channel name */
      send_reply(sptr, ERR_NOSUCHCHANNEL, name);
      continue;
    }

    if (cli_user(sptr)->joined >= feature_int(FEAT_MAXCHANNELSPERUSER)
	&& !HasPriv(sptr, PRIV_CHAN_LIMIT)) {
      send_reply(sptr, ERR_TOOMANYCHANNELS, name);
      break; /* no point processing the other channels */
    }

    /* BADCHANed channel */
    if ((gline = gline_find(name, GLINE_BADCHAN | GLINE_EXACT)) &&
	GlineIsActive(gline) && !IsAnOper(sptr)) {
      send_reply(sptr, ERR_BANNEDFROMCHAN, name);
      continue;
    }

    if (!(chptr = FindChannel(name))) {
      if ((name[0] == '&') && !feature_bool(FEAT_LOCAL_CHANNELS)) {
        send_reply(sptr, ERR_NOSUCHCHANNEL, name);
        continue;
      }

      if (!(chptr = get_channel(sptr, name, CGT_CREATE)))
        continue;

      /* Try to add the new channel as a recent target for the user. */
      if (check_target_limit(sptr, chptr, chptr->chname, 1)) {
        chptr->members = 0;
        destruct_channel(chptr);
        continue;
      }

      joinbuf_join(&create, chptr, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
    } else if (find_member_link(chptr, sptr)) {
      continue; /* already on channel */
    } else if (check_target_limit(sptr, chptr, chptr->chname, 0)) {
      continue;
    } else {
      int flags = CHFL_DEOPPED;
      int err = 0;

      /* Check target change limits. */

      /* Check Apass/Upass -- since we only ever look at a single
       * "key" per channel now, this hampers brute force attacks. */
      if (key && !strcmp(key, chptr->mode.apass))
        flags = CHFL_CHANOP | CHFL_CHANNEL_MANAGER;
      else if (key && !strcmp(key, chptr->mode.upass))
        flags = CHFL_CHANOP;
      else if (IsInvited(sptr, chptr)) {
        /* Invites bypass these other checks. */
      } else if (chptr->mode.mode & MODE_INVITEONLY)
        err = ERR_INVITEONLYCHAN;
      else if (chptr->mode.limit && (chptr->users >= chptr->mode.limit))
        err = ERR_CHANNELISFULL;
      else if ((chptr->mode.mode & MODE_REGONLY) && !IsAccount(sptr))
        err = ERR_NEEDREGGEDNICK;
      else if (find_ban(sptr, chptr->banlist))
        err = ERR_BANNEDFROMCHAN;
      else if (*chptr->mode.key && (!key || strcmp(key, chptr->mode.key)))
        err = ERR_BADCHANNELKEY;

      /* An oper with WALK_LCHAN privilege can join a local channel
       * he otherwise could not join by using "OVERRIDE" as the key.
       * This will generate a HACK(4) notice, but fails if the oper
       * could normally join the channel. */
      if (IsLocalChannel(chptr->chname)
          && HasPriv(sptr, PRIV_WALK_LCHAN)
          && !(flags & CHFL_CHANOP)
          && key && !strcmp(key, "OVERRIDE")
          && strcmp(chptr->mode.key, "OVERRIDE"))
      {
        switch (err) {
        case 0:
          send_reply(sptr, ERR_DONTCHEAT, chptr->chname);
          continue;
        case ERR_INVITEONLYCHAN: err = 'i'; break;
        case ERR_CHANNELISFULL:  err = 'l'; break;
        case ERR_BANNEDFROMCHAN: err = 'b'; break;
        case ERR_BADCHANNELKEY:  err = 'k'; break;
        case ERR_NEEDREGGEDNICK: err = 'r'; break;
        default: err = '?'; break;
        }
        /* send accountability notice */
        sendto_opmask_butone(0, SNO_HACK4, "OPER JOIN: %C JOIN %H "
                             "(overriding +%c)", sptr, chptr, err);
        err = 0;
      }

      /* Is there some reason the user may not join? */
      if (err) {
        send_reply(sptr, err, chptr->chname);
        continue;
      }

      joinbuf_join(&join, chptr, flags);
    }

    del_invite(sptr, chptr);

    if (chptr->topic[0]) {
      send_reply(sptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(sptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
		 chptr->topic_time);
    }

    do_names(sptr, chptr, NAMES_ALL|NAMES_EON); /* send /names list */
  }

  joinbuf_flush(&join); /* must be first, if there's a JOIN 0 */
  joinbuf_flush(&create);

  return 0;
}

/** Handle a JOIN message from a server connection.
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_join(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Membership *member;
  struct Channel *chptr;
  struct JoinBuf join;
  unsigned int flags;
  time_t creation = 0;
  char *p = 0;
  char *chanlist;
  char *name;

  if (IsServer(sptr))
  {
    return protocol_violation(cptr,
                              "%s tried to JOIN %s, duh!",
                              cli_name(sptr),
                              (parc < 2 || *parv[1] == '\0') ? "a channel" :
                                                               parv[1]
                              );
  }

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  if (parc > 2 && parv[2])
    creation = atoi(parv[2]);

  joinbuf_init(&join, sptr, cptr, JOINBUF_TYPE_JOIN, 0, 0);

  chanlist = last0(cptr, sptr, parv[1]); /* find last "JOIN 0" */

  for (name = ircd_strtok(&p, chanlist, ","); name;
       name = ircd_strtok(&p, 0, ",")) {

    if (name[0] == '0' && name[1] == ':')
    {
      flags = CHFL_CHANOP | CHFL_CHANNEL_MANAGER;
      name += 2;
    }
    else if (name[0] == '1' && name[1] == ':')
    {
      flags = CHFL_CHANOP;
      name += 2;
    }
    else
      flags = CHFL_DEOPPED;

    if (IsLocalChannel(name) || !IsChannelName(name))
    {
      protocol_violation(cptr, "%s tried to join %s", cli_name(sptr), name);
      continue;
    }

    if (!(chptr = FindChannel(name)))
    {
      /* No channel exists, so create one */
      if (!(chptr = get_channel(sptr, name, CGT_CREATE)))
      {
        protocol_violation(sptr,"couldn't get channel %s for %s",
        		   name,cli_name(sptr));
      	continue;
      }
      flags |= HasFlag(sptr, FLAG_TS8) ? CHFL_SERVOPOK : 0;

      /* when the network is 2.10.11+ then remove MAGIC_REMOTE_JOIN_TS */
      chptr->creationtime = creation ? creation : MAGIC_REMOTE_JOIN_TS;
    }
    else { /* We have a valid channel? */
      if ((member = find_member_link(chptr, sptr)))
      {
	/* It is impossible to get here --Run */
	if (!IsZombie(member)) /* already on channel */
	  continue;

	flags = member->status & (CHFL_DEOPPED | CHFL_SERVOPOK);
	remove_user_from_channel(sptr, chptr);
	chptr = FindChannel(name);
      }
      else
        flags |= HasFlag(sptr, FLAG_TS8) ? CHFL_SERVOPOK : 0;
      /* Always copy the timestamp when it is older, that is the only way to
         ensure network-wide synchronization of creation times. */
      if (creation && creation < chptr->creationtime)
	chptr->creationtime = creation;
    }

    joinbuf_join(&join, chptr, flags);
  }

  joinbuf_flush(&join); /* flush joins... */

  return 0;
}
