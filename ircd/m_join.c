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
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * Helper function to find last 0 in a comma-separated list of
 * channel names.
 */
static char *
last0(char *chanlist)
{
  char *p;

  for (p = chanlist; p[0]; p++) /* find last "JOIN 0" */
    if (p[0] == '0' && (p[1] == ',' || p[1] == '\0' || !IsChannelChar(p[1]))) {
      chanlist = p; /* we'll start parsing here */

      if (!p[1]) /* hit the end */
	break;

      p++;
    } else {
      while (p[0] != ',' && p[0] != '\0') /* skip past channel name */
	p++;

      if (!p[0]) /* hit the end */
	break;
    }

  return chanlist;
}

/*
 * Helper function to perform a JOIN 0 if needed; returns 0 if channel
 * name is not 0, else removes user from all channels and returns 1.
 */
static int
join0(struct JoinBuf *join, struct Client *cptr, struct Client *sptr,
      char *chan)
{
  struct Membership *member;
  struct JoinBuf part;

  /* is it a JOIN 0? */
  if (chan[0] != '0' || chan[1] != '\0')
    return 0;
  
  joinbuf_join(join, 0, 0); /* join special channel 0 */

  /* leave all channels */
  joinbuf_init(&part, sptr, cptr, JOINBUF_TYPE_PARTALL,
	       "Left all channels", 0);

  while ((member = cli_user(sptr)->channel))
    joinbuf_join(&part, member->channel,
		 IsZombie(member) ? CHFL_ZOMBIE : 0);

  joinbuf_flush(&part);

  return 1;
}

/*
 * m_join - generic message handler
 */
int m_join(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct JoinBuf join;
  struct JoinBuf create;
  struct Gline *gline;
  unsigned int flags = 0;
  int i;
  int j;
  int k = 0;
  char *p = 0;
  char *chanlist;
  char *name;
  char *keys;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  joinbuf_init(&join, sptr, cptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, sptr, cptr, JOINBUF_TYPE_CREATE, 0, TStime());

  chanlist = last0(parv[1]); /* find last "JOIN 0" */

  keys = parv[2]; /* remember where keys are */

  for (name = ircd_strtok(&p, chanlist, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    clean_channelname(name);

    if (join0(&join, cptr, sptr, name)) /* did client do a JOIN 0? */
      continue;

    if (!IsChannelName(name)) { /* bad channel name */
      send_reply(sptr, ERR_NOSUCHCHANNEL, name);
      continue;
    }

    /* This checks if the channel contains control codes and rejects em
     * until they are gone, then we will do it otherwise - *SOB Mode*
     */
    for (k = 0, j = 0; name[j]; j++)
      if (IsCntrl(name[j]))
	k++;

    if ( k > 0 ) {
      send_reply(sptr, ERR_NOSUCHCHANNEL, name);
      continue;
    }

    /* BADCHANed channel */
    if ((gline = gline_find(name, GLINE_BADCHAN | GLINE_EXACT)) &&
	GlineIsActive(gline) && !IsAnOper(sptr)) {
      send_reply(sptr, ERR_BANNEDFROMCHAN, name);
      continue;
    }

    if ((chptr = FindChannel(name))) {
      if (find_member_link(chptr, sptr))
	continue; /* already on channel */

      flags = CHFL_DEOPPED;
    }
    else
      flags = CHFL_CHANOP;

    if (cli_user(sptr)->joined >= feature_int(FEAT_MAXCHANNELSPERUSER) &&
	!HasPriv(sptr, PRIV_CHAN_LIMIT)) {
      send_reply(sptr, ERR_TOOMANYCHANNELS, chptr ? chptr->chname : name);
      break; /* no point processing the other channels */
    }

    if (chptr) {
      if (check_target_limit(sptr, chptr, chptr->chname, 0))
	continue; /* exceeded target limit */
      else if ((i = can_join(sptr, chptr, keys))) {
	if (i > MAGIC_OPER_OVERRIDE) { /* oper overrode mode */
	  switch (i - MAGIC_OPER_OVERRIDE) {
	  case ERR_CHANNELISFULL: /* figure out which mode */
	    i = 'l';
	    break;

	  case ERR_INVITEONLYCHAN:
	    i = 'i';
	    break;

	  case ERR_BANNEDFROMCHAN:
	    i = 'b';
	    break;

	  case ERR_BADCHANNELKEY:
	    i = 'k';
	    break;

	  case ERR_NEEDREGGEDNICK:
	    i = 'r';
	    break;

	  default:
	    i = '?';
	    break;
	  }

	  /* send accountability notice */
	  sendto_opmask_butone(0, SNO_HACK4, "OPER JOIN: %C JOIN %H "
			       "(overriding +%c)", sptr, chptr, i);
	} else {
	  send_reply(sptr, i, chptr->chname);
	  continue;
	}
      } /* else if ((i = can_join(sptr, chptr, keys))) { */

      joinbuf_join(&join, chptr, flags);
    } else if (!(chptr = get_channel(sptr, name, CGT_CREATE)))
      continue; /* couldn't get channel */
    else if (check_target_limit(sptr, chptr, chptr->chname, 1)) {
      /* Note: check_target_limit will only ever return 0 here */
      sub1_from_channel(chptr); /* created it... */
      continue;
    } else
      joinbuf_join(&create, chptr, flags);

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

/*
 * ms_join - server message handler
 */
int ms_join(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Membership *member;
  struct Channel *chptr;
  struct JoinBuf join;
  unsigned int flags = 0;
  time_t creation = 0;
  char *p = 0;
  char *chanlist;
  char *name;

  if (IsServer(sptr)) {
    return protocol_violation(cptr,
	"%s tried to JOIN %s, duh!",
	cli_name(sptr),
	(parc < 2 || *parv[1] == '\0') ? "a channel":parv[1]
	);
  }

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  if (parc > 2 && parv[2])
    creation = atoi(parv[2]);

  joinbuf_init(&join, sptr, cptr, JOINBUF_TYPE_JOIN, 0, 0);

  chanlist = last0(parv[1]); /* find last "JOIN 0" */

  for (name = ircd_strtok(&p, chanlist, ","); name;
       name = ircd_strtok(&p, 0, ",")) {

    if (join0(&join, cptr, sptr, name)) /* did client do a JOIN 0? */
      continue;

    if (IsLocalChannel(name) || !IsChannelName(name)) {
      protocol_violation(cptr,"%s tried to join %s",cli_name(sptr),name);
      continue;
    }

    if (!(chptr = FindChannel(name))) {
      /* No channel exists, so create one */
      if (!(chptr = get_channel(sptr, name, CGT_CREATE))) {
        protocol_violation(sptr,"couldn't get channel %s for %s",
        		   name,cli_name(sptr));
      	continue;
      }
      flags = CHFL_DEOPPED | (HasFlag(sptr, FLAG_TS8) ? CHFL_SERVOPOK : 0);

      /* when the network is 2.10.11+ then remove MAGIC_REMOTE_JOIN_TS */ 
      chptr->creationtime = creation ? creation : MAGIC_REMOTE_JOIN_TS;
    }
    else { /* We have a valid channel? */
      if ((member = find_member_link(chptr, sptr))) {
	if (!IsZombie(member)) /* already on channel */
	  continue;

	flags = member->status & (CHFL_DEOPPED | CHFL_SERVOPOK);
	remove_user_from_channel(sptr, chptr);
	chptr = FindChannel(name);
      } else
	flags = CHFL_DEOPPED | (HasFlag(sptr, FLAG_TS8) ? CHFL_SERVOPOK : 0);
    } 

    joinbuf_join(&join, chptr, flags);
  }

  joinbuf_flush(&join); /* flush joins... */

  return 0;
}
