/*
 * IRC - Internet Relay Chat, ircd/m_topic.c
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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
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
 * m_topic - generic message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = channel
 * parv[parc - 1] = topic (if parc > 2)
 */
int m_topic(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char *topic = 0, *name, *p = 0;

  if (parc < 2)
    return need_more_params(sptr, "TOPIC");

  if (parc > 2)
    topic = parv[parc - 1];

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = 0;
    if (!IsChannelName(name) || !(chptr = FindChannel(name)) ||
        ((topic || SecretChannel(chptr)) && !find_channel_member(sptr, chptr)))
    {
      send_reply(sptr, (chptr ? ERR_NOTONCHANNEL : ERR_NOSUCHCHANNEL),
		 chptr ? chptr->chname : name);
      continue;
    }
    if (IsModelessChannel(name))
    {
      send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
      continue;
    }
    if (IsLocalChannel(name) && !MyUser(sptr))
      continue;

    if (!topic)                 /* only asking  for topic  */
    {
      if (chptr->topic[0] == '\0')
	send_reply(sptr, RPL_NOTOPIC, chptr->chname);
      else
      {
	send_reply(sptr, RPL_TOPIC, chptr->chname, chptr->topic);
	send_reply(sptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
		   chptr->topic_time);
      }
    }
    else if (((chptr->mode.mode & MODE_TOPICLIMIT) == 0 ||
        is_chan_op(sptr, chptr)) && topic)
    {
      /* setting a topic */
      ircd_strncpy(chptr->topic, topic, TOPICLEN);
      ircd_strncpy(chptr->topic_nick, sptr->name, NICKLEN);
      chptr->topic_time = CurrentTime;
      sendcmdto_serv_butone(sptr, CMD_TOPIC, cptr, "%H :%s", chptr,
			    chptr->topic);
      sendcmdto_channel_butserv(sptr, CMD_TOPIC, chptr, "%H :%s", chptr,
				chptr->topic);
    }
    else
      send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
  }
  return 0;
}

/*
 * ms_topic - server message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = channel
 * parv[parc - 1] = topic (if parc > 2)
 */
int ms_topic(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char *topic = 0, *name, *p = 0;

  if (parc < 2)
    return need_more_params(sptr, "TOPIC");

  if (parc > 2)
    topic = parv[parc - 1];

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = 0;
    if (!IsChannelName(name) || !(chptr = FindChannel(name)) ||
        ((topic || SecretChannel(chptr)) && !find_channel_member(sptr, chptr)))
    {
      send_reply(sptr, (chptr ? ERR_NOTONCHANNEL : ERR_NOSUCHCHANNEL),
		 chptr ? chptr->chname : name);
      continue;
    }
    if (IsModelessChannel(name))
    {
      send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
      continue;
    }
    if (IsLocalChannel(name) && !MyUser(sptr))
      continue;

    if (!topic)                 /* only asking  for topic  */
    {
      if (chptr->topic[0] == '\0')
	send_reply(sptr, RPL_NOTOPIC, chptr->chname);
      else
      {
	send_reply(sptr, RPL_TOPIC, chptr->chname, chptr->topic);
	send_reply(sptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
		   chptr->topic_time);
      }
    }
    else if (((chptr->mode.mode & MODE_TOPICLIMIT) == 0 ||
        is_chan_op(sptr, chptr)) && topic)
    {
      /* setting a topic */
      ircd_strncpy(chptr->topic, topic, TOPICLEN);
      ircd_strncpy(chptr->topic_nick, sptr->name, NICKLEN);
      chptr->topic_time = CurrentTime;
      sendcmdto_serv_butone(sptr, CMD_TOPIC, cptr, "%H :%s", chptr,
			    chptr->topic);
      sendcmdto_channel_butserv(sptr, CMD_TOPIC, chptr, "%H :%s", chptr,
				chptr->topic);
    }
    else
      send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
  }
  return 0;
}


#if 0
/*
 * m_topic
 *
 * parv[0]        = sender prefix
 * parv[1]        = channel
 * parv[parc - 1] = topic (if parc > 2)
 */
int m_topic(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  char *topic = 0, *name, *p = 0;

  if (parc < 2)
    return need_more_params(sptr, "TOPIC");

  if (parc > 2)
    topic = parv[parc - 1];

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = 0;
    if (!IsChannelName(name) || !(chptr = FindChannel(name)) ||
        ((topic || SecretChannel(chptr)) && !find_channel_member(sptr, chptr)))
    {
      sendto_one(sptr, err_str(chptr ? ERR_NOTONCHANNEL : ERR_NOSUCHCHANNEL), /* XXX DEAD */
          me.name, parv[0], chptr ? chptr->chname : name);
      continue;
    }
    if (IsModelessChannel(name))
    {
      sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0], /* XXX DEAD */
          chptr->chname);
      continue;
    }
    if (IsLocalChannel(name) && !MyUser(sptr))
      continue;

    if (!topic)                 /* only asking  for topic  */
    {
      if (chptr->topic[0] == '\0')
        sendto_one(sptr, rpl_str(RPL_NOTOPIC), me.name, parv[0], chptr->chname); /* XXX DEAD */
      else
      {
        sendto_one(sptr, rpl_str(RPL_TOPIC), /* XXX DEAD */
            me.name, parv[0], chptr->chname, chptr->topic);
        sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), /* XXX DEAD */
            me.name, parv[0], chptr->chname,
            chptr->topic_nick, chptr->topic_time);
      }
    }
    else if (((chptr->mode.mode & MODE_TOPICLIMIT) == 0 ||
        is_chan_op(sptr, chptr)) && topic)
    {
      /* setting a topic */
      ircd_strncpy(chptr->topic, topic, TOPICLEN);
      ircd_strncpy(chptr->topic_nick, sptr->name, NICKLEN);
      chptr->topic_time = CurrentTime;
      sendto_serv_butone(cptr, "%s%s " TOK_TOPIC " %s :%s", /* XXX DEAD */
          NumNick(sptr), chptr->chname, chptr->topic);
      sendto_channel_butserv(chptr, sptr, ":%s TOPIC %s :%s", /* XXX DEAD */
          parv[0], chptr->chname, chptr->topic);
    }
    else
      sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), /* XXX DEAD */
          me.name, parv[0], chptr->chname);
  }
  return 0;
}
#endif /* 0 */

