/*
 * IRC - Internet Relay Chat, ircd/m_kick.c
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
 * m_kick - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[parc-1] = kick comment
 */
int m_kick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client*  who;
  struct Channel* chptr;
  struct Membership* member = 0;
  char*           channel_name;

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 3 || *parv[1] == '\0')
    return need_more_params(sptr, "KICK");

  channel_name = parv[1];

  if (IsLocalChannel(channel_name) && !MyUser(sptr))
    return 0;

  if (IsModelessChannel(channel_name)) {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
               channel_name);
    return 0;
  }

  chptr = get_channel(sptr, channel_name, CGT_NO_CREATE);
  if (!chptr) {
    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], channel_name);
    return 0;
  }

  if (!IsServer(cptr) && !is_chan_op(sptr, chptr)) {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
               me.name, parv[0], chptr->chname);
    return 0;
  }

  if (MyUser(sptr)) {
    if (!(who = find_chasing(sptr, parv[2], 0)))
      return 0;                 /* No such user left! */
  }
  else if (!(who = findNUser(parv[2])))
    return 0;                   /* No such user left! */

  /*
   * if the user is +k, prevent a kick from local user
   */
  if (IsChannelService(who) && MyUser(sptr)) {
    sendto_one(sptr, err_str(ERR_ISCHANSERVICE), me.name,
        parv[0], who->name, chptr->chname);
    return 0;
  }

#ifdef NO_OPER_DEOP_LCHAN
  /*
   * Prevent kicking opers from local channels -DM-
   */
  if (IsOperOnLocalChannel(who, chptr->chname)) {
    sendto_one(sptr, err_str(ERR_ISOPERLCHAN), me.name,
               parv[0], who->name, chptr->chname);
    return 0;
  }
#endif

  /* 
   * Servers can now send kicks without hacks during a netburst - they
   * are kicking users from a +i channel.
   *  - Isomer 25-11-1999
   */
  if (IsServer(sptr)
#if defined(NO_INVITE_NETRIDE)
      && !IsBurstOrBurstAck(sptr)
#endif
     ) {
    send_hack_notice(cptr, sptr, parc, parv, 1, 3);
  }

  if (IsServer(sptr) ||
      ((member = find_member_link(chptr, who)) && !IsZombie(member)))
  {
    struct Membership* sptr_link = find_member_link(chptr, sptr);
    if (who->from != cptr &&
        ((sptr_link && IsDeopped(sptr_link)) || (!sptr_link && IsUser(sptr))))
    {
      /*
       * Bounce here:
       * cptr must be a server (or cptr == sptr and
       * sptr->flags can't have DEOPPED set
       * when CHANOP is set).
       */
      sendto_one(cptr, "%s%s " TOK_JOIN " %s", NumNick(who), chptr->chname);
      if (IsChanOp(member))
      {
         sendto_one(cptr, "%s " TOK_MODE " %s +o %s%s " TIME_T_FMT,
              NumServ(&me), chptr->chname, NumNick(who), chptr->creationtime);
      }
      if (HasVoice(member))
      {
         sendto_one(cptr, "%s " TOK_MODE " %s +v %s%s " TIME_T_FMT,
              NumServ(&me), chptr->chname, NumNick(who), chptr->creationtime);
      }
    }
    else
    {
      char* comment = (EmptyString(parv[parc - 1])) ? parv[0] : parv[parc - 1];
      if (strlen(comment) > TOPICLEN)
        comment[TOPICLEN] = '\0';

      if (!IsLocalChannel(channel_name))
      {
        sendto_highprot_butone(cptr, 10, "%s%s " TOK_KICK " %s %s%s :%s",
            NumNick(sptr), chptr->chname, NumNick(who), comment);
      }
      if (member) {
        sendto_channel_butserv(chptr, sptr,
            ":%s KICK %s %s :%s", parv[0], chptr->chname, who->name, comment);
        make_zombie(member, who, cptr, sptr, chptr);
      }
    }
  }
  else if (MyUser(sptr))
    sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
        me.name, parv[0], who->name, chptr->chname);

  return 0;
}

/*
 * ms_kick - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[parc-1] = kick comment
 */
int ms_kick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client*  who;
  struct Channel* chptr;
  struct Membership* member = 0;
  char*           channel_name;

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 3 || *parv[1] == '\0')
    return need_more_params(sptr, "KICK");

  channel_name = parv[1];

  if (IsLocalChannel(channel_name) && !MyUser(sptr))
    return 0;

  if (IsModelessChannel(channel_name)) {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
               channel_name);
    return 0;
  }

  chptr = get_channel(sptr, channel_name, CGT_NO_CREATE);
  if (!chptr) {
    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], channel_name);
    return 0;
  }

  if (!IsServer(cptr) && !is_chan_op(sptr, chptr)) {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
               me.name, parv[0], chptr->chname);
    return 0;
  }

  if (MyUser(sptr)) {
    if (!(who = find_chasing(sptr, parv[2], 0)))
      return 0;                 /* No such user left! */
  }
  else if (!(who = findNUser(parv[2])))
    return 0;                   /* No such user left! */

  /*
   * if the user is +k, prevent a kick from local user
   */
  if (IsChannelService(who) && MyUser(sptr)) {
    sendto_one(sptr, err_str(ERR_ISCHANSERVICE), me.name,
        parv[0], who->name, chptr->chname);
    return 0;
  }

#ifdef NO_OPER_DEOP_LCHAN
  /*
   * Prevent kicking opers from local channels -DM-
   */
  if (IsOperOnLocalChannel(who, chptr->chname)) {
    sendto_one(sptr, err_str(ERR_ISOPERLCHAN), me.name,
               parv[0], who->name, chptr->chname);
    return 0;
  }
#endif

#if defined(NO_INVITE_NETRIDE)
  /* 
   * Servers can now send kicks without hacks during a netburst - they
   * are kicking users from a +i channel.
   *  - Isomer 25-11-1999
   */
  if (IsServer(sptr) && !IsBurstOrBurstAck(sptr)) {
#else
  if (IsServer(sptr)) {
#endif
    send_hack_notice(cptr, sptr, parc, parv, 1, 3);
  }

  if (IsServer(sptr) ||
      ((member = find_member_link(chptr, who)) && !IsZombie(member)))
  {
    struct Membership* sptr_link = find_member_link(chptr, sptr);
    if (who->from != cptr &&
        ((sptr_link && IsDeopped(sptr_link)) || (!sptr_link && IsUser(sptr))))
    {
      /*
       * Bounce here:
       * cptr must be a server (or cptr == sptr and
       * sptr->flags can't have DEOPPED set
       * when CHANOP is set).
       */
      sendto_one(cptr, "%s%s " TOK_JOIN " %s", NumNick(who), chptr->chname);
      if (IsChanOp(member))
      {
         sendto_one(cptr, "%s " TOK_MODE " %s +o %s%s " TIME_T_FMT,
              NumServ(&me), chptr->chname, NumNick(who), chptr->creationtime);
      }
      if (HasVoice(member))
      {
         sendto_one(cptr, "%s " TOK_MODE " %s +v %s%s " TIME_T_FMT,
              NumServ(&me), chptr->chname, NumNick(who), chptr->creationtime);
      }
    }
    else
    {
      char* comment = (EmptyString(parv[parc - 1])) ? parv[0] : parv[parc - 1];
      if (strlen(comment) > TOPICLEN)
        comment[TOPICLEN] = '\0';

      if (!IsLocalChannel(channel_name)) {
        if (IsServer(sptr)) {
          sendto_highprot_butone(cptr, 10, "%s " TOK_KICK " %s %s%s :%s",
                                 NumServ(sptr), chptr->chname, NumNick(who),
                                 comment);
        }
        else {
          sendto_highprot_butone(cptr, 10, "%s%s " TOK_KICK " %s %s%s :%s",
                                 NumNick(sptr), chptr->chname, NumNick(who),
                                 comment);
        }
      }
      if (member) {
        sendto_channel_butserv(chptr, sptr,
            ":%s KICK %s %s :%s", parv[0], chptr->chname, who->name, comment);
        make_zombie(member, who, cptr, sptr, chptr);
      }
    }
  }
  else if (MyUser(sptr))
    sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
        me.name, parv[0], who->name, chptr->chname);

  return 0;
}


#if 0
/*
 * m_kick
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[parc-1] = kick comment
 */
int m_kick(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client*  who;
  struct Channel* chptr;
  struct Membership* member = 0;
  char*           channel_name;

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 3 || *parv[1] == '\0')
    return need_more_params(sptr, "KICK");

  channel_name = parv[1];

  if (IsLocalChannel(channel_name) && !MyUser(sptr))
    return 0;

  if (IsModelessChannel(channel_name)) {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
               channel_name);
    return 0;
  }

  chptr = get_channel(sptr, channel_name, CGT_NO_CREATE);
  if (!chptr) {
    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], channel_name);
    return 0;
  }

  if (!IsServer(cptr) && !is_chan_op(sptr, chptr)) {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
               me.name, parv[0], chptr->chname);
    return 0;
  }

  if (MyUser(sptr)) {
    if (!(who = find_chasing(sptr, parv[2], 0)))
      return 0;                 /* No such user left! */
  }
  else if (!(who = findNUser(parv[2])))
    return 0;                   /* No such user left! */

  /*
   * if the user is +k, prevent a kick from local user
   */
  if (IsChannelService(who) && MyUser(sptr)) {
    sendto_one(sptr, err_str(ERR_ISCHANSERVICE), me.name,
        parv[0], who->name, chptr->chname);
    return 0;
  }

#ifdef NO_OPER_DEOP_LCHAN
  /*
   * Prevent kicking opers from local channels -DM-
   */
  if (IsOperOnLocalChannel(who, chptr->chname)) {
    sendto_one(sptr, err_str(ERR_ISOPERLCHAN), me.name,
               parv[0], who->name, chptr->chname);
    return 0;
  }
#endif

  /* 
   * Servers can now send kicks without hacks during a netburst - they
   * are kicking users from a +i channel.
   *  - Isomer 25-11-1999
   */
  if (IsServer(sptr)
#if defined(NO_INVITE_NETRIDE)
      && !IsBurstOrBurstAck(sptr)
#endif
     ) {
    send_hack_notice(cptr, sptr, parc, parv, 1, 3);
  }

  if (IsServer(sptr) ||
      ((member = find_member_link(chptr, who)) && !IsZombie(member)))
  {
    struct Membership* sptr_link = find_member_link(chptr, sptr);
    if (who->from != cptr &&
        ((sptr_link && IsDeopped(sptr_link)) || (!sptr_link && IsUser(sptr))))
    {
      /*
       * Bounce here:
       * cptr must be a server (or cptr == sptr and
       * sptr->flags can't have DEOPPED set
       * when CHANOP is set).
       */
      sendto_one(cptr, "%s%s " TOK_JOIN " %s", NumNick(who), chptr->chname);
      if (IsChanOp(member))
      {
         sendto_one(cptr, "%s " TOK_MODE " %s +o %s%s " TIME_T_FMT,
              NumServ(&me), chptr->chname, NumNick(who), chptr->creationtime);
      }
      if (HasVoice(member))
      {
         sendto_one(cptr, "%s " TOK_MODE " %s +v %s%s " TIME_T_FMT,
              NumServ(&me), chptr->chname, NumNick(who), chptr->creationtime);
      }
    }
    else
    {
      char* comment = (EmptyString(parv[parc - 1])) ? parv[0] : parv[parc - 1];
      if (strlen(comment) > TOPICLEN)
        comment[TOPICLEN] = '\0';

      if (!IsLocalChannel(channel_name))
      {
        sendto_highprot_butone(cptr, 10, "%s%s " TOK_KICK " %s %s%s :%s",
            NumNick(sptr), chptr->chname, NumNick(who), comment);
      }
      if (member) {
        sendto_channel_butserv(chptr, sptr,
            ":%s KICK %s %s :%s", parv[0], chptr->chname, who->name, comment);
        make_zombie(member, who, cptr, sptr, chptr);
      }
    }
  }
  else if (MyUser(sptr))
    sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
        me.name, parv[0], who->name, chptr->chname);

  return 0;
}
#endif /* 0 */

