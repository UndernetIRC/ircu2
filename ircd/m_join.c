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
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if !defined(XXX_BOGUS_TEMP_HACK)
#include "handlers.h"      /* m_names */
#endif

/*
 * m_join - generic message handler
 */
int m_join(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  static char     jbuf[BUFSIZE];
  static char     mbuf[BUFSIZE];
  struct Membership* member;
  struct Channel* chptr;
  char*           name;
  char*           keysOrTS = NULL;
  int             i = 0;
  int             zombie = 0;
  int             sendcreate = 0;
  unsigned int    flags = 0;
  size_t          jlen = 0;
  size_t          mlen = 0;
  size_t*         buflen;
  char*           p = NULL;
  char*           bufptr;

  /*
   * Doesn't make sense having a server join a channel, and besides
   * the server cores.
   */
  if (IsServer(sptr))
    return 0;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  for (p = parv[1]; *p; p++)    /* find the last "JOIN 0" in the line -Kev */
    if (*p == '0'
        && (*(p + 1) == ',' || *(p + 1) == '\0' || !IsChannelChar(*(p + 1))))
    {
      /* If it's a single "0", remember the place; we will start parsing
         the channels after the last 0 in the line -Kev */
      parv[1] = p;
      if (!*(p + 1))
        break;
      p++;
    }
    else
    {                           /* Step through to the next comma or until the
                                   end of the line, in an attempt to save CPU
                                   -Kev */
      while (*p != ',' && *p != '\0')
        p++;
      if (!*p)
        break;
    }

  keysOrTS = parv[2];           /* Remember where our keys are or the TS is;
                                   parv[2] needs to be NULL for the call to
                                   m_names below -Kev */
  parv[2] = p = NULL;

  *jbuf = *mbuf = '\0';         /* clear both join and mode buffers -Kev */
  /*
   *  Rebuild list of channels joined to be the actual result of the
   *  JOIN.  Note that "JOIN 0" is the destructive problem.
   */
  for (name = ircd_strtok(&p, parv[1], ","); name; name = ircd_strtok(&p, NULL, ","))
  {
    size_t len;
    if (MyConnect(sptr))
      clean_channelname(name);
    else if (IsLocalChannel(name))
      continue;
    if (*name == '0' && *(name + 1) == '\0')
    {
      /* Remove the user from all his channels -Kev */
      while ((member = sptr->user->channel))
      {
        chptr = member->channel;
        if (!IsZombie(member))
          sendto_channel_butserv(chptr, sptr, PartFmt2,
              parv[0], chptr->chname, "Left all channels");
        remove_user_from_channel(sptr, chptr);
      }
      /* Just in case */
      *mbuf = *jbuf = '\0';
      mlen = jlen = 0;
    }
    else
    {                           /* not a /join 0, so treat it as
                                   a /join #channel -Kev */
      if (!IsChannelName(name))
      {
        if (MyUser(sptr))
          sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
        continue;
      }

      if (MyConnect(sptr))
      {
#ifdef BADCHAN
        if (bad_channel(name) && !IsAnOper(sptr))
        {
          sendto_one(sptr, err_str(ERR_BANNEDFROMCHAN), me.name, parv[0], name);
          continue;
        }
#endif
        /*
         * Local client is first to enter previously nonexistant
         * channel so make them (rightfully) the Channel Operator.
         * This looks kind of ugly because we try to avoid calling the strlen()
         */
        if (ChannelExists(name))
        {
          flags = CHFL_DEOPPED;
          sendcreate = 0;
        }
        else if (strlen(name) > CHANNELLEN)
        {
          *(name + CHANNELLEN) = '\0';
          if (ChannelExists(name))
          {
            flags = CHFL_DEOPPED;
            sendcreate = 0;
          }
          else
          {
            flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
            sendcreate = 1;
          }
        }
        else
        {
          flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
          sendcreate = 1;
        }

#ifdef OPER_NO_CHAN_LIMIT
        /*
         * Opers are allowed to join any number of channels
         */
        if (sptr->user->joined >= MAXCHANNELSPERUSER && !IsAnOper(sptr))
#else
        if (sptr->user->joined >= MAXCHANNELSPERUSER)
#endif
        {
          chptr = get_channel(sptr, name, CGT_NO_CREATE);
          sendto_one(sptr, err_str(ERR_TOOMANYCHANNELS),
                     me.name, parv[0], chptr ? chptr->chname : name);
          /*
           * Can't return, else he won't get on ANY channels!
           * Break out of the for loop instead.  -Kev
           */
          break;
        }
      }
      chptr = get_channel(sptr, name, CGT_CREATE);
      if (chptr && (member = find_member_link(chptr, sptr)))
      {
        if (IsZombie(member))
        {
          zombie = 1;
          flags = member->status & (CHFL_DEOPPED | CHFL_SERVOPOK);
          remove_user_from_channel(sptr, chptr);
          chptr = get_channel(sptr, name, CGT_CREATE);
        }
        else
          continue;
      }
      name = chptr->chname;
      if (!chptr->creationtime) /* A remote JOIN created this channel ? */
        chptr->creationtime = MAGIC_REMOTE_JOIN_TS;
      if (parc > 2)
      {
        if (chptr->creationtime == MAGIC_REMOTE_JOIN_TS)
          chptr->creationtime = atoi(keysOrTS);
        else
          parc = 2;             /* Don't pass it on */
      }
      if (!zombie)
      {
        if (!MyConnect(sptr))
          flags = CHFL_DEOPPED;
        if (sptr->flags & FLAGS_TS8)
          flags |= CHFL_SERVOPOK;
      }
      if (MyConnect(sptr))
      {
        int created = chptr->users == 0;
        if (check_target_limit(sptr, chptr, chptr->chname, created))
        {
          if (created)          /* Did we create the channel? */
            sub1_from_channel(chptr);   /* Remove it again! */
          continue;
        }
        if ((i = can_join(sptr, chptr, keysOrTS)))
        {
#ifdef OPER_WALK_THROUGH_LMODES
	  if (i > MAGIC_OPER_OVERRIDE)
 	  {
 	    switch(i - MAGIC_OPER_OVERRIDE)
 	    {
 	    case ERR_CHANNELISFULL: i = 'l'; break;
 	    case ERR_INVITEONLYCHAN: i = 'i'; break;
 	    case ERR_BANNEDFROMCHAN: i = 'b'; break;
 	    case ERR_BADCHANNELKEY: i = 'k'; break;
 	    }
 	    sendto_op_mask(SNO_HACK4,"OPER JOIN: %s JOIN %s (overriding +%c)",sptr->name,chptr->chname,i);
 	  }
 	  else
 	  {
            sendto_one(sptr, err_str(i), me.name, parv[0], chptr->chname);
 	    continue;
 	  }
#else	  
          sendto_one(sptr, err_str(i), me.name, parv[0], chptr->chname);
          continue;
#endif
        }
      }
      /*
       * Complete user entry to the new channel (if any)
       */
      add_user_to_channel(chptr, sptr, flags);

      /*
       * Notify all other users on the new channel
       */
      sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);

      if (MyUser(sptr))
      {
        del_invite(sptr, chptr);
        if (chptr->topic[0] != '\0')
        {
          sendto_one(sptr, rpl_str(RPL_TOPIC), me.name,
              parv[0], name, chptr->topic);
          sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0], name,
              chptr->topic_nick, chptr->topic_time);
        }
        parv[1] = name;
        m_names(cptr, sptr, 2, parv);
      }
    }

    /* Select proper buffer; mbuf for creation, jbuf otherwise */

    if (*name == '&')
      continue;                 /* Head off local channels at the pass */

    bufptr = (sendcreate == 0) ? jbuf : mbuf;
    buflen = (sendcreate == 0) ? &jlen : &mlen;
    len = strlen(name);
    if (*buflen < BUFSIZE - len - 2)
    {
      if (*bufptr)
      {
        strcat(bufptr, ",");    /* Add to join buf */
        *buflen += 1;
      }
      strncat(bufptr, name, BUFSIZE - *buflen - 1);
      *buflen += len;
    }
    sendcreate = 0;             /* Reset sendcreate */
  }

  if (*jbuf)                    /* Propgate joins to P10 servers */
    sendto_serv_butone(cptr, 
        parc > 2 ? "%s%s " TOK_JOIN " %s %s" : "%s%s " TOK_JOIN " %s", NumNick(sptr), jbuf, keysOrTS);
  if (*mbuf)                    /* and now creation events */
    sendto_serv_butone(cptr, "%s%s " TOK_CREATE " %s " TIME_T_FMT,
        NumNick(sptr), mbuf, TStime());

  if (MyUser(sptr))
  {                             /* shouldn't ever set TS for remote JOIN's */
    if (*jbuf)
    {                           /* check for channels that need TS's */
      p = NULL;
      for (name = ircd_strtok(&p, jbuf, ","); name; name = ircd_strtok(&p, NULL, ","))
      {
        chptr = get_channel(sptr, name, CGT_NO_CREATE);
        if (chptr && chptr->mode.mode & MODE_SENDTS)
        {                       /* send a TS? */
          sendto_serv_butone(cptr, "%s " TOK_MODE " %s + " TIME_T_FMT, NumServ(&me),
              chptr->chname, chptr->creationtime);      /* ok, send TS */
          chptr->mode.mode &= ~MODE_SENDTS;     /* reset flag */
        }
      }
    }
  }
  return 0;
}

/*
 * ms_join - server message handler
 */
int ms_join(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  static char     jbuf[BUFSIZE];
  static char     mbuf[BUFSIZE];
  struct Membership* member;
  struct Channel* chptr;
  char*           name;
  char*           keysOrTS = NULL;
  int             i = 0;
  int             zombie = 0;
  int             sendcreate = 0;
  unsigned int    flags = 0;
  size_t          jlen = 0;
  size_t          mlen = 0;
  size_t*         buflen;
  char*           p = NULL;
  char*           bufptr;

  /*
   * Doesn't make sense having a server join a channel, and besides
   * the server cores.
   */
  if (IsServer(sptr))
    return 0;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  for (p = parv[1]; *p; p++)    /* find the last "JOIN 0" in the line -Kev */
    if (*p == '0'
        && (*(p + 1) == ',' || *(p + 1) == '\0' || !IsChannelChar(*(p + 1))))
    {
      /* If it's a single "0", remember the place; we will start parsing
         the channels after the last 0 in the line -Kev */
      parv[1] = p;
      if (!*(p + 1))
        break;
      p++;
    }
    else
    {                           /* Step through to the next comma or until the
                                   end of the line, in an attempt to save CPU
                                   -Kev */
      while (*p != ',' && *p != '\0')
        p++;
      if (!*p)
        break;
    }

  keysOrTS = parv[2];           /* Remember where our keys are or the TS is;
                                   parv[2] needs to be NULL for the call to
                                   m_names below -Kev */
  parv[2] = p = NULL;

  *jbuf = *mbuf = '\0';         /* clear both join and mode buffers -Kev */
  /*
   *  Rebuild list of channels joined to be the actual result of the
   *  JOIN.  Note that "JOIN 0" is the destructive problem.
   */
  for (name = ircd_strtok(&p, parv[1], ","); name; name = ircd_strtok(&p, NULL, ","))
  {
    size_t len;
    if (MyConnect(sptr))
      clean_channelname(name);
    else if (IsLocalChannel(name))
      continue;
    if (*name == '0' && *(name + 1) == '\0')
    {
      /* Remove the user from all his channels -Kev */
      while ((member = sptr->user->channel))
      {
        chptr = member->channel;
        if (!IsZombie(member))
          sendto_channel_butserv(chptr, sptr, PartFmt2,
              parv[0], chptr->chname, "Left all channels");
        remove_user_from_channel(sptr, chptr);
      }
      /* Just in case */
      *mbuf = *jbuf = '\0';
      mlen = jlen = 0;
    }
    else
    {                           /* not a /join 0, so treat it as
                                   a /join #channel -Kev */
      if (!IsChannelName(name))
      {
        if (MyUser(sptr))
          sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
        continue;
      }

      if (MyConnect(sptr))
      {
#ifdef BADCHAN
        if (bad_channel(name) && !IsAnOper(sptr))
        {
          sendto_one(sptr, err_str(ERR_BANNEDFROMCHAN), me.name, parv[0], name);
          continue;
        }
#endif
        /*
         * Local client is first to enter previously nonexistant
         * channel so make them (rightfully) the Channel Operator.
         * This looks kind of ugly because we try to avoid calling the strlen()
         */
        if (ChannelExists(name))
        {
          flags = CHFL_DEOPPED;
          sendcreate = 0;
        }
        else if (strlen(name) > CHANNELLEN)
        {
          *(name + CHANNELLEN) = '\0';
          if (ChannelExists(name))
          {
            flags = CHFL_DEOPPED;
            sendcreate = 0;
          }
          else
          {
            flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
            sendcreate = 1;
          }
        }
        else
        {
          flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
          sendcreate = 1;
        }

#ifdef OPER_NO_CHAN_LIMIT
        /*
         * Opers are allowed to join any number of channels
         */
        if (sptr->user->joined >= MAXCHANNELSPERUSER && !IsAnOper(sptr))
#else
        if (sptr->user->joined >= MAXCHANNELSPERUSER)
#endif
        {
          chptr = get_channel(sptr, name, CGT_NO_CREATE);
          sendto_one(sptr, err_str(ERR_TOOMANYCHANNELS),
                     me.name, parv[0], chptr ? chptr->chname : name);
          /*
           * Can't return, else he won't get on ANY channels!
           * Break out of the for loop instead.  -Kev
           */
          break;
        }
      }
      chptr = get_channel(sptr, name, CGT_CREATE);
      if (chptr && (member = find_member_link(chptr, sptr)))
      {
        if (IsZombie(member))
        {
          zombie = 1;
          flags = member->status & (CHFL_DEOPPED | CHFL_SERVOPOK);
          remove_user_from_channel(sptr, chptr);
          chptr = get_channel(sptr, name, CGT_CREATE);
        }
        else
          continue;
      }
      name = chptr->chname;
      if (!chptr->creationtime) /* A remote JOIN created this channel ? */
        chptr->creationtime = MAGIC_REMOTE_JOIN_TS;
      if (parc > 2)
      {
        if (chptr->creationtime == MAGIC_REMOTE_JOIN_TS)
          chptr->creationtime = atoi(keysOrTS);
        else
          parc = 2;             /* Don't pass it on */
      }
      if (!zombie)
      {
        if (!MyConnect(sptr))
          flags = CHFL_DEOPPED;
        if (sptr->flags & FLAGS_TS8)
          flags |= CHFL_SERVOPOK;
      }
      if (MyConnect(sptr))
      {
        int created = chptr->users == 0;
        if (check_target_limit(sptr, chptr, chptr->chname, created))
        {
          if (created)          /* Did we create the channel? */
            sub1_from_channel(chptr);   /* Remove it again! */
          continue;
        }
        if ((i = can_join(sptr, chptr, keysOrTS)))
        {
          sendto_one(sptr, err_str(i), me.name, parv[0], chptr->chname);
          continue;
        }
      }
      /*
       * Complete user entry to the new channel (if any)
       */
      add_user_to_channel(chptr, sptr, flags);

      /*
       * Notify all other users on the new channel
       */
      sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);

      if (MyUser(sptr))
      {
        del_invite(sptr, chptr);
        if (chptr->topic[0] != '\0')
        {
          sendto_one(sptr, rpl_str(RPL_TOPIC), me.name,
              parv[0], name, chptr->topic);
          sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0], name,
              chptr->topic_nick, chptr->topic_time);
        }
        parv[1] = name;
        m_names(cptr, sptr, 2, parv);
      }
    }

    /* Select proper buffer; mbuf for creation, jbuf otherwise */

    if (*name == '&')
      continue;                 /* Head off local channels at the pass */

    bufptr = (sendcreate == 0) ? jbuf : mbuf;
    buflen = (sendcreate == 0) ? &jlen : &mlen;
    len = strlen(name);
    if (*buflen < BUFSIZE - len - 2)
    {
      if (*bufptr)
      {
        strcat(bufptr, ",");    /* Add to join buf */
        *buflen += 1;
      }
      strncat(bufptr, name, BUFSIZE - *buflen - 1);
      *buflen += len;
    }
    sendcreate = 0;             /* Reset sendcreate */
  }

  if (*jbuf)                    /* Propgate joins to P10 servers */
    sendto_serv_butone(cptr, 
        parc > 2 ? "%s%s " TOK_JOIN " %s %s" : "%s%s " TOK_JOIN " %s", NumNick(sptr), jbuf, keysOrTS);
  if (*mbuf)                    /* and now creation events */
    sendto_serv_butone(cptr, "%s%s " TOK_CREATE " %s " TIME_T_FMT,
        NumNick(sptr), mbuf, TStime());

  if (MyUser(sptr))
  {                             /* shouldn't ever set TS for remote JOIN's */
    if (*jbuf)
    {                           /* check for channels that need TS's */
      p = NULL;
      for (name = ircd_strtok(&p, jbuf, ","); name; name = ircd_strtok(&p, NULL, ","))
      {
        chptr = get_channel(sptr, name, CGT_NO_CREATE);
        if (chptr && chptr->mode.mode & MODE_SENDTS)
        {                       /* send a TS? */
          sendto_serv_butone(cptr, "%s " TOK_MODE " %s + " TIME_T_FMT, NumServ(&me),
              chptr->chname, chptr->creationtime);      /* ok, send TS */
          chptr->mode.mode &= ~MODE_SENDTS;     /* reset flag */
        }
      }
    }
  }
  return 0;
}


#if 0
/*
 * m_join
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = channel keys (client), or channel TS (server)
 */
int m_join(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  static char     jbuf[BUFSIZE];
  static char     mbuf[BUFSIZE];
  struct Membership* member;
  struct Channel* chptr;
  char*           name;
  char*           keysOrTS = NULL;
  int             i = 0;
  int             zombie = 0;
  int             sendcreate = 0;
  unsigned int    flags = 0;
  size_t          jlen = 0;
  size_t          mlen = 0;
  size_t*         buflen;
  char*           p = NULL;
  char*           bufptr;

  /*
   * Doesn't make sense having a server join a channel, and besides
   * the server cores.
   */
  if (IsServer(sptr))
    return 0;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "JOIN");

  for (p = parv[1]; *p; p++)    /* find the last "JOIN 0" in the line -Kev */
    if (*p == '0'
        && (*(p + 1) == ',' || *(p + 1) == '\0' || !IsChannelChar(*(p + 1))))
    {
      /* If it's a single "0", remember the place; we will start parsing
         the channels after the last 0 in the line -Kev */
      parv[1] = p;
      if (!*(p + 1))
        break;
      p++;
    }
    else
    {                           /* Step through to the next comma or until the
                                   end of the line, in an attempt to save CPU
                                   -Kev */
      while (*p != ',' && *p != '\0')
        p++;
      if (!*p)
        break;
    }

  keysOrTS = parv[2];           /* Remember where our keys are or the TS is;
                                   parv[2] needs to be NULL for the call to
                                   m_names below -Kev */
  parv[2] = p = NULL;

  *jbuf = *mbuf = '\0';         /* clear both join and mode buffers -Kev */
  /*
   *  Rebuild list of channels joined to be the actual result of the
   *  JOIN.  Note that "JOIN 0" is the destructive problem.
   */
  for (name = ircd_strtok(&p, parv[1], ","); name; name = ircd_strtok(&p, NULL, ","))
  {
    size_t len;
    if (MyConnect(sptr))
      clean_channelname(name);
    else if (IsLocalChannel(name))
      continue;
    if (*name == '0' && *(name + 1) == '\0')
    {
      /* Remove the user from all his channels -Kev */
      while ((member = sptr->user->channel))
      {
        chptr = member->channel;
        if (!IsZombie(member))
          sendto_channel_butserv(chptr, sptr, PartFmt2,
              parv[0], chptr->chname, "Left all channels");
        remove_user_from_channel(sptr, chptr);
      }
      /* Just in case */
      *mbuf = *jbuf = '\0';
      mlen = jlen = 0;
    }
    else
    {                           /* not a /join 0, so treat it as
                                   a /join #channel -Kev */
      if (!IsChannelName(name))
      {
        if (MyUser(sptr))
          sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
        continue;
      }

      if (MyConnect(sptr))
      {
#ifdef BADCHAN
        if (bad_channel(name) && !IsAnOper(sptr))
        {
          sendto_one(sptr, err_str(ERR_BANNEDFROMCHAN), me.name, parv[0], name);
          continue;
        }
#endif
        /*
         * Local client is first to enter previously nonexistant
         * channel so make them (rightfully) the Channel Operator.
         * This looks kind of ugly because we try to avoid calling the strlen()
         */
        if (ChannelExists(name))
        {
          flags = CHFL_DEOPPED;
          sendcreate = 0;
        }
        else if (strlen(name) > CHANNELLEN)
        {
          *(name + CHANNELLEN) = '\0';
          if (ChannelExists(name))
          {
            flags = CHFL_DEOPPED;
            sendcreate = 0;
          }
          else
          {
            flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
            sendcreate = 1;
          }
        }
        else
        {
          flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
          sendcreate = 1;
        }

#ifdef OPER_NO_CHAN_LIMIT
        /*
         * Opers are allowed to join any number of channels
         */
        if (sptr->user->joined >= MAXCHANNELSPERUSER && !IsAnOper(sptr))
#else
        if (sptr->user->joined >= MAXCHANNELSPERUSER)
#endif
        {
          chptr = get_channel(sptr, name, CGT_NO_CREATE);
          sendto_one(sptr, err_str(ERR_TOOMANYCHANNELS),
                     me.name, parv[0], chptr ? chptr->chname : name);
          /*
           * Can't return, else he won't get on ANY channels!
           * Break out of the for loop instead.  -Kev
           */
          break;
        }
      }
      chptr = get_channel(sptr, name, CGT_CREATE);
      if (chptr && (member = find_member_link(chptr, sptr)))
      {
        if (IsZombie(member))
        {
          zombie = 1;
          flags = member->status & (CHFL_DEOPPED | CHFL_SERVOPOK);
          remove_user_from_channel(sptr, chptr);
          chptr = get_channel(sptr, name, CGT_CREATE);
        }
        else
          continue;
      }
      name = chptr->chname;
      if (!chptr->creationtime) /* A remote JOIN created this channel ? */
        chptr->creationtime = MAGIC_REMOTE_JOIN_TS;
      if (parc > 2)
      {
        if (chptr->creationtime == MAGIC_REMOTE_JOIN_TS)
          chptr->creationtime = atoi(keysOrTS);
        else
          parc = 2;             /* Don't pass it on */
      }
      if (!zombie)
      {
        if (!MyConnect(sptr))
          flags = CHFL_DEOPPED;
        if (sptr->flags & FLAGS_TS8)
          flags |= CHFL_SERVOPOK;
      }
      if (MyConnect(sptr))
      {
        int created = chptr->users == 0;
        if (check_target_limit(sptr, chptr, chptr->chname, created))
        {
          if (created)          /* Did we create the channel? */
            sub1_from_channel(chptr);   /* Remove it again! */
          continue;
        }
        if ((i = can_join(sptr, chptr, keysOrTS)))
        {
          sendto_one(sptr, err_str(i), me.name, parv[0], chptr->chname);
#ifdef OPER_WALK_THROUGH_LMODES
	  if (i > MAGIC_OPER_OVERRIDE)
 	  {
 	    switch(i - MAGIC_OPER_OVERRIDE)
 	    {
 	    case ERR_CHANNELISFULL: i = 'l'; break;
 	    case ERR_INVITEONLYCHAN: i = 'i'; break;
 	    case ERR_BANNEDFROMCHAN: i = 'b'; break;
 	    case ERR_BADCHANNELKEY: i = 'k'; break;
 	    }
 	    sendto_op_mask(SNO_HACK4,"OPER JOIN: %s JOIN %s (overriding +%c)",sptr->name,chptr->chname,i);
 	  }
 	  else
 	    continue;	  
#else	  
          continue;
#endif
        }
      }
      /*
       * Complete user entry to the new channel (if any)
       */
      add_user_to_channel(chptr, sptr, flags);

      /*
       * Notify all other users on the new channel
       */
      sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);

      if (MyUser(sptr))
      {
        del_invite(sptr, chptr);
        if (chptr->topic[0] != '\0')
        {
          sendto_one(sptr, rpl_str(RPL_TOPIC), me.name,
              parv[0], name, chptr->topic);
          sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0], name,
              chptr->topic_nick, chptr->topic_time);
        }
        parv[1] = name;
        m_names(cptr, sptr, 2, parv);
      }
    }

    /* Select proper buffer; mbuf for creation, jbuf otherwise */

    if (*name == '&')
      continue;                 /* Head off local channels at the pass */

    bufptr = (sendcreate == 0) ? jbuf : mbuf;
    buflen = (sendcreate == 0) ? &jlen : &mlen;
    len = strlen(name);
    if (*buflen < BUFSIZE - len - 2)
    {
      if (*bufptr)
      {
        strcat(bufptr, ",");    /* Add to join buf */
        *buflen += 1;
      }
      strncat(bufptr, name, BUFSIZE - *buflen - 1);
      *buflen += len;
    }
    sendcreate = 0;             /* Reset sendcreate */
  }

  if (*jbuf)                    /* Propgate joins to P10 servers */
    sendto_serv_butone(cptr, 
        parc > 2 ? "%s%s " TOK_JOIN " %s %s" : "%s%s " TOK_JOIN " %s", NumNick(sptr), jbuf, keysOrTS);
  if (*mbuf)                    /* and now creation events */
    sendto_serv_butone(cptr, "%s%s " TOK_CREATE " %s " TIME_T_FMT,
        NumNick(sptr), mbuf, TStime());

  if (MyUser(sptr))
  {                             /* shouldn't ever set TS for remote JOIN's */
    if (*jbuf)
    {                           /* check for channels that need TS's */
      p = NULL;
      for (name = ircd_strtok(&p, jbuf, ","); name; name = ircd_strtok(&p, NULL, ","))
      {
        chptr = get_channel(sptr, name, CGT_NO_CREATE);
        if (chptr && chptr->mode.mode & MODE_SENDTS)
        {                       /* send a TS? */
          sendto_serv_butone(cptr, "%s " TOK_MODE " %s + " TIME_T_FMT, NumServ(&me),
              chptr->chname, chptr->creationtime);      /* ok, send TS */
          chptr->mode.mode &= ~MODE_SENDTS;     /* reset flag */
        }
      }
    }
  }
  return 0;
}
#endif /* 0 */
