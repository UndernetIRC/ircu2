/*
 * IRC - Internet Relay Chat, ircd/m_names.c
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
#include "s_user.h"
#include "send.h"
 
#include <assert.h>
#include <string.h>

#define NAMES_ALL 1 /* List all users in channel */
#define NAMES_VIS 2 /* List only visible users in non-secret channels */

/*
 *  Sends a suitably formatted 'names' reply to 'sptr' consisting of nicks within
 *  'chptr', depending on 'filter'.
 *
 *  NAMES_ALL - Lists all users on channel.
 *  NAMES_VIS - Only list visible (-i) users. --Gte (04/06/2000).
 *
 */

void do_names(struct Client* sptr, struct Channel* chptr, int filter)
{ 
  int mlen;
  int idx;
  int flag;
  int needs_space; 
  int len; 
  char buf[BUFSIZE];
  struct Client *c2ptr;
  struct Membership* member;

  /* Tag Pub/Secret channels accordingly. */

  strcpy(buf, "* ");
  if (PubChannel(chptr))
    *buf = '=';
  else if (SecretChannel(chptr))
    *buf = '@';
 
  len = strlen(chptr->chname);
  strcpy(buf + 2, chptr->chname);
  strcpy(buf + 2 + len, " :");

  idx = len + 4;
  flag = 1;
  needs_space = 0;

  if (!ShowChannel(sptr, chptr)) /* Don't list private channels unless we are on them. */
    return;

  /* Iterate over all channel members, and build up the list. */

  mlen = strlen(me.name) + 10 + strlen(sptr->name);
  
  for (member = chptr->members; member; member = member->next_member)
  {
    c2ptr = member->user;

    if ((filter == NAMES_VIS) && IsInvisible(c2ptr))
      continue;

    if (needs_space) {
    	strcat(buf, " ");
      idx++;
    }
    needs_space=1;
    if (IsZombie(member))
    {
      if (member->user != sptr)
        continue;
      else
      {
        strcat(buf, "!");
        idx++;
      }
    }
    else if (IsChanOp(member))
    {
      strcat(buf, "@");
      idx++;
    }
    else if (HasVoice(member))
    {
      strcat(buf, "+");
      idx++;
    }
    strcat(buf, c2ptr->name);
    idx += strlen(c2ptr->name) + 1;
    flag = 1;
    if (mlen + idx + NICKLEN + 5 > BUFSIZE)
      /* space, modifier, nick, \r \n \0 */
    {
      send_reply(sptr, RPL_NAMREPLY, buf);
      strcpy(buf, "* ");
      ircd_strncpy(buf + 2, chptr->chname, len + 1);
      buf[len + 2] = 0;
      strcat(buf, " :");
      if (PubChannel(chptr))
        *buf = '=';
      else if (SecretChannel(chptr))
        *buf = '@';
      idx = len + 4;
      flag = 0;
      needs_space=0;
    }
  }
  if (flag)
    send_reply(sptr, RPL_NAMREPLY, buf); 
}

/*
 * m_names - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 */

int m_names(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr; 
  struct Channel *ch2ptr; 
  struct Client *c2ptr;
  struct Membership* member; 
  char* s;
  char* para = parc > 1 ? parv[1] : 0; 

  if (parc > 2 && hunt_server_cmd(sptr, CMD_NAMES, cptr, 1, "%s %C", 2, parc,
				  parv))
    return 0; 

  if (EmptyString(para))
    return 0;
  else if (*para == '0')
    *para = '\0';
  
  s = strchr(para, ','); /* Recursively call m_names for each comma-seperated channel. */
  if (s) {
    parv[1] = ++s;
    m_names(cptr, sptr, parc, parv);
  }
 
  /*
   * Special Case 1: "/names 0". 
   * Full list as per RFC. 
   */

  if (!*para) { 
    int idx; 
    int mlen;
    int flag;
    struct Channel *ch3ptr;
    char buf[BUFSIZE]; 

    mlen = strlen(me.name) + 10 + strlen(sptr->name);

    /* List all visible channels/visible members */ 

    for (ch2ptr = GlobalChannelList; ch2ptr; ch2ptr = ch2ptr->next)
    { 
      if (!ShowChannel(sptr, ch2ptr))
        continue;                 /* Don't show secret chans. */ 

      if (find_channel_member(sptr, ch2ptr))
      {
        do_names(sptr, ch2ptr, NAMES_ALL); /* Full list if we're in this chan. */
      } else { 
        do_names(sptr, ch2ptr, NAMES_VIS);
      }
    } 

    /* List all remaining users on channel '*' */

    strcpy(buf, "* * :");
    idx = 5;
    flag = 0;

    for (c2ptr = GlobalClientList; c2ptr; c2ptr = c2ptr->next)
    {
      int showflag = 0;

      if (!IsUser(c2ptr) || (sptr != c2ptr && IsInvisible(c2ptr)))
        continue;

      member = c2ptr->user->channel; 

      while (member)
      {
        ch3ptr = member->channel;
  
        if (PubChannel(ch3ptr) || find_channel_member(sptr, ch3ptr))
          showflag = 1;
 
        member = member->next_channel;
      }

      if (showflag)               /* Have we already shown them? */
        continue;
 
      strcat(buf, c2ptr->name);
      strcat(buf, " ");
      idx += strlen(c2ptr->name) + 1;
      flag = 1;

      if (mlen + idx + NICKLEN + 3 > BUFSIZE)     /* space, \r\n\0 */
      {
        send_reply(sptr, RPL_NAMREPLY, buf);
        strcpy(buf, "* * :");
        idx = 5;
        flag = 0;
      }
    }
    if (flag)
      send_reply(sptr, RPL_NAMREPLY, buf);
    send_reply(sptr, RPL_ENDOFNAMES, "*");
    return 1; 
  } 

  /*
   *  Special Case 2: User is on this channel, requesting full names list.
   *  (As performed with each /join) - ** High frequency usage **
   */

  clean_channelname(para);
  chptr = FindChannel(para); 
 
  member = find_member_link(chptr, sptr); 
  if (member)
  { 
    if (chptr) do_names(sptr, chptr, NAMES_ALL);
    if (!EmptyString(para))
    {
      send_reply(sptr, RPL_ENDOFNAMES, chptr ? chptr->chname : para);
      return 1;
    }

  }
    else
  {
    /*
     *  Special Case 3: User isn't on this channel, show all visible users, in 
     *  non secret channels.
     */
     
    if (chptr) do_names(sptr, chptr, NAMES_VIS);
    if (!EmptyString(para))
    {
      send_reply(sptr, RPL_ENDOFNAMES, para);
      return 1;
    }
  }
  return 1;
}

 
/*
 * ms_names - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 */
int ms_names(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr; 
  struct Channel *ch2ptr; 
  struct Client *c2ptr;
  struct Membership* member; 
  char* s;
  char* para = parc > 1 ? parv[1] : 0; 

  if (parc > 2 && hunt_server_cmd(sptr, CMD_NAMES, cptr, 1, "%s %C", 2, parc,
				  parv))
    return 0; 

  if (EmptyString(para))
    return 0;
  else if (*para == '0')
    *para = '\0';
  
  s = strchr(para, ','); /* Recursively call m_names for each comma-seperated channel. */
  if (s) {
    parv[1] = ++s;
    m_names(cptr, sptr, parc, parv);
  }
 
  /*
   * Special Case 1: "/names 0".
   * Full list as per RFC. 
   */

  if (!*para) { 
    int idx; 
    int mlen;
    int flag;
    struct Channel *ch3ptr;
    char buf[BUFSIZE]; 

    mlen = strlen(me.name) + 10 + strlen(sptr->name);

    /* List all visible channels/visible members */ 

    for (ch2ptr = GlobalChannelList; ch2ptr; ch2ptr = ch2ptr->next)
    { 
      if (!ShowChannel(sptr, ch2ptr))
        continue;                 /* Don't show secret chans. */ 

      if (find_channel_member(sptr, ch2ptr))
      {
        do_names(sptr, ch2ptr, NAMES_ALL); /* Full list if we're in this chan. */
      } else { 
        do_names(sptr, ch2ptr, NAMES_VIS);
      }
    } 
 
    /* List all remaining users on channel '*' */

    strcpy(buf, "* * :");
    idx = 5;
    flag = 0;

    for (c2ptr = GlobalClientList; c2ptr; c2ptr = c2ptr->next)
    {
      int showflag = 0;

      if (!IsUser(c2ptr) || (sptr != c2ptr && IsInvisible(c2ptr)))
        continue;

      member = c2ptr->user->channel; 

      while (member)
      {
        ch3ptr = member->channel;
  
        if (PubChannel(ch3ptr) || find_channel_member(sptr, ch3ptr))
          showflag = 1;
 
        member = member->next_channel;
      }

      if (showflag)               /* Have we already shown them? */
        continue;
 
      strcat(buf, c2ptr->name);
      strcat(buf, " ");
      idx += strlen(c2ptr->name) + 1;
      flag = 1;

      if (mlen + idx + NICKLEN + 3 > BUFSIZE)     /* space, \r\n\0 */
      {
        send_reply(sptr, RPL_NAMREPLY, buf);
        strcpy(buf, "* * :");
        idx = 5;
        flag = 0;
      }
    }
    if (flag)
      send_reply(sptr, RPL_NAMREPLY, buf);
    send_reply(sptr, RPL_ENDOFNAMES, "*");
    return 1; 
  } 

  /*
   *  Special Case 2: User is on this channel, requesting full names list.
   *  (As performed with each /join) - ** High frequency usage **
   */

  clean_channelname(para);
  chptr = FindChannel(para); 
 
  member = find_member_link(chptr, sptr); 
  if (member)
  { 
    if (chptr) do_names(sptr, chptr, NAMES_ALL);
    if (!EmptyString(para))
    {
      send_reply(sptr, RPL_ENDOFNAMES, chptr ? chptr->chname : para);
      return 1;
    }

  }
    else
  {
    /*
     *  Special Case 3: User isn't on this channel, show all visible users, in 
     *  non secret channels.
     */
     
    if (chptr) do_names(sptr, chptr, NAMES_VIS);
    if (!EmptyString(para))
    {
      send_reply(sptr, RPL_ENDOFNAMES, para);
      return 1;
    }
  } 
  return 1;
}
 

#if 0
/*
 * m_names                              - Added by Jto 27 Apr 1989
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 */
int m_names(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct Client *c2ptr;
  struct Membership* member;
  struct Channel *ch2ptr = 0;
  int idx, flag, len, mlen;
  char *s, *para = parc > 1 ? parv[1] : 0;
  char buf[BUFSIZE];

  if (parc > 2 && hunt_server(1, cptr, sptr, "%s%s " TOK_NAMES " %s %s", 2, parc, parv)) /* XXX DEAD */
    return 0;

  mlen = strlen(me.name) + 10 + strlen(sptr->name);

  if (!EmptyString(para))
  {
    s = strchr(para, ',');
    if (s)
    {
      parv[1] = ++s;
      m_names(cptr, sptr, parc, parv);
    }
    clean_channelname(para);
    ch2ptr = FindChannel(para);
  }

  /*
   * First, do all visible channels (public and the one user self is)
   */

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
  {
    if ((chptr != ch2ptr) && !EmptyString(para))
      continue;                 /* -- wanted a specific channel */
    if (!MyConnect(sptr) && EmptyString(para))
      continue;
#ifndef GODMODE
    if (!ShowChannel(sptr, chptr))
      continue;                 /* -- users on this are not listed */
#endif

    /* Find users on same channel (defined by chptr) */

    strcpy(buf, "* ");
    len = strlen(chptr->chname);
    strcpy(buf + 2, chptr->chname);
    strcpy(buf + 2 + len, " :");

    if (PubChannel(chptr))
      *buf = '=';
    else if (SecretChannel(chptr))
      *buf = '@';
    idx = len + 4;
    flag = 1;
    for (member = chptr->members; member; member = member->next_member)
    {
      c2ptr = member->user;
#ifndef GODMODE
      if (sptr != c2ptr && IsInvisible(c2ptr) && !find_channel_member(sptr, chptr))
        continue;
#endif
      if (IsZombie(member))
      {
        if (member->user != sptr)
          continue;
        else
        {
          strcat(buf, "!");
          idx++;
        }
      }
      else if (IsChanOp(member))
      {
        strcat(buf, "@");
        idx++;
      }
      else if (HasVoice(member))
      {
        strcat(buf, "+");
        idx++;
      }
      strcat(buf, c2ptr->name);
      strcat(buf, " ");
      idx += strlen(c2ptr->name) + 1;
      flag = 1;
#ifdef GODMODE
      {
        char yxx[6];
        sprintf_irc(yxx, "%s%s", NumNick(c2ptr));
        assert(c2ptr == findNUser(yxx));
        sprintf_irc(buf + strlen(buf), "(%s) ", yxx);
        idx += 6;
      }
      if (mlen + idx + NICKLEN + 11 > BUFSIZE)
#else
      if (mlen + idx + NICKLEN + 5 > BUFSIZE)
#endif
        /* space, modifier, nick, \r \n \0 */
      {
        sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf); /* XXX DEAD */
        strcpy(buf, "* ");
        ircd_strncpy(buf + 2, chptr->chname, len + 1);
        buf[len + 2] = 0;
        strcat(buf, " :");
        if (PubChannel(chptr))
          *buf = '=';
        else if (SecretChannel(chptr))
          *buf = '@';
        idx = len + 4;
        flag = 0;
      }
    }
    if (flag)
      sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf); /* XXX DEAD */
  }
  if (!EmptyString(para))
  {
    sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], /* XXX DEAD */
        ch2ptr ? ch2ptr->chname : para);
    return (1);
  }

  /* Second, do all non-public, non-secret channels in one big sweep */

  strcpy(buf, "* * :");
  idx = 5;
  flag = 0;
  for (c2ptr = GlobalClientList; c2ptr; c2ptr = c2ptr->next)
  {
    struct Channel *ch3ptr;
    int showflag = 0, secret = 0;

#ifndef GODMODE
    if (!IsUser(c2ptr) || (sptr != c2ptr && IsInvisible(c2ptr)))
#else
    if (!IsUser(c2ptr))
#endif
      continue;
    member = c2ptr->user->channel;
    /*
     * Don't show a client if they are on a secret channel or when
     * they are on a channel sptr is on since they have already
     * been show earlier. -avalon
     */
    while (member)
    {
      ch3ptr = member->channel;
#ifndef GODMODE
      if (PubChannel(ch3ptr) || find_channel_member(sptr, ch3ptr))
#endif
        showflag = 1;
      if (SecretChannel(ch3ptr))
        secret = 1;
      member = member->next_channel;
    }
    if (showflag)               /* Have we already shown them ? */
      continue;
#ifndef GODMODE
    if (secret)                 /* On any secret channels ? */
      continue;
#endif
    strcat(buf, c2ptr->name);
    strcat(buf, " ");
    idx += strlen(c2ptr->name) + 1;
    flag = 1;
#ifdef GODMODE
    {
      char yxx[6];
      sprintf_irc(yxx, "%s%s", NumNick(c2ptr));
      assert(c2ptr == findNUser(yxx));
      sprintf_irc(buf + strlen(buf), "(%s) ", yxx);
      idx += 6;
    }
#endif
#ifdef GODMODE
    if (mlen + idx + NICKLEN + 9 > BUFSIZE)
#else
    if (mlen + idx + NICKLEN + 3 > BUFSIZE)     /* space, \r\n\0 */
#endif
    {
      sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf); /* XXX DEAD */
      strcpy(buf, "* * :");
      idx = 5;
      flag = 0;
    }
  }
  if (flag)
    sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf); /* XXX DEAD */
  sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], "*"); /* XXX DEAD */
  return 1;
}
#endif /* 0 */

