/*
 * IRC - Internet Relay Chat, ircd/m_whois.c
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
#include "ircd_policy.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "whocmds.h"

#include <assert.h>
#include <string.h>

/*
 * m_whois - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server
 * parv[2] = nickname masklist
 */
int m_whois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct User*    user;
  struct Client*  acptr;
  struct Client*  a2cptr;
  struct Channel* chptr;
  char*           nick;
  char*           tmp;
  char*           name;
  char*           p = 0;
  int             found;
  int             len;
  int             mlen;
  int             total;
  static char     buf[512];

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, parv[0]);
    return 0;
  }

  if (parc > 2)
  {
    struct Client *acptr;
    /* For convenience: Accept a nickname as first parameter, by replacing
       it with the correct servername - as is needed by hunt_server() */
#if HEAD_IN_SAND_REMOTE
    /* If remote queries are disabled, then use the *second* parameter of
     * of whois, so /whois nick nick still works.
     */
    if (MyUser(sptr) && (acptr = FindUser(parv[2])))
#else
    if (MyUser(sptr) && (acptr = FindUser(parv[1])))
#endif
      parv[1] = acptr->user->server->name;

    if (hunt_server(0, cptr, sptr, "%s%s " TOK_WHOIS " %s :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  total = 0;
  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    int invis, showperson, member, wilds;

    found = 0;
    collapse(nick);
    wilds = (strchr(nick, '?') || strchr(nick, '*'));
    /* Do a hash lookup if the nick does not contain wilds */
    if (wilds)
    {
      /*
       * We're no longer allowing remote users to generate requests with wildcards.
       */
      if (!MyConnect(sptr))
        continue;
      for (acptr = GlobalClientList; (acptr = next_client(acptr, nick));
          acptr = acptr->next)
      {
        if (!IsRegistered(acptr) || IsServer(acptr))
          continue;
        /*
         * I'm always last :-) and acptr->next == 0!!
         */
        if (IsMe(acptr))
          break;
        /*
         * 'Rules' established for sending a WHOIS reply:
         *
         * - if wildcards are being used dont send a reply if
         *   the querier isnt any common channels and the
         *   client in question is invisible and wildcards are
         *   in use (allow exact matches only);
         *
         * - only send replies about common or public channels
         *   the target user(s) are on;
         */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;

        invis = acptr != sptr && IsInvisible(acptr);
        member = (user && user->channel) ? 1 : 0;
        showperson = (wilds && !invis && !member) || !wilds;
        if (user) {
          struct Membership* chan;
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            member = find_channel_member(sptr, chptr) ? 1 : 0;
            if (invis && !member)
              continue;
            if (IsZombie(chan))
              continue;
            if (member || (!invis && PubChannel(chptr)))
            {
              showperson = 1;
              break;
            }
            if (!invis && HiddenChannel(chptr) && !SecretChannel(chptr))
              showperson = 1;
          }
        }
        if (!showperson)
          continue;

        if (user)
        {
          a2cptr = user->server;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, user->username, user->host, acptr->info);
        }
        else
        {
          a2cptr = &me;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, "<unknown>", "<unknown>", "<unknown>");
        }

        found = 1;

exact_match:
        if (user && !IsChannelService(acptr))
        {
          struct Membership* chan;
          mlen = strlen(me.name) + strlen(parv[0]) + 12 + strlen(name);
          len = 0;
          *buf = '\0';
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            if (ShowChannel(sptr, chptr) &&
                (acptr == sptr || !IsZombie(chan)))
            {
              if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5)
              {
                sendto_one(sptr, ":%s %d %s %s :%s",
                    me.name, RPL_WHOISCHANNELS, parv[0], name, buf);
                *buf = '\0';
                len = 0;
              }
              if (IsDeaf(acptr))
                *(buf + len++) = '-';
              if (is_chan_op(acptr, chptr))
                *(buf + len++) = '@';
              else if (has_voice(acptr, chptr))
                *(buf + len++) = '+';
              else if (IsZombie(chan))
                *(buf + len++) = '!';
              if (len)
                *(buf + len) = '\0';
              strcpy(buf + len, chptr->chname);
              len += strlen(chptr->chname);
              strcat(buf + len, " ");
              len++;
            }
          }
          if (buf[0] != '\0')
            sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS),
                me.name, parv[0], name, buf);
        }

#ifdef HEAD_IN_SAND_WHOIS_SERVERNAME
        if (!IsAnOper(sptr) && sptr != acptr)
	  sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name,
	      parv[0], name, "*.undernet.org","The Undernet Underworld");
        else
#endif
          sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name,
              parv[0], name, a2cptr->name, a2cptr->info);
        if (user)
        {
          if (user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
                parv[0], name, user->away);

          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
                me.name, parv[0], name);

#ifdef HEAD_IN_SAND_IDLETIME
          if (MyConnect(acptr) && (IsAnOper(sptr) || parc>=3))
#else
          if (MyConnect(acptr))
#endif
            sendto_one(sptr, rpl_str(RPL_WHOISIDLE), me.name,
                parv[0], name, CurrentTime - user->last, acptr->firsttime);
        }
        if (found == 2 || total++ >= MAX_WHOIS_LINES)
          break;
      }
    }
    else
    {
      /* No wildcards */
      if ((acptr = FindUser(nick)))
      {
        found = 2;              /* Make sure we exit the loop after passing it once */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;
        a2cptr = user->server;
        sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
            parv[0], name, user->username, user->host, acptr->info);
        goto exact_match;
      }
    }
    if (!found)
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
    if (p)
      p[-1] = ',';
    if (!MyConnect(sptr) || total >= MAX_WHOIS_LINES)
      break;
  }
  sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);

  return 0;
}

/*
 * ms_whois - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server
 * parv[2] = nickname masklist
 */
int ms_whois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct User*    user;
  struct Client*  acptr;
  struct Client*  a2cptr;
  struct Channel* chptr;
  char*           nick;
  char*           tmp;
  char*           name;
  char*           p = 0;
  int             found;
  int             len;
  int             mlen;
  int             total;
  static char     buf[512];

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, parv[0]);
    return 0;
  }

  if (parc > 2)
  {
    struct Client *acptr;
    /* For convenience: Accept a nickname as first parameter, by replacing
       it with the correct servername - as is needed by hunt_server() */
    if (MyUser(sptr) && (acptr = FindUser(parv[1])))
      parv[1] = acptr->user->server->name;
    if (hunt_server(0, cptr, sptr, "%s%s " TOK_WHOIS " %s :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  total = 0;
  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    int invis, showperson, member, wilds;

    found = 0;
    collapse(nick);
    wilds = (strchr(nick, '?') || strchr(nick, '*'));
    /* Do a hash lookup if the nick does not contain wilds */
    if (wilds)
    {
      /*
       * We're no longer allowing remote users to generate requests with wildcards.
       */
      if (!MyConnect(sptr))
        continue;
      for (acptr = GlobalClientList; (acptr = next_client(acptr, nick));
          acptr = acptr->next)
      {
        if (!IsRegistered(acptr) || IsServer(acptr))
          continue;
        /*
         * I'm always last :-) and acptr->next == 0!!
         */
        if (IsMe(acptr))
          break;
        /*
         * 'Rules' established for sending a WHOIS reply:
         *
         * - if wildcards are being used dont send a reply if
         *   the querier isnt any common channels and the
         *   client in question is invisible and wildcards are
         *   in use (allow exact matches only);
         *
         * - only send replies about common or public channels
         *   the target user(s) are on;
         */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;

        invis = acptr != sptr && IsInvisible(acptr);
        member = (user && user->channel) ? 1 : 0;
        showperson = (wilds && !invis && !member) || !wilds;
        if (user) {
          struct Membership* chan;
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            member = find_channel_member(sptr, chptr) ? 1 : 0;
            if (invis && !member)
              continue;
            if (IsZombie(chan))
              continue;
            if (member || (!invis && PubChannel(chptr)))
            {
              showperson = 1;
              break;
            }
            if (!invis && HiddenChannel(chptr) && !SecretChannel(chptr))
              showperson = 1;
          }
        }
        if (!showperson)
          continue;

        if (user)
        {
          a2cptr = user->server;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, user->username, user->host, acptr->info);
        }
        else
        {
          a2cptr = &me;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, "<unknown>", "<unknown>", "<unknown>");
        }

        found = 1;

exact_match:
        if (user && !IsChannelService(acptr))
        {
          struct Membership* chan;
          mlen = strlen(me.name) + strlen(parv[0]) + 12 + strlen(name);
          len = 0;
          *buf = '\0';
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            if (ShowChannel(sptr, chptr) &&
                (acptr == sptr || !IsZombie(chan)))
            {
              if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5)
              {
                sendto_one(sptr, ":%s %d %s %s :%s",
                    me.name, RPL_WHOISCHANNELS, parv[0], name, buf);
                *buf = '\0';
                len = 0;
              }
              if (IsDeaf(acptr))
                *(buf + len++) = '-';
              if (is_chan_op(acptr, chptr))
                *(buf + len++) = '@';
              else if (has_voice(acptr, chptr))
                *(buf + len++) = '+';
              else if (IsZombie(chan))
                *(buf + len++) = '!';
              if (len)
                *(buf + len) = '\0';
              strcpy(buf + len, chptr->chname);
              len += strlen(chptr->chname);
              strcat(buf + len, " ");
              len++;
            }
          }
          if (buf[0] != '\0')
            sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS),
                me.name, parv[0], name, buf);
        }

        sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name,
            parv[0], name, a2cptr->name, a2cptr->info);

        if (user)
        {
          if (user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
                parv[0], name, user->away);

          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
                me.name, parv[0], name);

          if (MyConnect(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISIDLE), me.name,
                parv[0], name, CurrentTime - user->last, acptr->firsttime);
        }
        if (found == 2 || total++ >= MAX_WHOIS_LINES)
          break;
      }
    }
    else
    {
      /* No wildcards */
      if ((acptr = FindUser(nick)))
      {
        found = 2;              /* Make sure we exit the loop after passing it once */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;
        a2cptr = user->server;
        sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
            parv[0], name, user->username, user->host, acptr->info);
        goto exact_match;
      }
    }
    if (!found)
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
    if (p)
      p[-1] = ',';
    if (!MyConnect(sptr) || total >= MAX_WHOIS_LINES)
      break;
  }
  sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);

  return 0;
}

/*
 * mo_whois - oper message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server
 * parv[2] = nickname masklist
 */
int mo_whois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct User*    user;
  struct Client*  acptr;
  struct Client*  a2cptr;
  struct Channel* chptr;
  char*           nick;
  char*           tmp;
  char*           name;
  char*           p = 0;
  int             found;
  int             len;
  int             mlen;
  int             total;
  static char     buf[512];

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, parv[0]);
    return 0;
  }

  if (parc > 2)
  {
    struct Client *acptr;
    /* For convenience: Accept a nickname as first parameter, by replacing
       it with the correct servername - as is needed by hunt_server() */
    if (MyUser(sptr) && (acptr = FindUser(parv[1])))
      parv[1] = acptr->user->server->name;
    if (hunt_server(0, cptr, sptr, "%s%s " TOK_WHOIS " %s :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  total = 0;
  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    int invis, showperson, member, wilds;

    found = 0;
    collapse(nick);
    wilds = (strchr(nick, '?') || strchr(nick, '*'));
    /* Do a hash lookup if the nick does not contain wilds */
    if (wilds)
    {
      /*
       * We're no longer allowing remote users to generate requests with wildcards.
       */
      if (!MyConnect(sptr))
        continue;
      for (acptr = GlobalClientList; (acptr = next_client(acptr, nick));
          acptr = acptr->next)
      {
        if (!IsRegistered(acptr) || IsServer(acptr))
          continue;
        /*
         * I'm always last :-) and acptr->next == 0!!
         */
        if (IsMe(acptr))
          break;
        /*
         * 'Rules' established for sending a WHOIS reply:
         *
         * - if wildcards are being used dont send a reply if
         *   the querier isnt any common channels and the
         *   client in question is invisible and wildcards are
         *   in use (allow exact matches only);
         *
         * - only send replies about common or public channels
         *   the target user(s) are on;
         */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;

        invis = acptr != sptr && IsInvisible(acptr);
        member = (user && user->channel) ? 1 : 0;
        showperson = (wilds && !invis && !member) || !wilds;
        if (user) {
          struct Membership* chan;
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            member = find_channel_member(sptr, chptr) ? 1 : 0;
            if (invis && !member)
              continue;
            if (IsZombie(chan))
              continue;
            if (member || (!invis && PubChannel(chptr)))
            {
              showperson = 1;
              break;
            }
            if (!invis && HiddenChannel(chptr) && !SecretChannel(chptr))
              showperson = 1;
          }
        }
        if (!showperson)
          continue;

        if (user)
        {
          a2cptr = user->server;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, user->username, user->host, acptr->info);
        }
        else
        {
          a2cptr = &me;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, "<unknown>", "<unknown>", "<unknown>");
        }

        found = 1;

exact_match:
        if (user && !IsChannelService(acptr))
        {
          struct Membership* chan;
          mlen = strlen(me.name) + strlen(parv[0]) + 12 + strlen(name);
          len = 0;
          *buf = '\0';
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            if (ShowChannel(sptr, chptr) &&
                (acptr == sptr || !IsZombie(chan)))
            {
              if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5)
              {
                sendto_one(sptr, ":%s %d %s %s :%s",
                    me.name, RPL_WHOISCHANNELS, parv[0], name, buf);
                *buf = '\0';
                len = 0;
              }
              if (IsDeaf(acptr))
                *(buf + len++) = '-';
              if (is_chan_op(acptr, chptr))
                *(buf + len++) = '@';
              else if (has_voice(acptr, chptr))
                *(buf + len++) = '+';
              else if (IsZombie(chan))
                *(buf + len++) = '!';
              if (len)
                *(buf + len) = '\0';
              strcpy(buf + len, chptr->chname);
              len += strlen(chptr->chname);
              strcat(buf + len, " ");
              len++;
            }
          }
          if (buf[0] != '\0')
            sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS),
                me.name, parv[0], name, buf);
        }

        sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name,
            parv[0], name, a2cptr->name, a2cptr->info);

        if (user)
        {
          if (user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
                parv[0], name, user->away);

          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
                me.name, parv[0], name);

          if (MyConnect(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISIDLE), me.name,
                parv[0], name, CurrentTime - user->last, acptr->firsttime);
        }
        if (found == 2 || total++ >= MAX_WHOIS_LINES)
          break;
      }
    }
    else
    {
      /* No wildcards */
      if ((acptr = FindUser(nick)))
      {
        found = 2;              /* Make sure we exit the loop after passing it once */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;
        a2cptr = user->server;
        sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
            parv[0], name, user->username, user->host, acptr->info);
        goto exact_match;
      }
    }
    if (!found)
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
    if (p)
      p[-1] = ',';
    if (!MyConnect(sptr) || total >= MAX_WHOIS_LINES)
      break;
  }
  sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);

  return 0;
}

  

#if 0
/*
 * m_whois
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server
 * parv[2] = nickname masklist
 */
int m_whois(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct User*    user;
  struct Client*  acptr;
  struct Client*  a2cptr;
  struct Channel* chptr;
  char*           nick;
  char*           tmp;
  char*           name;
  char*           p = 0;
  int             found;
  int             len;
  int             mlen;
  int             total;
  static char     buf[512];

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, parv[0]);
    return 0;
  }

  if (parc > 2)
  {
    struct Client *acptr;
    /* For convenience: Accept a nickname as first parameter, by replacing
       it with the correct servername - as is needed by hunt_server() */
    if (MyUser(sptr) && (acptr = FindUser(parv[1])))
      parv[1] = acptr->user->server->name;
    if (hunt_server(0, cptr, sptr, "%s%s " TOK_WHOIS " %s :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  total = 0;
  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    int invis, showperson, member, wilds;

    found = 0;
    collapse(nick);
    wilds = (strchr(nick, '?') || strchr(nick, '*'));
    /* Do a hash lookup if the nick does not contain wilds */
    if (wilds)
    {
      /*
       * We're no longer allowing remote users to generate requests with wildcards.
       */
      if (!MyConnect(sptr))
        continue;
      for (acptr = GlobalClientList; (acptr = next_client(acptr, nick));
          acptr = acptr->next)
      {
        if (!IsRegistered(acptr) || IsServer(acptr))
          continue;
        /*
         * I'm always last :-) and acptr->next == NULL!!
         */
        if (IsMe(acptr))
          break;
        /*
         * 'Rules' established for sending a WHOIS reply:
         *
         * - if wildcards are being used dont send a reply if
         *   the querier isnt any common channels and the
         *   client in question is invisible and wildcards are
         *   in use (allow exact matches only);
         *
         * - only send replies about common or public channels
         *   the target user(s) are on;
         */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;

        invis = acptr != sptr && IsInvisible(acptr);
        member = (user && user->channel) ? 1 : 0;
        showperson = (wilds && !invis && !member) || !wilds;
        if (user) {
          struct Membership* chan;
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            member = find_channel_member(sptr, chptr) ? 1 : 0;
            if (invis && !member)
              continue;
            if (IsZombie(chan))
              continue;
            if (member || (!invis && PubChannel(chptr)))
            {
              showperson = 1;
              break;
            }
            if (!invis && HiddenChannel(chptr) && !SecretChannel(chptr))
              showperson = 1;
          }
        }
        if (!showperson)
          continue;

        if (user)
        {
          a2cptr = user->server;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, user->username, user->host, acptr->info);
        }
        else
        {
          a2cptr = &me;
          sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
              parv[0], name, "<unknown>", "<unknown>", "<unknown>");
        }

        found = 1;

exact_match:
        if (user && !IsChannelService(acptr))
        {
          struct Membership* chan;
          mlen = strlen(me.name) + strlen(parv[0]) + 12 + strlen(name);
          len = 0;
          *buf = '\0';
          for (chan = user->channel; chan; chan = chan->next_channel)
          {
            chptr = chan->channel;
            if (ShowChannel(sptr, chptr) &&
                (acptr == sptr || !IsZombie(chan)))
            {
              if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5)
              {
                sendto_one(sptr, ":%s %d %s %s :%s",
                    me.name, RPL_WHOISCHANNELS, parv[0], name, buf);
                *buf = '\0';
                len = 0;
              }
              if (IsDeaf(acptr))
                *(buf + len++) = '-';
              if (is_chan_op(acptr, chptr))
                *(buf + len++) = '@';
              else if (has_voice(acptr, chptr))
                *(buf + len++) = '+';
              else if (IsZombie(chan))
                *(buf + len++) = '!';
              if (len)
                *(buf + len) = '\0';
              strcpy(buf + len, chptr->chname);
              len += strlen(chptr->chname);
              strcat(buf + len, " ");
              len++;
            }
          }
          if (buf[0] != '\0')
            sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS),
                me.name, parv[0], name, buf);
        }

        sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name,
            parv[0], name, a2cptr->name, a2cptr->info);

        if (user)
        {
          if (user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
                parv[0], name, user->away);

          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
                me.name, parv[0], name);

          if (MyConnect(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISIDLE), me.name,
                parv[0], name, CurrentTime - user->last, acptr->firsttime);
        }
        if (found == 2 || total++ >= MAX_WHOIS_LINES)
          break;
      }
    }
    else
    {
      /* No wildcards */
      if ((acptr = FindUser(nick)))
      {
        found = 2;              /* Make sure we exit the loop after passing it once */
        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;
        a2cptr = user->server;
        sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
            parv[0], name, user->username, user->host, acptr->info);
        goto exact_match;
      }
    }
    if (!found)
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
    if (p)
      p[-1] = ',';
    if (!MyConnect(sptr) || total >= MAX_WHOIS_LINES)
      break;
  }
  sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);

  return 0;
}
#endif /* 0 */

