/*
 * IRC - Internet Relay Chat, ircd/m_notice.c
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
#include "client.h"
#include "ircd_chattr.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

#include <assert.h>
#include <string.h>

#if !defined(XXX_BOGUS_TEMP_HACK)
#include "handlers.h"
#endif

/*
 * m_notice - generic message handler
 */
int m_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];

  assert(0 != cptr);
  assert(cptr == sptr);

  cli_flags(sptr) &= ~FLAGS_TS8;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_NOTICE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (parv[1][0] == '@' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  }

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name)) {
      relay_channel_notice(sptr, name, parv[parc - 1]);
    }
    /*
     * we have to check for the '@' at least once no matter what we do
     * handle it first so we don't have to do it twice
     */
    else if ((server = strchr(name, '@')))
      relay_directed_notice(sptr, name, server, parv[parc - 1]);
    else 
      relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/*
 * ms_notice - server message handler template
 */
int ms_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* name;
  char* server;

  cli_flags(sptr) &= ~FLAGS_TS8;

  if (parc < 3) {
    /*
     * we can't deliver it, sending an error back is pointless
     */
    return protocol_violation(sptr,"Not enough params for NOTICE");
  }
  name = parv[1];
  /*
   * channel msg?
   */
  if (IsChannelPrefix(*name)) {
    server_relay_channel_notice(sptr, name, parv[parc - 1]);
  }
  /*
   * coming from another server, we have to check this here
   */
  else if ('$' == *name && IsOper(sptr)) {
    server_relay_masked_notice(sptr, name, parv[parc - 1]);
  }
  else if ((server = strchr(name, '@'))) {
    /*
     * XXX - can't get away with not doing everything
     * relay_directed_notice has to do
     */
    relay_directed_notice(sptr, name, server, parv[parc - 1]);
  }
  else {
    server_relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/*
 * mo_notice - oper message handler
 */
int mo_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];
  assert(0 != cptr);
  assert(cptr == sptr);

  cli_flags(sptr) &= ~FLAGS_TS8;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_NOTICE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (parv[1][0] == '@' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  }

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name))
      relay_channel_notice(sptr, name, parv[parc - 1]);

    else if (*name == '$')
      relay_masked_notice(sptr, name, parv[parc - 1]);

    else if ((server = strchr(name, '@')))
      relay_directed_notice(sptr, name, server, parv[parc - 1]);

    else 
      relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}


#if 0
/*
 * m_message (used in m_private() and m_notice())
 *
 * The general function to deliver MSG's between users/channels
 *
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[parc-1] = message text
 *
 * massive cleanup
 * rev argv 6/91
 */
static int m_message(struct Client *cptr, struct Client *sptr,
    int parc, char *parv[], int notice)
{
  struct Client*  acptr;
  char*           s;
  struct Channel* chptr;
  char*           nick;
  char*           server;
  char*           cmd;
  char*           host;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];

  sptr->flags &= ~FLAGS_TS8;

  cmd = notice ? MSG_NOTICE : MSG_PRIVATE;

  if (parc < 2 || EmptyString(parv[1]))
    return send_error_to_client(sptr, ERR_NORECIPIENT, cmd); /* XXX DEAD */

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_error_to_client(sptr, ERR_NOTEXTTOSEND); /* XXX DEAD */


#if 0
  if (MyUser(sptr))
    parv[1] = canonize(parv[1]);
  for (p = 0, nick = ircd_strtok(&p, parv[1], ","); nick;
      nick = ircd_strtok(&p, 0, ","))
#endif

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);
  for (i = 0; i < count; ++i) {
    nick = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelName(nick))
    {
      if ((chptr = FindChannel(nick)))
      {
        /* This first: Almost never a server/service */
        if (client_can_send_to_channel(sptr, chptr) || IsChannelService(sptr))
        {
          if (MyUser(sptr) && (chptr->mode.mode & MODE_NOPRIVMSGS) &&
              check_target_limit(sptr, chptr, chptr->chname, 0))
            continue;
          sendmsgto_channel_butone(cptr, sptr, chptr, /* XXX DEAD */
              parv[0], (notice ? TOK_NOTICE : TOK_PRIVATE), 
              chptr->chname, parv[parc - 1]);
        }
        else if (!notice)
          sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), /* XXX DEAD */
              me.name, parv[0], chptr->chname);
        continue;
      }
    }
    else if (*nick != '$' && !strchr(nick, '@'))
    {
      /*
       * nickname addressed?
       */
      if (MyUser(sptr))
        acptr = FindUser(nick);
      else if ((acptr = findNUser(nick)) && !IsUser(acptr))
        acptr = 0;
      if (acptr)
      {
        if (MyUser(sptr) && check_target_limit(sptr, acptr, acptr->name, 0))
          continue;
        if (!is_silenced(sptr, acptr))
        {
          if (!notice && MyConnect(sptr) && acptr->user && acptr->user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), /* XXX DEAD */
                me.name, parv[0], acptr->name, acptr->user->away);
          if (MyUser(acptr))
          {
            add_target(acptr, sptr);
            sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", /* XXX DEAD */
                parv[0], cmd, acptr->name, parv[parc - 1]);
          }
          else
            sendto_prefix_one(acptr, sptr, ":%s %s %s%s :%s", /* XXX DEAD */
                parv[0], (notice ? TOK_NOTICE : TOK_PRIVATE),
                NumNick(acptr), parv[parc - 1]);
        }
      }
      else if (MyUser(sptr))
        sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick); /* XXX DEAD */
      else
        sendto_one(sptr, /* XXX DEAD */
            ":%s %d %s * :Target left UnderNet. Failed to deliver: [%.50s]",
            me.name, ERR_NOSUCHNICK, sptr->name, parv[parc - 1]);
      continue;
    }
    /*
     * The following two cases allow masks in NOTICEs
     * (for OPERs only)
     *
     * Armin, 8Jun90 (gruner@informatik.tu-muenchen.de)
     */
    if ((*nick == '$' || *nick == '#') && IsAnOper(sptr))
    {
      if (MyConnect(sptr))
      {
        if (!(s = strrchr(nick, '.')))
        {
          sendto_one(sptr, err_str(ERR_NOTOPLEVEL), me.name, parv[0], nick); /* XXX DEAD */
          continue;
        }
        while (*++s)
          if (*s == '.' || *s == '*' || *s == '?')
            break;
        if (*s == '*' || *s == '?')
        {
          sendto_one(sptr, err_str(ERR_WILDTOPLEVEL), me.name, parv[0], nick); /* XXX DEAD */
          continue;
        }
      }
      sendto_match_butone(IsServer(cptr) ? cptr : 0, /* XXX DEAD */
          sptr, nick + 1, (*nick == '#') ? MATCH_HOST : MATCH_SERVER,
          ":%s %s %s :%s", parv[0], cmd, nick, parv[parc - 1]);
      continue;
    }
    else if ((server = strchr(nick, '@')) && (acptr = FindServer(server + 1)))
    {
      /*
       * NICK[%host]@server addressed? See if <server> is me first
       */
      if (!IsMe(acptr))
      {
        sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[parc - 1]); /* XXX DEAD */
        continue;
      }

      /* Look for an user whose NICK is equal to <nick> and then
       * check if it's hostname matches <host> and if it's a local
       * user. */
      *server = '\0';
      if ((host = strchr(nick, '%')))
        *host++ = '\0';

      if ((!(acptr = FindUser(nick))) ||
          (!(MyUser(acptr))) ||
          ((!(EmptyString(host))) && match(host, acptr->user->host)))
        acptr = 0;

      *server = '@';
      if (host)
        *--host = '%';

      if (acptr)
      {
        if (!(is_silenced(sptr, acptr)))
          sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", /* XXX DEAD */
              parv[0], cmd, nick, parv[parc - 1]);
        continue;
      }
    }
    if (IsChannelName(nick))
      sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], nick); /* XXX DEAD */
    else
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick); /* XXX DEAD */
  }
  return 0;
}

/*
 * m_private
 *
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[parc-1] = message text
 */
int m_private(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  return m_message(cptr, sptr, parc, parv, 0);
}

/*
 * m_notice
 *
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[parc-1] = notice text
 */
int m_notice(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (MyUser(sptr) && parv[1] && parv[1][0] == '@' &&
      IsChannelName(&parv[1][1]))
  {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  }
  return m_message(cptr, sptr, parc, parv, 1);
}

#endif
