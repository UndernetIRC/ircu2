/*
 * IRC - Internet Relay Chat, ircd/m_mode.c
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
#include "handlers.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
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
 * m_mode - generic message handler
 */
int m_mode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int             badop;
  int             sendts;
  struct Channel* chptr = 0;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  char nparabuf[MODEBUFLEN];


  if (parc < 2)
    return need_more_params(sptr, "MODE");

  /*
   * if local user, cleanup channel name, don't allow local channel operations
   * for remote clients
   */
  if (MyUser(sptr))
    clean_channelname(parv[1]);
  else if (IsLocalChannel(parv[1]))
    return 0;

  /* 
   * try to find the channel
   */
  if ('#' == *parv[1] || '&' == *parv[1])
    chptr = FindChannel(parv[1]);
  if (!chptr)
    return set_user_mode(cptr, sptr, parc, parv);

  sptr->flags &= ~FLAGS_TS8;
  /*
   * sending an error wasnt good, lets just send an empty mode reply..  poptix
   */
  if (IsModelessChannel(chptr->chname)) {
    if (IsUser(sptr))
      sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
                 chptr->chname, "+nt", "");
    return 0;
  }

  if (parc < 3) {
    /*
     * no parameters, send channel modes
     */
    *modebuf = *parabuf = '\0';
    modebuf[1] = '\0';
    channel_modes(sptr, modebuf, parabuf, chptr);
    sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
               chptr->chname, modebuf, parabuf);
    sendto_one(sptr, rpl_str(RPL_CREATIONTIME), me.name, parv[0],
               chptr->chname, chptr->creationtime);
    return 0;
  }

  LocalChanOperMode = 0;

  if (!(sendts = set_mode(cptr, sptr, chptr, parc - 2, parv + 2,
                          modebuf, parabuf, nparabuf, &badop))) {
    sendto_one(sptr, err_str(find_channel_member(sptr, chptr) ? ERR_CHANOPRIVSNEEDED :
        ERR_NOTONCHANNEL), me.name, parv[0], chptr->chname);
    return 0;
  }

  if (badop >= 2)
    send_hack_notice(cptr, sptr, parc, parv, badop, 1);

  if (strlen(modebuf) > 1 || sendts > 0) {
    if (badop != 2 && strlen(modebuf) > 1) {
#ifdef OPER_MODE_LCHAN
      if (LocalChanOperMode) {
        sendto_channel_butserv(chptr, &me, ":%s MODE %s %s %s",
                               me.name, chptr->chname, modebuf, parabuf);
        sendto_op_mask(SNO_HACK4,"OPER MODE: %s MODE %s %s %s",
                       sptr->name, chptr->chname, modebuf, parabuf);
      }
      else
#endif
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s %s",
          parv[0], chptr->chname, modebuf, parabuf);
    }
    if (IsLocalChannel(chptr->chname))
      return 0;
    /* We send a creationtime of 0, to mark it as a hack --Run */
    if (IsServer(sptr) && (badop == 2 || sendts > 0)) {
      if (*modebuf == '\0')
        strcpy(modebuf, "+");
      if (badop != 2) {
        sendto_highprot_butone(cptr, 10, "%s " TOK_MODE " %s %s %s " TIME_T_FMT,
            NumServ(sptr), chptr->chname, modebuf, nparabuf,
            (badop == 4) ? (time_t) 0 : chptr->creationtime);
      }
    }
    else {
      if (IsServer(sptr))
         sendto_highprot_butone(cptr, 10, "%s " TOK_MODE " %s %s %s",
           NumServ(sptr), chptr->chname, modebuf, nparabuf);
      else
         sendto_highprot_butone(cptr, 10, "%s%s " TOK_MODE " %s %s %s",
           NumNick(sptr), chptr->chname, modebuf, nparabuf);
    }
  }
  return 0;
}

/*
 * ms_mode - server message handler
 */
int ms_mode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int             badop;
  int             sendts;
  struct Channel* chptr = 0;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  char nparabuf[MODEBUFLEN];

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  /*
   * if local user, cleanup channel name, don't allow local channel operations
   * for remote clients
   */
  if (MyUser(sptr))
    clean_channelname(parv[1]);
  else if (IsLocalChannel(parv[1]))
    return 0;

  /* 
   * try to find the channel
   */
  if ('#' == *parv[1] || '&' == *parv[1])
    chptr = FindChannel(parv[1]);
  if (!chptr)
    return set_user_mode(cptr, sptr, parc, parv);

  sptr->flags &= ~FLAGS_TS8;
  /*
   * sending an error wasnt good, lets just send an empty mode reply..  poptix
   */
  if (IsModelessChannel(chptr->chname)) {
    if (IsUser(sptr))
      sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
                 chptr->chname, "+nt", "");
    return 0;
  }

  if (parc < 3) {
    /*
     * no parameters, send channel modes
     */
    *modebuf = *parabuf = '\0';
    modebuf[1] = '\0';
    channel_modes(sptr, modebuf, parabuf, chptr);
    sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
               chptr->chname, modebuf, parabuf);
    sendto_one(sptr, rpl_str(RPL_CREATIONTIME), me.name, parv[0],
               chptr->chname, chptr->creationtime);
    return 0;
  }

  LocalChanOperMode = 0;

  if (!(sendts = set_mode(cptr, sptr, chptr, parc - 2, parv + 2,
                          modebuf, parabuf, nparabuf, &badop))) {
    sendto_one(sptr, err_str(find_channel_member(sptr, chptr) ? ERR_CHANOPRIVSNEEDED :
        ERR_NOTONCHANNEL), me.name, parv[0], chptr->chname);
    return 0;
  }

  if (badop >= 2)
    send_hack_notice(cptr, sptr, parc, parv, badop, 1);

  if (strlen(modebuf) > 1 || sendts > 0) {
    if (badop != 2 && strlen(modebuf) > 1) {
#ifdef OPER_MODE_LCHAN
      if (LocalChanOperMode) {
        sendto_channel_butserv(chptr, &me, ":%s MODE %s %s %s",
                               me.name, chptr->chname, modebuf, parabuf);
        sendto_op_mask(SNO_HACK4,"OPER MODE: %s MODE %s %s %s",
                       me.name, chptr->chname, modebuf, parabuf);
      }
      else
#endif
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s %s",
          parv[0], chptr->chname, modebuf, parabuf);
    }
    if (IsLocalChannel(chptr->chname))
      return 0;
    /* We send a creationtime of 0, to mark it as a hack --Run */
    if (IsServer(sptr) && (badop == 2 || sendts > 0)) {
      if (*modebuf == '\0')
        strcpy(modebuf, "+");
      if (badop != 2) {
        sendto_highprot_butone(cptr, 10, "%s " TOK_MODE " %s %s %s " TIME_T_FMT,
            NumServ(sptr), chptr->chname, modebuf, nparabuf,
            (badop == 4) ? (time_t) 0 : chptr->creationtime);
      }
    }
    else {
      if (IsServer(sptr))
         sendto_highprot_butone(cptr, 10, "%s " TOK_MODE " %s %s %s",
           NumServ(sptr), chptr->chname, modebuf, nparabuf);
      else
         sendto_highprot_butone(cptr, 10, "%s%s " TOK_MODE " %s %s %s",
           NumNick(sptr), chptr->chname, modebuf, nparabuf);
    }
  }
  return 0;
}

#if 0
/*
 * m_mode
 * parv[0] - sender
 * parv[1] - channel
 */
int m_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  int             badop;
  int             sendts;
  struct Channel* chptr = 0;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  /*
   * if local user, cleanup channel name, don't allow local channel operations
   * for remote clients
   */
  if (MyUser(sptr))
    clean_channelname(parv[1]);
  else if (IsLocalChannel(parv[1]))
    return 0;

  /* 
   * try to find the channel
   */
  if ('#' == *parv[1] || '&' == *parv[1])
    chptr = FindChannel(parv[1]);
  if (!chptr)
    return set_user_mode(cptr, sptr, parc, parv);

  sptr->flags &= ~FLAGS_TS8;
  /*
   * sending an error wasnt good, lets just send an empty mode reply..  poptix
   */
  if (IsModelessChannel(chptr->chname)) {
    if (IsUser(sptr))
      sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
                 chptr->chname, "+nt", "");
    return 0;
  }

  if (parc < 3) {
    /*
     * no parameters, send channel modes
     */
    *modebuf = *parabuf = '\0';
    modebuf[1] = '\0';
    channel_modes(sptr, modebuf, parabuf, chptr);
    sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
               chptr->chname, modebuf, parabuf);
    sendto_one(sptr, rpl_str(RPL_CREATIONTIME), me.name, parv[0],
               chptr->chname, chptr->creationtime);
    return 0;
  }

  LocalChanOperMode = 0;

  if (!(sendts = set_mode(cptr, sptr, chptr, parc - 2, parv + 2,
                          modebuf, parabuf, nparabuf, &badop))) {
    sendto_one(sptr, err_str(find_channel_member(sptr, chptr) ? ERR_CHANOPRIVSNEEDED :
        ERR_NOTONCHANNEL), me.name, parv[0], chptr->chname);
    return 0;
  }

  if (badop >= 2)
    send_hack_notice(cptr, sptr, parc, parv, badop, 1);

  if (strlen(modebuf) > 1 || sendts > 0) {
    if (badop != 2 && strlen(modebuf) > 1) {
#ifdef OPER_MODE_LCHAN
      if (LocalChanOperMode) {
        sendto_channel_butserv(chptr, &me, ":%s MODE %s %s %s",
                               me.name, chptr->chname, modebuf, parabuf);
        sendto_op_mask(SNO_HACK4,"OPER MODE: %s MODE %s %s %s",
                       me.name, chptr->chname, modebuf, parabuf);
      }
      else
#endif
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s %s",
          parv[0], chptr->chname, modebuf, parabuf);
    }
    if (IsLocalChannel(chptr->chname))
      return 0;
    /* We send a creationtime of 0, to mark it as a hack --Run */
    if (IsServer(sptr) && (badop == 2 || sendts > 0)) {
      if (*modebuf == '\0')
        strcpy(modebuf, "+");
      if (badop != 2) {
        sendto_highprot_butone(cptr, 10, "%s " TOK_MODE " %s %s %s " TIME_T_FMT,
            NumServ(sptr), chptr->chname, modebuf, nparabuf,
            (badop == 4) ? (time_t) 0 : chptr->creationtime);
      }
    }
    else {
      if (IsServer(sptr))
         sendto_highprot_butone(cptr, 10, "%s " TOK_MODE " %s %s %s",
           NumServ(sptr), chptr->chname, modebuf, nparabuf);
      else
         sendto_highprot_butone(cptr, 10, "%s%s " TOK_MODE " %s %s %s",
           NumNick(sptr), chptr->chname, modebuf, nparabuf);
    }
  }
  return 0;
}

#endif /* 0 */
