/*
 * IRC - Internet Relay Chat, ircd/m_connect.c
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
#include "crule.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>

/*
 * ms_connect - server message handler
 * - Added by Jto 11 Feb 1989
 *
 *    parv[0] = sender prefix
 *    parv[1] = servername
 *    parv[2] = port number
 *    parv[3] = remote server
 */
int ms_connect(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  unsigned short   port;
  unsigned short   tmpport;
  const char*      crule_name;
  struct ConfItem* aconf;
  struct Client*   acptr;
  
  assert(0 != cptr);
  assert(0 != sptr);

  if (!IsPrivileged(sptr))
    return send_error_to_client(sptr, ERR_NOPRIVILEGES);

  if (parc < 4) {
    /*
     * this is coming from a server which should have already
     * checked it's args, if we don't have parc == 4, something
     * isn't right.
     */
    return need_more_params(sptr, "CONNECT");
  }

  if (hunt_server(1, cptr, sptr,
                  "%s%s " TOK_CONNECT " %s %s :%s", 3, parc, parv) != HUNTED_ISME)
    return 0;

  /*
   * need to find the conf entry first so we can use the server name from
   * the conf entry instead of parv[1] to find out if the server is already
   * present below. --Bleep
   */
  if (0 == (aconf = conf_find_server(parv[1]))) {
    sendto_one(sptr, "%s NOTICE %s%s :Connect: Host %s not listed in ircd.conf",
               NumServ(&me), NumNick(sptr), parv[1]);
    return 0;
  }
  /*
   * use aconf->name to look up the server
   */
  if ((acptr = FindServer(aconf->name))) {
    sendto_one(sptr, "%s NOTICE %s%s :Connect: Server %s %s %s.",
               NumServ(&me), NumNick(sptr), parv[1], "already exists from",
               acptr->from->name);
    return 0;
  }
  /*
   * Evaluate connection rules...  If no rules found, allow the
   * connect.   Otherwise stop with the first true rule (ie: rules
   * are ored together.  Oper connects are effected only by D
   * lines (CRULEALL) not d lines (CRULEAUTO).
   */
  if ((crule_name = conf_eval_crule(aconf))) {
    sendto_one(sptr, "%s NOTICE %s%s :Connect: Disallowed by rule: %s",
               NumServ(&me), NumNick(sptr), crule_name);
    return 0;
  }
  /*
   * Get port number from params, port must be non-zero if it comes from a
   * server.
   */
  if ((port = atoi(parv[2])) == 0) {
    sendto_one(sptr, "%s NOTICE %s%s :Connect: Invalid port number",
               NumServ(&me), NumNick(sptr));
    return 0;
  }
  /*
   * save the old port
   */
  tmpport = aconf->port;
  aconf->port = port;
  /*
   * Notify all operators about remote connect requests
   */
  sendto_ops("Remote CONNECT %s %s from %s",
             parv[1], parv[2] ? parv[2] : "", get_client_name(sptr, HIDE_IP));

  ircd_log(L_INFO, "CONNECT From %s : %s %d", parv[0], parv[1], parv[2] ? parv[2] : "");

  if (connect_server(aconf, sptr, 0)) {
    sendto_one(sptr, "%s NOTICE %s%s :*** Connecting to %s.",
               NumServ(&me), NumNick(sptr), aconf->name);
  }
  else {
    sendto_one(sptr, "%s NOTICE %s%s :*** Connection to %s failed",
               NumServ(&me), NumNick(sptr), aconf->name);
  }
  aconf->port = tmpport;
  return 0;
}

/*
 * mo_connect - oper message handler
 * - Added by Jto 11 Feb 1989
 *
 *    parv[0] = sender prefix
 *    parv[1] = servername
 *    parv[2] = port number
 *    parv[3] = remote server
 */
int mo_connect(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  unsigned short   port;
  unsigned short   tmpport;
  const char*      crule_name;
  struct ConfItem* aconf;
  struct Client*   acptr;

  assert(0 != cptr);
  assert(cptr == sptr);
  assert(IsAnOper(sptr));

  if (parc < 2)
    return need_more_params(sptr, "CONNECT");

  if (parc > 3) {
    /*
     * if parc > 3, we are trying to connect two remote
     * servers to each other
     */
    if (IsLocOp(sptr)) {
      /*
       * Only allow LocOps to make local CONNECTS --SRB
       */
      return 0;
    }
    else {
      struct Client* acptr2;
      struct Client* acptr3;

      if (!(acptr3 = find_match_server(parv[3]))) {
        send_error_to_client(sptr, ERR_NOSUCHSERVER, parv[3]);
        return 0;
      }

      /*
       * Look for closest matching server 
       * needed for "/connect blah 4400 *"?
       */
      for (acptr2 = acptr3; acptr2 != &me; acptr2 = acptr2->serv->up) {
        if (!match(parv[3], acptr2->name))
          acptr3 = acptr2;
      }
      parv[3] = acptr3->name;
      if (hunt_server(1, cptr, sptr, "%s%s " TOK_CONNECT " %s %s :%s",
                      3, parc, parv) != HUNTED_ISME)
        return 0;
    }
  }
  /*
   * need to find the conf entry first so we can use the server name from
   * the conf entry instead of parv[1] to find out if the server is already
   * present below. --Bleep
   */
  if (0 == (aconf = conf_find_server(parv[1]))) {
    sendto_one(sptr,
               ":%s NOTICE %s :Connect: Host %s not listed in ircd.conf",
               me.name, parv[0], parv[1]);
    return 0;
  }
  /*
   * use aconf->name to look up the server, see above
   */
  if ((acptr = FindServer(aconf->name))) {
    sendto_one(sptr, ":%s NOTICE %s :Connect: Server %s %s %s.",
               me.name, parv[0], parv[1], "already exists from",
               acptr->from->name);
    return 0;
  }
  /*
   * Evaluate connection rules...  If no rules found, allow the
   * connect.   Otherwise stop with the first true rule (ie: rules
   * are ored together.  Oper connects are effected only by D
   * lines (CRULEALL) not d lines (CRULEAUTO).
   */
  if ((crule_name = conf_eval_crule(aconf))) {
    sendto_one(sptr, ":%s NOTICE %s :Connect: Disallowed by rule: %s",
               me.name, parv[0], crule_name);
    return 0;
  }
  /*
   *  Get port number from user, if given. If not specified,
   *  use the default from configuration structure. If missing
   *  from there, then use the precompiled default.
   */
  port = aconf->port;
  if (parc > 2) {
    assert(0 != parv[2]);
    if (0 == (port = atoi(parv[2]))) {
      sendto_one(sptr, ":%s NOTICE %s :Connect: Invalid port number",
                 me.name, parv[0]);
      return 0;
    }
  }
  if (0 == port && 0 == (port = SERVER_PORT)) {
    sendto_one(sptr, ":%s NOTICE %s :Connect: missing port number",
               me.name, parv[0]);
    return 0;
  }

  tmpport = aconf->port;
  aconf->port = port;

  if (connect_server(aconf, sptr, 0)) {
    sendto_one(sptr, ":%s NOTICE %s :*** Connecting to %s.",
               me.name, parv[0], aconf->name);
  }
  else {
    sendto_one(sptr, ":%s NOTICE %s :*** Connection to %s failed",
               me.name, parv[0], aconf->name);
  }
  aconf->port = tmpport;
  return 0;
}

  
#if 0
/*
 * XXX - remove when regression testing complete
 *
 *  m_connect                           - Added by Jto 11 Feb 1989
 *
 *    parv[0] = sender prefix
 *    parv[1] = servername
 *    parv[2] = port number
 *    parv[3] = remote server
 */
int m_connect(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  unsigned short   port;
  unsigned short   tmpport;
  struct ConfItem* aconf;
  struct ConfItem* cconf;
  struct Client*   acptr;

  if (!IsPrivileged(sptr)) {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return -1;
  }

  if (IsLocOp(sptr) && parc > 3)        /* Only allow LocOps to make */
    return 0;                   /* local CONNECTS --SRB      */

  if (parc > 3 && MyUser(sptr)) {
    struct Client* acptr2;
    struct Client* acptr3;
    if (!(acptr3 = find_match_server(parv[3]))) {
      sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], parv[3]);
      return 0;
    }

    /* Look for closest matching server */
    for (acptr2 = acptr3; acptr2 != &me; acptr2 = acptr2->serv->up)
      if (!match(parv[3], acptr2->name))
        acptr3 = acptr2;

    parv[3] = acptr3->name;
  }

  if (hunt_server(1, cptr, sptr,
                  "%s%s " TOK_CONNECT " %s %s :%s", 3, parc, parv) != HUNTED_ISME)
    return 0;

  if (parc < 2 || *parv[1] == '\0') {
    return need_more_params(sptr, "CONNECT");
#if 0
    return -1;
#endif
  }

  if ((acptr = FindServer(parv[1]))) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :Connect: Server %s %s %s.",
          me.name, parv[0], parv[1], "already exists from", acptr->from->name);
    else
      sendto_one(sptr, "%s NOTICE %s%s :Connect: Server %s %s %s.",
          NumServ(&me), NumNick(sptr), parv[1], "already exists from",
          acptr->from->name);
    return 0;
  }

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (CONF_SERVER == aconf->status && 0 == match(parv[1], aconf->name))
      break;
  }
#if 0
  /*
   * Checked first servernames, then try hostnames.
   */
  if (!aconf) {
    for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
      if (CONF_SERVER == aconf->status && 0 == match(parv[1], aconf->host))
        break;
    }
  }
#endif
  if (!aconf) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :Connect: Host %s not listed in ircd.conf",
                 me.name, parv[0], parv[1]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :Connect: Host %s not listed in ircd.conf",
                 NumServ(&me), NumNick(sptr), parv[1]);
    return 0;
  }
  /*
   *  Get port number from user, if given. If not specified,
   *  use the default from configuration structure. If missing
   *  from there, then use the precompiled default.
   */
  tmpport = port = aconf->port;
  if (parc > 2 && !BadPtr(parv[2])) {
    if ((port = atoi(parv[2])) == 0) {
      if (MyUser(sptr))
        sendto_one(sptr, ":%s NOTICE %s :Connect: Invalid port number", me.name, parv[0]);
      else
        sendto_one(sptr, "%s NOTICE %s%s :Connect: Invalid port number",
                   NumServ(&me), NumNick(sptr));
      return 0;
    }
  }
  else if (port == 0 && (port = PORTNUM) == 0) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :Connect: missing port number",
                 me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :Connect: missing port number",
                 NumServ(&me), NumNick(sptr));
    return 0;
  }

  /*
   * Evaluate connection rules...  If no rules found, allow the
   * connect.   Otherwise stop with the first true rule (ie: rules
   * are ored together.  Oper connects are effected only by D
   * lines (CRULEALL) not d lines (CRULEAUTO).
   */
  for (cconf = GlobalConfList; cconf; cconf = cconf->next) {
    if ((CONF_CRULEALL == cconf->status) &&
        (0 == match(cconf->host, aconf->name))) {
      if (crule_eval(cconf->passwd)) {
        if (MyUser(sptr))
          sendto_one(sptr, ":%s NOTICE %s :Connect: Disallowed by rule: %s",
                     me.name, parv[0], cconf->name);
        else
          sendto_one(sptr, "%s NOTICE %s%s :Connect: Disallowed by rule: %s",
                     NumServ(&me), NumNick(sptr), cconf->name);
        return 0;
      }
    }
  }

  /*
   * Notify all operators about remote connect requests
   */
  if (!IsAnOper(cptr)) {
    sendto_ops("Remote CONNECT %s %s from %s",
               parv[1], parv[2] ? parv[2] : "", get_client_name(sptr, HIDE_IP));

    ircd_log(L_INFO, "CONNECT From %s : %s %d",
             parv[0], parv[1], parv[2] ? parv[2] : "");
  }
  aconf->port = port;
  if (connect_server(aconf, sptr, 0)) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :*** Connecting to %s.",
                 me.name, parv[0], aconf->name);
    else
      sendto_one(sptr, "%s NOTICE %s%s :*** Connecting to %s.",
                 NumServ(&me), NumNick(sptr), aconf->name);
  }
  else {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :*** Connection to %s failed",
                 me.name, parv[0], aconf->name);
    else
      sendto_one(sptr, "%s NOTICE %s%s :*** Connection to %s failed",
                 NumServ(&me), NumNick(sptr), aconf->name);
  }
  aconf->port = tmpport;
  return 0;
}
#endif /* 0 */

