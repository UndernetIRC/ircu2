/*
 * IRC - Internet Relay Chat, ircd/m_trace.c
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
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
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
#include "version.h"

#include <assert.h>
#include <string.h>

/*
 * m_trace - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nick or servername
 * parv[2] = 'target' servername
 */
int m_trace(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int i;
  struct Client *acptr;
  struct ConfClass *cltmp;
  char *tname;
  int doall, link_s[MAXCONNECTIONS], link_u[MAXCONNECTIONS];
  int cnt = 0, wilds, dow;

  if (parc < 2 || BadPtr(parv[1]))
  {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = me.name;
    i = HUNTED_ISME;
  }
  else if (parc < 3 || BadPtr(parv[2]))
  {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr)))
    {
      if (IsUser(acptr))
        parv[2] = acptr->user->server->name;
      else
        parv[2] = acptr->name;
      parc = 3;
      parv[3] = 0;
      if ((i = hunt_server(IsServer(acptr), cptr, sptr,
          "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    }
    else
      i = HUNTED_ISME;
  }
  else
  {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server(0, cptr, sptr,
        "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS)
  {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = acptr->from;
    sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
#ifndef GODMODE
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>");
#else /* GODMODE */
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>",
        (acptr && acptr->from->serv) ? acptr->from->serv->timestamp : 0);
#endif /* GODMODE */
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, me.name) : 1;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall)
  {
    for (acptr = GlobalClientList; acptr; acptr = acptr->next) {
      if (IsUser(acptr))
        link_u[acptr->from->fd]++;
      else if (IsServer(acptr))
        link_s[acptr->from->fd]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++)
  {
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, acptr->name))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, acptr->name))
      continue;

    conClass = get_client_class(acptr);

    switch (acptr->status)
    {
      case STAT_CONNECTING:
        sendto_one(sptr, rpl_str(RPL_TRACECONNECTING),
                   me.name, parv[0], conClass, acptr->name);
        cnt++;
        break;
      case STAT_HANDSHAKE:
        sendto_one(sptr, rpl_str(RPL_TRACEHANDSHAKE),
                   me.name, parv[0], conClass, acptr->name);
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
            me.name, parv[0], conClass, get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
      case STAT_UNKNOWN_SERVER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
                   me.name, parv[0], conClass, "Unknown Server");
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr))
        {
          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
                me.name, parv[0], conClass, get_client_name(acptr, SHOW_IP),
                CurrentTime - acptr->lasttime);
          else
            sendto_one(sptr, rpl_str(RPL_TRACEUSER),
                me.name, parv[0], conClass, get_client_name(acptr, SHOW_IP),
                CurrentTime - acptr->lasttime);
          cnt++;
        }
        break;
        /*
         * Connection is a server
         *
         * Serv <class> <nS> <nC> <name> <ConnBy> <last> <age>
         *
         * class        Class the server is in
         * nS           Number of servers reached via this link
         * nC           Number of clients reached via this link
         * name         Name of the server linked
         * ConnBy       Who established this link
         * last         Seconds since we got something from this link
         * age          Seconds this link has been alive
         *
         * Additional comments etc......        -Cym-<cym@acrux.net>
         */

      case STAT_SERVER:
        if (acptr->serv->user)
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                     me.name, parv[0], conClass, link_s[i],
                     link_u[i], acptr->name,
                     (*acptr->serv->by) ? acptr->serv->by : "*",
                     acptr->serv->user->username, acptr->serv->user->host,
                     CurrentTime - acptr->lasttime,
                     CurrentTime - acptr->serv->timestamp);
        else
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                     me.name, parv[0], conClass, link_s[i],
                     link_u[i], acptr->name,
                     (*acptr->serv->by) ?  acptr->serv->by : "*", "*",
                     me.name, CurrentTime - acptr->lasttime,
                     CurrentTime - acptr->serv->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
        sendto_one(sptr, rpl_str(RPL_TRACENEWTYPE), me.name, parv[0],
                   get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt)
  {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                 me.name, parv[0], 0, link_s[me.fd],
                 link_u[me.fd], "<No_match>", *(me.serv->by) ?
                 me.serv->by : "*", "*", me.name, 0, 0);
    return 0;
  }
  for (cltmp = FirstClass(); doall && cltmp; cltmp = NextClass(cltmp))
    if (Links(cltmp) > 0)
      sendto_one(sptr, rpl_str(RPL_TRACECLASS), me.name,
                 parv[0], ConClass(cltmp), Links(cltmp));
  return 0;
}

/*
 * ms_trace - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nick or servername
 * parv[2] = 'target' servername
 */
int ms_trace(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int i;
  struct Client *acptr;
  struct ConfClass *cltmp;
  char *tname;
  int doall, link_s[MAXCONNECTIONS], link_u[MAXCONNECTIONS];
  int cnt = 0, wilds, dow;

  if (parc < 2 || BadPtr(parv[1]))
  {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = me.name;
    i = HUNTED_ISME;
  }
  else if (parc < 3 || BadPtr(parv[2]))
  {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr)))
    {
      if (IsUser(acptr))
        parv[2] = acptr->user->server->name;
      else
        parv[2] = acptr->name;
      parc = 3;
      parv[3] = 0;
      if ((i = hunt_server(IsServer(acptr), cptr, sptr,
          "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    }
    else
      i = HUNTED_ISME;
  }
  else
  {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server(0, cptr, sptr,
        "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS)
  {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = acptr->from;
    sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
#ifndef GODMODE
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>");
#else /* GODMODE */
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>",
        (acptr && acptr->from->serv) ? acptr->from->serv->timestamp : 0);
#endif /* GODMODE */
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, me.name) : 1;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall)
  {
    for (acptr = GlobalClientList; acptr; acptr = acptr->next) {
      if (IsUser(acptr))
        link_u[acptr->from->fd]++;
      else if (IsServer(acptr))
        link_s[acptr->from->fd]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++)
  {
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, acptr->name))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, acptr->name))
      continue;
    conClass = get_client_class(acptr);

    switch (acptr->status)
    {
      case STAT_CONNECTING:
        sendto_one(sptr, rpl_str(RPL_TRACECONNECTING),
                   me.name, parv[0], conClass, acptr->name);
        cnt++;
        break;
      case STAT_HANDSHAKE:
        sendto_one(sptr, rpl_str(RPL_TRACEHANDSHAKE),
                   me.name, parv[0], conClass, acptr->name);
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
                   me.name, parv[0], conClass, get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
      case STAT_UNKNOWN_SERVER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
                   me.name, parv[0], conClass, "Unknown Server");
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr))
        {
          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
                me.name, parv[0], conClass, get_client_name(acptr, SHOW_IP),
                CurrentTime - acptr->lasttime);
          else
            sendto_one(sptr, rpl_str(RPL_TRACEUSER),
                me.name, parv[0], conClass, get_client_name(acptr, SHOW_IP),
                CurrentTime - acptr->lasttime);
          cnt++;
        }
        break;
        /*
         * Connection is a server
         *
         * Serv <class> <nS> <nC> <name> <ConnBy> <last> <age>
         *
         * class        Class the server is in
         * nS           Number of servers reached via this link
         * nC           Number of clients reached via this link
         * name         Name of the server linked
         * ConnBy       Who established this link
         * last         Seconds since we got something from this link
         * age          Seconds this link has been alive
         *
         * Additional comments etc......        -Cym-<cym@acrux.net>
         */

      case STAT_SERVER:
        if (acptr->serv->user)
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                     me.name, parv[0], conClass, link_s[i],
                     link_u[i], acptr->name,
                     (*acptr->serv->by) ? acptr->serv->by : "*",
                     acptr->serv->user->username, acptr->serv->user->host,
                     CurrentTime - acptr->lasttime,
                     CurrentTime - acptr->serv->timestamp);
        else
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                     me.name, parv[0], conClass, link_s[i],
                     link_u[i], acptr->name,
                     (*acptr->serv->by) ?  acptr->serv->by : "*", "*",
                     me.name, CurrentTime - acptr->lasttime,
                     CurrentTime - acptr->serv->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
        sendto_one(sptr, rpl_str(RPL_TRACENEWTYPE), me.name, parv[0],
                   get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt)
  {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      sendto_one(sptr, rpl_str(RPL_TRACESERVER),
          me.name, parv[0], 0, link_s[me.fd],
          link_u[me.fd], "<No_match>", *(me.serv->by) ?
          me.serv->by : "*", "*", me.name, 0, 0);
    return 0;
  }
  for (cltmp = FirstClass(); doall && cltmp; cltmp = NextClass(cltmp))
    if (Links(cltmp) > 0)
      sendto_one(sptr, rpl_str(RPL_TRACECLASS), me.name,
          parv[0], ConClass(cltmp), Links(cltmp));
  return 0;
}

/*
 * mo_trace - oper message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nick or servername
 * parv[2] = 'target' servername
 */
int mo_trace(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int i;
  struct Client *acptr;
  struct ConfClass *cltmp;
  char *tname;
  int doall, link_s[MAXCONNECTIONS], link_u[MAXCONNECTIONS];
  int cnt = 0, wilds, dow;

  if (parc < 2 || BadPtr(parv[1]))
  {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = me.name;
    i = HUNTED_ISME;
  }
  else if (parc < 3 || BadPtr(parv[2]))
  {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr)))
    {
      if (IsUser(acptr))
        parv[2] = acptr->user->server->name;
      else
        parv[2] = acptr->name;
      parc = 3;
      parv[3] = 0;
      if ((i = hunt_server(IsServer(acptr), cptr, sptr,
          "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    }
    else
      i = HUNTED_ISME;
  }
  else
  {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server(0, cptr, sptr,
        "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS)
  {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = acptr->from;
    sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
#ifndef GODMODE
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>");
#else /* GODMODE */
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>",
        (acptr && acptr->from->serv) ? acptr->from->serv->timestamp : 0);
#endif /* GODMODE */
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, me.name) : 1;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall)
  {
    for (acptr = GlobalClientList; acptr; acptr = acptr->next) {
      if (IsUser(acptr))
        link_u[acptr->from->fd]++;
      else if (IsServer(acptr))
        link_s[acptr->from->fd]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++)
  {
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, acptr->name))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, acptr->name))
      continue;
    conClass = get_client_class(acptr);

    switch (acptr->status)
    {
      case STAT_CONNECTING:
        sendto_one(sptr, rpl_str(RPL_TRACECONNECTING),
                   me.name, parv[0], conClass, acptr->name);
        cnt++;
        break;
      case STAT_HANDSHAKE:
        sendto_one(sptr, rpl_str(RPL_TRACEHANDSHAKE),
                   me.name, parv[0], conClass, acptr->name);
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
                   me.name, parv[0], conClass, get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
      case STAT_UNKNOWN_SERVER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
                   me.name, parv[0], conClass, "Unknown Server");
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr))
        {
          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
                       me.name, parv[0], conClass, get_client_name(acptr, SHOW_IP),
                       CurrentTime - acptr->lasttime);
          else
            sendto_one(sptr, rpl_str(RPL_TRACEUSER),
                       me.name, parv[0], conClass, get_client_name(acptr, SHOW_IP),
                       CurrentTime - acptr->lasttime);
          cnt++;
        }
        break;
        /*
         * Connection is a server
         *
         * Serv <class> <nS> <nC> <name> <ConnBy> <last> <age>
         *
         * class        Class the server is in
         * nS           Number of servers reached via this link
         * nC           Number of clients reached via this link
         * name         Name of the server linked
         * ConnBy       Who established this link
         * last         Seconds since we got something from this link
         * age          Seconds this link has been alive
         *
         * Additional comments etc......        -Cym-<cym@acrux.net>
         */

      case STAT_SERVER:
        if (acptr->serv->user)
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                     me.name, parv[0], conClass, link_s[i],
                     link_u[i], acptr->name,
                     (*acptr->serv->by) ? acptr->serv->by : "*",
                     acptr->serv->user->username, acptr->serv->user->host,
                     CurrentTime - acptr->lasttime,
                     CurrentTime - acptr->serv->timestamp);
        else
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                     me.name, parv[0], conClass, link_s[i],
                     link_u[i], acptr->name,
                     (*acptr->serv->by) ?  acptr->serv->by : "*", "*",
                     me.name, CurrentTime - acptr->lasttime,
                     CurrentTime - acptr->serv->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
        sendto_one(sptr, rpl_str(RPL_TRACENEWTYPE), me.name, parv[0],
                   get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt)
  {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                 me.name, parv[0], 0, link_s[me.fd],
                 link_u[me.fd], "<No_match>", *(me.serv->by) ?
                 me.serv->by : "*", "*", me.name, 0, 0);
    return 0;
  }
  for (cltmp = FirstClass(); doall && cltmp; cltmp = NextClass(cltmp))
    if (Links(cltmp) > 0)
      sendto_one(sptr, rpl_str(RPL_TRACECLASS), me.name,
                 parv[0], ConClass(cltmp), Links(cltmp));
  return 0;
}

  
#if 0
/*
 * m_trace
 *
 * parv[0] = sender prefix
 * parv[1] = nick or servername
 * parv[2] = 'target' servername
 */
int m_trace(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  int i;
  struct Client *acptr;
  struct ConfClass *cltmp;
  char *tname;
  int doall, link_s[MAXCONNECTIONS], link_u[MAXCONNECTIONS];
  int cnt = 0, wilds, dow;

  if (parc < 2 || BadPtr(parv[1]))
  {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = me.name;
    i = HUNTED_ISME;
  }
  else if (parc < 3 || BadPtr(parv[2]))
  {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr)))
    {
      if (IsUser(acptr))
        parv[2] = acptr->user->server->name;
      else
        parv[2] = acptr->name;
      parc = 3;
      parv[3] = 0;
      if ((i = hunt_server(IsServer(acptr), cptr, sptr,
          "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    }
    else
      i = HUNTED_ISME;
  }
  else
  {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server(0, cptr, sptr,
        "%s%s " TOK_TRACE " %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS)
  {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = acptr->from;
    sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
#ifndef GODMODE
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>");
#else /* GODMODE */
        version, debugmode, tname, acptr ? acptr->from->name : "<No_match>",
        (acptr && acptr->from->serv) ? acptr->from->serv->timestamp : 0);
#endif /* GODMODE */
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, me.name) : TRUE;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall)
  {
    for (acptr = GlobalClientList; acptr; acptr = acptr->next) {
      if (IsUser(acptr))
        link_u[acptr->from->fd]++;
      else if (IsServer(acptr))
        link_s[acptr->from->fd]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++)
  {
    const char* name;
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, acptr->name))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, acptr->name))
      continue;
    conClass = get_client_class(acptr);

    switch (acptr->status)
    {
      case STAT_CONNECTING:
        sendto_one(sptr, rpl_str(RPL_TRACECONNECTING),
            me.name, parv[0], conClass, name);
        cnt++;
        break;
      case STAT_HANDSHAKE:
        sendto_one(sptr, rpl_str(RPL_TRACEHANDSHAKE),
            me.name, parv[0], conClass, name);
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
      case STAT_UNKNOWN_SERVER:
        sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
            me.name, parv[0], conClass, name);
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr))
        {
          if (IsAnOper(acptr))
            sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
                me.name, parv[0], conClass, name, CurrentTime - acptr->lasttime);
          else
            sendto_one(sptr, rpl_str(RPL_TRACEUSER),
                me.name, parv[0], conClass, name, CurrentTime - acptr->lasttime);
          cnt++;
        }
        break;
        /*
         * Connection is a server
         *
         * Serv <class> <nS> <nC> <name> <ConnBy> <last> <age>
         *
         * class        Class the server is in
         * nS           Number of servers reached via this link
         * nC           Number of clients reached via this link
         * name         Name of the server linked
         * ConnBy       Who established this link
         * last         Seconds since we got something from this link
         * age          Seconds this link has been alive
         *
         * Additional comments etc......        -Cym-<cym@acrux.net>
         */

      case STAT_SERVER:
        if (acptr->serv->user)
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
              me.name, parv[0], conClass, link_s[i],
              link_u[i], name, (*acptr->serv->by) ? acptr->serv->by : "*",
              acptr->serv->user->username, acptr->serv->user->host,
              CurrentTime - acptr->lasttime,
              CurrentTime - acptr->serv->timestamp);
        else
          sendto_one(sptr, rpl_str(RPL_TRACESERVER),
              me.name, parv[0], conClass, link_s[i],
              link_u[i], name, (*acptr->serv->by) ?  acptr->serv->by : "*", "*",
              me.name, CurrentTime - acptr->lasttime,
              CurrentTime - acptr->serv->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
        sendto_one(sptr, rpl_str(RPL_TRACENEWTYPE), me.name, parv[0], name);
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt)
  {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      sendto_one(sptr, rpl_str(RPL_TRACESERVER),
          me.name, parv[0], 0, link_s[me.fd],
          link_u[me.fd], "<No_match>", *(me.serv->by) ?
          me.serv->by : "*", "*", me.name, 0, 0);
    return 0;
  }
  for (cltmp = FirstClass(); doall && cltmp; cltmp = NextClass(cltmp))
    if (Links(cltmp) > 0)
      sendto_one(sptr, rpl_str(RPL_TRACECLASS), me.name,
          parv[0], ConClass(cltmp), Links(cltmp));
  return 0;
}
#endif /* 0 */

