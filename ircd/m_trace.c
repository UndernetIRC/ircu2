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
#include "config.h"

#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
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
  const struct ConnectionClass* cl;
  char* tname;
  int doall;
  int link_s[MAXCONNECTIONS];
  int link_u[MAXCONNECTIONS];
  int cnt = 0;
  int wilds;
  int dow;

  if (feature_bool(FEAT_HIS_TRACE))
    return send_reply(cptr, ERR_NOPRIVILEGES);

  if (parc < 2 || BadPtr(parv[1])) {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = cli_name(&me);
    i = HUNTED_ISME;
  } else if (parc < 3 || BadPtr(parv[2])) {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr))) {
      if (IsUser(acptr))
        parv[2] = cli_name(cli_user(acptr)->server);
      else
        parv[2] = cli_name(acptr);
      parc = 3;
      parv[3] = 0;
      if ((i = hunt_server_cmd(sptr, CMD_TRACE, cptr, IsServer(acptr),
			       "%s :%C", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    } else
      i = HUNTED_ISME;
  } else {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server_cmd(sptr, CMD_TRACE, cptr, 0, "%s :%C", 2, parc,
			     parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS) {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = cli_from(acptr);
    send_reply(sptr, RPL_TRACELINK,
	       version, debugmode, tname,
	       acptr ? cli_name(cli_from(acptr)) : "<No_match>");
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, cli_name(&me)) : 1;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall) {
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (IsUser(acptr))
        link_u[cli_fd(cli_from(acptr))]++;
      else if (IsServer(acptr))
        link_s[cli_fd(cli_from(acptr))]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++) {
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, cli_name(acptr)))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, cli_name(acptr)))
      continue;

    conClass = get_client_class(acptr);

    switch (cli_status(acptr)) {
      case STAT_CONNECTING:
	send_reply(sptr, RPL_TRACECONNECTING, conClass, cli_name(acptr));
        cnt++;
        break;
      case STAT_HANDSHAKE:
	send_reply(sptr, RPL_TRACEHANDSHAKE, conClass, cli_name(acptr));
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
	send_reply(sptr, RPL_TRACEUNKNOWN, conClass,
		   get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
      case STAT_UNKNOWN_SERVER:
	send_reply(sptr, RPL_TRACEUNKNOWN, conClass, "Unknown Server");
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr)) {
          if (IsAnOper(acptr))
	    send_reply(sptr, RPL_TRACEOPERATOR, conClass,
		       get_client_name(acptr, SHOW_IP),
		       CurrentTime - cli_lasttime(acptr));
          else
	    send_reply(sptr, RPL_TRACEUSER, conClass,
		       get_client_name(acptr, SHOW_IP),
		       CurrentTime - cli_lasttime(acptr));
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
        if (cli_serv(acptr)->user)
	  send_reply(sptr, RPL_TRACESERVER, conClass, link_s[i],
                     link_u[i], cli_name(acptr),
                     (*(cli_serv(acptr))->by) ? cli_serv(acptr)->by : "*",
                     cli_serv(acptr)->user->username, cli_serv(acptr)->user->host,
                     CurrentTime - cli_lasttime(acptr),
                     CurrentTime - cli_serv(acptr)->timestamp);
	else
	  send_reply(sptr, RPL_TRACESERVER, conClass, link_s[i],
                     link_u[i], cli_name(acptr),
                     (*(cli_serv(acptr))->by) ?  cli_serv(acptr)->by : "*", "*",
                     cli_name(&me), CurrentTime - cli_lasttime(acptr),
		     CurrentTime - cli_serv(acptr)->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
	send_reply(sptr, RPL_TRACENEWTYPE, get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt) {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      send_reply(sptr, RPL_TRACESERVER, 0, link_s[cli_fd(&me)],
                 link_u[cli_fd(&me)], "<No_match>", *(cli_serv(&me)->by) ?
                 cli_serv(&me)->by : "*", "*", cli_name(&me), 0, 0);
    return 0;
  }
  if (doall) {
    for (cl = get_class_list(); cl; cl = cl->next) {
      if (Links(cl) > 0)
       send_reply(sptr, RPL_TRACECLASS, ConClass(cl), Links(cl));
    }
  }
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
  const struct ConnectionClass* cl;
  char *tname;
  int doall;
  int link_s[MAXCONNECTIONS];
  int link_u[MAXCONNECTIONS];
  int cnt = 0;
  int wilds;
  int dow;

  if (parc < 2 || BadPtr(parv[1])) {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = cli_name(&me);
    i = HUNTED_ISME;
  } else if (parc < 3 || BadPtr(parv[2])) {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr))) {
      if (IsUser(acptr))
        parv[2] = cli_name(cli_user(acptr)->server);
      else
        parv[2] = cli_name(acptr);
      parc = 3;
      parv[3] = 0;

      if ((i = hunt_server_cmd(sptr, CMD_TRACE, cptr, IsServer(acptr),
			       "%s :%C", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    } else
      i = HUNTED_ISME;
  } else {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server_cmd(sptr, CMD_TRACE, cptr, 0, "%s :%C", 2, parc,
			     parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS) {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = cli_from(acptr);
    send_reply(sptr, RPL_TRACELINK,
	       version, debugmode, tname,
	       acptr ? cli_name(cli_from(acptr)) : "<No_match>");
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, cli_name(&me)) : 1;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall) {
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (IsUser(acptr))
        link_u[cli_fd(cli_from(acptr))]++;
      else if (IsServer(acptr))
        link_s[cli_fd(cli_from(acptr))]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++) {
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, cli_name(acptr)))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, cli_name(acptr)))
      continue;
    conClass = get_client_class(acptr);

    switch (cli_status(acptr)) {
      case STAT_CONNECTING:
	send_reply(sptr, RPL_TRACECONNECTING, conClass, cli_name(acptr));
        cnt++;
        break;
      case STAT_HANDSHAKE:
	send_reply(sptr, RPL_TRACEHANDSHAKE, conClass, cli_name(acptr));
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
	send_reply(sptr, RPL_TRACEUNKNOWN, conClass,
		   get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
      case STAT_UNKNOWN_SERVER:
	send_reply(sptr, RPL_TRACEUNKNOWN, conClass, "Unknown Server");
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr)) {
          if (IsAnOper(acptr))
	    send_reply(sptr, RPL_TRACEOPERATOR, conClass,
		       get_client_name(acptr, SHOW_IP),
		       CurrentTime - cli_lasttime(acptr));
          else
	    send_reply(sptr, RPL_TRACEUSER, conClass,
		       get_client_name(acptr, SHOW_IP),
		       CurrentTime - cli_lasttime(acptr));
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
        if (cli_serv(acptr)->user)
	  send_reply(sptr, RPL_TRACESERVER, conClass, link_s[i],
                     link_u[i], cli_name(acptr),
                     (*(cli_serv(acptr))->by) ? cli_serv(acptr)->by : "*",
                     cli_serv(acptr)->user->username, cli_serv(acptr)->user->host,
                     CurrentTime - cli_lasttime(acptr),
                     CurrentTime - cli_serv(acptr)->timestamp);
        else
	  send_reply(sptr, RPL_TRACESERVER, conClass, link_s[i],
                     link_u[i], cli_name(acptr),
                     (*(cli_serv(acptr))->by) ? cli_serv(acptr)->by : "*", "*",
                     cli_name(&me), CurrentTime - cli_lasttime(acptr),
                     CurrentTime - cli_serv(acptr)->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
	send_reply(sptr, RPL_TRACENEWTYPE, get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt) {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      send_reply(sptr, RPL_TRACESERVER, 0, link_s[cli_fd(&me)],
          link_u[cli_fd(&me)], "<No_match>", *(cli_serv(&me)->by) ?
          cli_serv(&me)->by : "*", "*", cli_name(&me), 0, 0);
    return 0;
  }
  if (doall) {
    for (cl = get_class_list(); cl; cl = cl->next) {
      if (Links(cl) > 0)
        send_reply(sptr, RPL_TRACECLASS, ConClass(cl), Links(cl));
    }
  }
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
  int               i;
  struct Client*    acptr;
  const struct ConnectionClass* cl;
  char*             tname;
  int doall;
  int link_s[MAXCONNECTIONS];
  int link_u[MAXCONNECTIONS];
  int cnt = 0;
  int wilds;
  int dow;

  if (parc < 2 || BadPtr(parv[1])) {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = cli_name(&me);
    i = HUNTED_ISME;
  } else if (parc < 3 || BadPtr(parv[2])) {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
        ((acptr = FindClient(parv[1])) && !MyUser(acptr))) {
      if (IsUser(acptr))
        parv[2] = cli_name(cli_user(acptr)->server);
      else
        parv[2] = cli_name(acptr);
      parc = 3;
      parv[3] = 0;
      if ((i = hunt_server_cmd(sptr, CMD_TRACE, cptr, IsServer(acptr),
			       "%s :%C", 2, parc, parv)) == HUNTED_NOSUCH)
        return 0;
    } else
      i = HUNTED_ISME;
  } else {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server_cmd(sptr, CMD_TRACE, cptr, 0, "%s :%C", 2, parc,
			     parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS) {
    if (!acptr)
      acptr = next_client(GlobalClientList, tname);
    else
      acptr = cli_from(acptr);
    send_reply(sptr, RPL_TRACELINK,
	       version, debugmode, tname,
	       acptr ? cli_name(cli_from(acptr)) : "<No_match>");
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, cli_name(&me)) : 1;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall) {
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (IsUser(acptr))
        link_u[cli_fd(cli_from(acptr))]++;
      else if (IsServer(acptr))
        link_s[cli_fd(cli_from(acptr))]++;
    }
  }

  /* report all direct connections */

  for (i = 0; i <= HighestFd; i++) {
    unsigned int conClass;

    if (!(acptr = LocalClientArray[i])) /* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
        !IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, cli_name(acptr)))
      continue;
    if (!dow && 0 != ircd_strcmp(tname, cli_name(acptr)))
      continue;
    conClass = get_client_class(acptr);

    switch (cli_status(acptr)) {
      case STAT_CONNECTING:
	send_reply(sptr, RPL_TRACECONNECTING, conClass, cli_name(acptr));
        cnt++;
        break;
      case STAT_HANDSHAKE:
	send_reply(sptr, RPL_TRACEHANDSHAKE, conClass, cli_name(acptr));
        cnt++;
        break;
      case STAT_ME:
        break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
	send_reply(sptr, RPL_TRACEUNKNOWN, conClass,
		   get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
      case STAT_UNKNOWN_SERVER:
	send_reply(sptr, RPL_TRACEUNKNOWN, conClass, "Unknown Server");
        cnt++;
        break;
      case STAT_USER:
        /* Only opers see users if there is a wildcard
           but anyone can see all the opers. */
        if ((IsAnOper(sptr) && (MyUser(sptr) ||
            !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr)) {
          if (IsAnOper(acptr))
	    send_reply(sptr, RPL_TRACEOPERATOR, conClass,
		       get_client_name(acptr, SHOW_IP),
                       CurrentTime - cli_lasttime(acptr));
          else
	    send_reply(sptr, RPL_TRACEUSER, conClass,
		       get_client_name(acptr, SHOW_IP),
                       CurrentTime - cli_lasttime(acptr));
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
        if (cli_serv(acptr)->user)
	  send_reply(sptr, RPL_TRACESERVER, conClass, link_s[i],
                     link_u[i], cli_name(acptr),
                     (*(cli_serv(acptr))->by) ? cli_serv(acptr)->by : "*",
                     cli_serv(acptr)->user->username, cli_serv(acptr)->user->host,
                     CurrentTime - cli_lasttime(acptr),
                     CurrentTime - cli_serv(acptr)->timestamp);
        else
	  send_reply(sptr, RPL_TRACESERVER, conClass, link_s[i],
                     link_u[i], cli_name(acptr),
                     (*(cli_serv(acptr))->by) ? cli_serv(acptr)->by : "*", "*",
                     cli_name(&me), CurrentTime - cli_lasttime(acptr),
                     CurrentTime - cli_serv(acptr)->timestamp);
        cnt++;
        break;
      default:                  /* We actually shouldn't come here, -msa */
	send_reply(sptr, RPL_TRACENEWTYPE, get_client_name(acptr, HIDE_IP));
        cnt++;
        break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt) {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      send_reply(sptr, RPL_TRACESERVER, 0, link_s[cli_fd(&me)],
                 link_u[cli_fd(&me)], "<No_match>", *(cli_serv(&me)->by) ?
                 cli_serv(&me)->by : "*", "*", cli_name(&me), 0, 0);
    return 0;
  }
  if (doall) {
    for (cl = get_class_list(); cl; cl = cl->next) {
      if (Links(cl) > 0)
        send_reply(sptr, RPL_TRACECLASS, ConClass(cl), Links(cl));
    }
  }
  return 0;
}


