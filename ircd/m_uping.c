/*
 * IRC - Internet Relay Chat, ircd/m_uping.c
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

#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"
#include "uping.h"


#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * ms_uping - server message handler
 *
 * m_uping  -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = pinged server
 * parv[2] = port
 * parv[3] = hunted server
 * parv[4] = number of requested pings
 */
int ms_uping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem *aconf;
  int port;
  int count;

  assert(0 != cptr);
  assert(0 != sptr);

  if (!IsAnOper(sptr)) {
    send_reply(sptr, ERR_NOPRIVILEGES);
    return 0;
  }

  if (parc < 5) {
    send_reply(sptr, ERR_NEEDMOREPARAMS, "UPING");
    return 0;
  }

  if (hunt_server_cmd(sptr, CMD_UPING, cptr, 1, "%s %s %C %s", 3, parc, parv)
      != HUNTED_ISME)
    return 0;
  /*
   * Determine port: First user supplied, then default : 7007
   */
  if (EmptyString(parv[2]) || (port = atoi(parv[2])) <= 0)
    port = atoi(UDP_PORT);

  if (EmptyString(parv[4]) || (count = atoi(parv[4])) <= 0)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING : Illegal number of "
		  "packets: %s", sptr, parv[4]);
    return 0;
  }
  /* 
   * Check if a CONNECT would be possible at all (adapted from m_connect)
   */
  if ((aconf = conf_find_server(parv[1])))
    uping_server(sptr, aconf, port, count);
  else
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Host %s not listed in "
		  "ircd.conf", sptr, parv[1]);

  return 0;
}

/*
 * mo_uping - oper message handler
 *
 * m_uping  -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = pinged server
 * parv[2] = port
 * parv[3] = hunted server
 * parv[4] = number of requested pings
 */
int mo_uping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem *aconf;
  int port;
  int count;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);

  assert(IsAnOper(sptr));

  if (parc < 2) {
    send_reply(sptr, ERR_NEEDMOREPARAMS, "UPING");
    return 0;
  }

  if (parc == 2) {
    parv[parc++] = UDP_PORT;
    parv[parc++] = cli_name(&me);
    parv[parc++] = "5";
  }
  else if (parc == 3) {
    if (IsDigit(*parv[2]))
      parv[parc++] = cli_name(&me);
    else {
      parv[parc++] = parv[2];
      parv[2] = UDP_PORT;
    }
    parv[parc++] = "5";
  }
  else if (parc == 4) {
    if (IsDigit(*parv[2])) {
      if (IsDigit(*parv[3])) {
        parv[parc++] = parv[3];
        parv[3] = cli_name(&me);
      }
      else
        parv[parc++] = "5";
    }
    else {
      parv[parc++] = parv[3];
      parv[3] = parv[2];
      parv[2] = UDP_PORT;
    }
  }
  if (hunt_server_cmd(sptr, CMD_UPING, sptr, 1, "%s %s %C %s", 3, parc, parv)
      != HUNTED_ISME)
    return 0;
  /*
   * Determine port: First user supplied, then default : 7007
   */
  if (EmptyString(parv[2]) || (port = atoi(parv[2])) <= 0)
    port = atoi(UDP_PORT);

  if (EmptyString(parv[4]) || (count = atoi(parv[4])) <= 0)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Illegal number of "
		  "packets: %s", sptr, parv[4]);
    return 0;
  }
  /* 
   * Check if a CONNECT would be possible at all (adapted from m_connect)
   */
  if ((aconf = conf_find_server(parv[1])))
    uping_server(sptr, aconf, port, count);
  else {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Host %s not listed in "
		  "ircd.conf", sptr, parv[1]);
  }
  return 0;
}


#if 0
/*
 * m_uping  -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = pinged server
 * parv[2] = port
 * parv[3] = hunted server
 * parv[4] = number of requested pings
 */
int m_uping(struct Client* cptr, struct Client *sptr, int parc, char *parv[])
{
  struct ConfItem *aconf;
  int port;
  int fd;
  struct UPing* pptr = 0;

  if (!IsPrivileged(sptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]); /* XXX DEAD */
    return -1;
  }

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "UPING"); /* XXX DEAD */
    return 0;
  }

  if (MyUser(sptr))
  {
    if (parc == 2)
    {
      parv[parc++] = UDP_PORT;
      parv[parc++] = me.name;
      parv[parc++] = "5";
    }
    else if (parc == 3)
    {
      if (IsDigit(*parv[2]))
	parv[parc++] = me.name;
      else
      {
	parv[parc++] = parv[2];
	parv[2] = UDP_PORT;
      }
      parv[parc++] = "5";
    }
    else if (parc == 4)
    {
      if (IsDigit(*parv[2]))
      {
	if (IsDigit(*parv[3]))
	{
	  parv[parc++] = parv[3];
	  parv[3] = me.name;
	}
	else
	  parv[parc++] = "5";
      }
      else
      {
	parv[parc++] = parv[3];
	parv[3] = parv[2];
	parv[2] = UDP_PORT;
      }
    }
  }
  if (hunt_server(1, cptr, sptr, ":%s UPING %s %s %s %s", 3, parc, parv) != HUNTED_ISME) /* XXX DEAD */
    return 0;

  if (BadPtr(parv[4]) || atoi(parv[4]) <= 0)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Illegal number of packets: %s", /* XXX DEAD */
	  me.name, parv[0], parv[4]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: Illegal number of packets: %s", /* XXX DEAD */
	  NumServ(&me), NumNick(sptr), parv[4]);
    return 0;
  }

  /* Check if a CONNECT would be possible at all (adapted from m_connect) */
  for (aconf = GlobalConfList; aconf; aconf = aconf->next)
  {
    if (aconf->status == CONF_SERVER &&
	match(parv[1], aconf->name) == 0)
      break;
  }
  if (!aconf)
  {
    for (aconf = GlobalConfList; aconf; aconf = aconf->next)
    {
      if (aconf->status == CONF_SERVER &&
	  (match(parv[1], aconf->host) == 0 ||
	   match(parv[1], strchr(aconf->host, '@') + 1) == 0))
	break;
    }
  }
  if (!aconf)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Host %s not listed in ircd.conf", /* XXX DEAD */
	  me.name, parv[0], parv[1]);
    else
      sendto_one(sptr, /* XXX DEAD */
	  "%s NOTICE %s%s :UPING: Host %s not listed in ircd.conf",
	  NumServ(&me), NumNick(sptr), parv[1]);
    return 0;
  }

  if (IsUPing(sptr))
    cancel_ping(sptr, sptr);  /* Cancel previous ping request */

  /*
   * Determine port: First user supplied, then default : 7007
   */
  if (BadPtr(parv[2]) || (port = atoi(parv[2])) <= 0)
    port = atoi(UDP_PORT);

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    int err = errno;
    sendto_ops("m_uping: socket: %s", (err != EMFILE)  /* XXX DEAD */
                ? ((strerror(err)) ? strerror(err) : "Unknown error") : "No more sockets");
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr,  /* XXX DEAD */
                 ":%s NOTICE %s :UPING: Unable to create udp ping socket",
                 me.name, parv[0]);
    else
      sendto_one(sptr, /* XXX DEAD */
                 "%s NOTICE %s%s :UPING: Unable to create udp ping socket",
                 NumServ(&me), NumNick(sptr));
    ircd_log(L_ERROR, "UPING: Unable to create UDP socket"); /* XXX DEAD */
    return 0;
  }

  if (!os_set_nonblocking(fd)) {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Can't set fd non-blocking", /* XXX DEAD */
            me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: Can't set fd non-blocking", /* XXX DEAD */
            NumServ(&me), NumNick(sptr));
    close(fd);
    return 0;
  }
  pptr = (struct UPing*) MyMalloc(sizeof(struct UPing));
  assert(0 != pptr);
  memset(pptr, 0, sizeof(struct UPing));

  pptr->fd = fd;
  pptr->sin.sin_port = htons(port);
  pptr->sin.sin_addr.s_addr = aconf->ipnum.s_addr;
  pptr->sin.sin_family = AF_INET;
  pptr->count = IRCD_MIN(20, atoi(parv[4]));
  strcpy(pptr->name, aconf->host);
  pptr->client = sptr;
  pptr->index = -1;

  pptr->next = pingList;
  pingList = pptr;

  SetUPing(sptr);
  ping_server(pptr);
  return 0;
}
#endif /* 0 */

