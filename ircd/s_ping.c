/*
 * IRC - Internet Relay Chat, ircd/s_ping.c
 * Copyright (C) 1994 Carlo Wood ( Run @ undernet.org )
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 */

#include "sys.h"
#include <sys/socket.h>
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef	UNIXPORT
#include <sys/un.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdlib.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include "h.h"
#include "struct.h"
#include "send.h"
#include "s_conf.h"
#include "match.h"
#include "res.h"
#include "s_bsd.h"
#include "s_serv.h"
#include "ircd.h"
#include "s_ping.h"
#include "support.h"
#include "numeric.h"
#include "s_user.h"
#include "s_err.h"
#include "common.h"
#include "s_user.h"
#include "numnicks.h"

RCSTAG_CC("$Id$");

#define UPINGBUFSIZE 2000	/* Lot bigger then 1024,
				   bit smaller then 2048 */
#define UPINGTIMEOUT 120	/* Timeout waitting for first ping response */

/*
 * start_ping
 *
 * As for now, I am abusing the client structure for a ping connection.
 *                 .... And I really don't like this solution --Nemesi
 * Used members are:
 * These are used by existing routines as well, and do have their own meaning:
 *   fd       : The socket file descriptor.
 *   status   : To flag that this IS one of these abused ping structures
 *   sockhost : Name of requested server to ping (aconf->host).
 *   name     : aconf->name
 *   ip       : ip#
 * These have more or less their own meaning,
 * but are not used by existing routines:
 *   flags    : To flag that a next ping is requested.
 *   port     : Requested remote port.
 * These are only used by the 'uping' routines
 * and have totally different meanings:
 *   buffer   : buffer hold pingtimes of received packets
 *   confs    : recv/send (char *) buffer.
 *   hopcount : Total number of requested pings
 *   sendB    : Number of pings left to send.
 *   receiveB : Number of pings left to be received.
 *   acpt     : client asking for this ping
 *   lasttime : last time a ping was sent
 *   firsttime: recvfrom timeout
 *   since    : timeout in seconds to next recvfrom
 *   receiveK : minimum in ms
 *   sendM    : average in ms
 *   receiveM : maximum in ms
 */
int start_ping(aClient *cptr)
{
  struct sockaddr_in remote_addr;

  Debug((DEBUG_NOTICE, "start_ping(%p) status %d", cptr, cptr->status));

  if (!(cptr->acpt))
    return -1;

  memcpy(&remote_addr.sin_addr, &cptr->ip, sizeof(struct in_addr));
#ifdef TESTNET
  remote_addr.sin_port = htons(cptr->port + 10000);
#else
  remote_addr.sin_port = htons(cptr->port);
#endif
  remote_addr.sin_family = AF_INET;

  if (MyUser(cptr->acpt) || Protocol(cptr->acpt->from) < 10)
  {
    sendto_one(cptr->acpt,
	":%s NOTICE %s :Sending %d ping%s to %s[%s] port %u",
	me.name, cptr->acpt->name, cptr->hopcount,
	(cptr->hopcount == 1) ? "" : "s", cptr->name,
#ifdef TESTNET
	inetntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port) - 10000);
#else
	inetntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));
#endif
  }
  else
  {
    sendto_one(cptr->acpt,
	"%s NOTICE %s%s :Sending %d ping%s to %s[%s] port %u",
	NumServ(&me), NumNick(cptr->acpt), cptr->hopcount,
	(cptr->hopcount == 1) ? "" : "s", cptr->name,
#ifdef TESTNET
	inetntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port) - 10000);
#else
	inetntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));
#endif
  }

  cptr->firsttime = now + UPINGTIMEOUT;
  cptr->since = UPINGTIMEOUT;
  cptr->flags |= (FLAGS_PING);

  return 0;
}

/*
 * send_ping
 *
 */
void send_ping(aClient *cptr)
{
  struct sockaddr_in remote_addr;
  struct timeval tv;

  memcpy(&remote_addr.sin_addr, &cptr->ip, sizeof(struct in_addr));
#ifdef TESTNET
  remote_addr.sin_port = htons(cptr->port + 10000);
#else
  remote_addr.sin_port = htons(cptr->port);
#endif
  remote_addr.sin_family = AF_INET;

  gettimeofday(&tv, NULL);
#if defined(__sun__) || (__GLIBC__ >= 2) || defined(__NetBSD__)
  sprintf((char *)cptr->confs, " %10lu%c%6lu", tv.tv_sec, '\0', tv.tv_usec);
#else
  sprintf((char *)cptr->confs, " %10u%c%6u", tv.tv_sec, '\0', tv.tv_usec);
#endif

  Debug((DEBUG_SEND, "send_ping: sending [%s %s] to %s.%d on %d",
      (char *)cptr->confs, (char *)cptr->confs + 12,
      inetntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port), cptr->fd));

  if (sendto(cptr->fd, (char *)cptr->confs, 1024, 0,
      (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in)) != 1024)
  {
#ifdef DEBUGMODE
    int err = errno;
#endif
    if (cptr->acpt)
    {
      if (MyUser(cptr->acpt)
#ifndef NO_PROTOCOL9
	  || (IsServer(cptr->acpt->from) && Protocol(cptr->acpt->from) < 10)
#endif
	  )
	sendto_one(cptr->acpt, ":%s NOTICE %s :UPING: sendto() failed: %s",
	    me.name, cptr->acpt->name, strerror(get_sockerr(cptr)));
      else
	sendto_one(cptr->acpt, "%s NOTICE %s%s :UPING: sendto() failed: %s",
	    NumServ(&me), NumNick(cptr->acpt), strerror(get_sockerr(cptr)));
    }
    Debug((DEBUG_SEND, "send_ping: sendto failed on %d (%d)", cptr->fd, err));
    end_ping(cptr);
  }
  else if (--(cptr->sendB) <= 0)
  {
    ClearPing(cptr);
    if (cptr->receiveB <= 0)
      end_ping(cptr);
  }

  return;
}

/*
 * read_ping
 */
void read_ping(aClient *cptr)
{
  size_t addr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in remote_addr;
  struct timeval tv;
  int len;
  unsigned long int pingtime;
  char *s;

  memcpy(&remote_addr.sin_addr, &cptr->ip, sizeof(struct in_addr));
#ifdef TESTNET
  remote_addr.sin_port = htons(cptr->port + 10000);
#else
  remote_addr.sin_port = htons(cptr->port);
#endif
  remote_addr.sin_family = AF_INET;

  gettimeofday(&tv, NULL);

  if ((len = recvfrom(cptr->fd, (char *)cptr->confs, UPINGBUFSIZE, 0,
      (struct sockaddr *)&remote_addr, &addr_len)) == -1)
  {
    int err = errno;
    if (MyUser(cptr->acpt)
#ifndef NO_PROTOCOL9
	|| (IsServer(cptr->acpt->from) && Protocol(cptr->acpt->from) < 10)
#endif
	)
      sendto_one(cptr->acpt, ":%s NOTICE %s :UPING: recvfrom: %s",
	  me.name, cptr->acpt->name, strerror(get_sockerr(cptr)));
    else
      sendto_one(cptr->acpt, "%s NOTICE %s%s :UPING: recvfrom: %s",
	  NumServ(&me), NumNick(cptr->acpt), strerror(get_sockerr(cptr)));
    Debug((DEBUG_SEND, "read_ping: recvfrom: %d", err));
    if (err != EAGAIN)
      end_ping(cptr);
    return;
  }

  if (len < 19)
    return;			/* Broken packet */

  pingtime = (tv.tv_sec - atoi((char *)cptr->confs + 1)) * 1000 +
      (tv.tv_usec - atoi((char *)cptr->confs + strlen((char *)cptr->confs) +
      1)) / 1000;
  cptr->sendM += pingtime;
  if (!(cptr->receiveK) || (cptr->receiveK > pingtime))
    cptr->receiveK = pingtime;
  if (pingtime > cptr->receiveM)
    cptr->receiveM = pingtime;
  /* Wait at most 10 times the average pingtime for the next one: */
  if ((cptr->since =
      cptr->sendM / (100 * (cptr->hopcount - cptr->receiveB + 1))) < 2)
    cptr->since = 2;
  cptr->firsttime = tv.tv_sec + cptr->since;

  Debug((DEBUG_SEND, "read_ping: %d bytes, ti " TIME_T_FMT ": [%s %s] %lu ms",
      len, cptr->since, (char *)cptr->confs,
      (char *)cptr->confs + strlen((char *)cptr->confs) + 1, pingtime));

  s = cptr->buffer + strlen(cptr->buffer);
  sprintf(s, " %lu", pingtime);

  if ((--(cptr->receiveB) <= 0 && !DoPing(cptr)) || !(cptr->acpt))
    end_ping(cptr);

  return;
}

int ping_server(aClient *cptr)
{
  if ((!cptr->ip.s_addr)
#ifdef UNIXPORT
      && ((cptr->sockhost[2]) != '/')
#endif
      )
  {
    struct hostent *hp;
    char *s;
    Link lin;

    if (!(cptr->acpt))
      return -1;		/* Oper left already */

    lin.flags = ASYNC_PING;
    lin.value.cptr = cptr;
    nextdnscheck = 1;
    s = strchr(cptr->sockhost, '@');
    s++;			/* should never be NULL;
				   cptr->sockhost is actually a conf->host */
    if ((cptr->ip.s_addr = inet_addr(s)) == INADDR_NONE)
    {
      cptr->ip.s_addr = INADDR_ANY;
      hp = gethost_byname(s, &lin);
      Debug((DEBUG_NOTICE, "ping_sv: hp %p ac %p ho %s", hp, cptr, s));
      if (!hp)
	return 0;
      memcpy(&cptr->ip, hp->h_addr, sizeof(struct in_addr));
    }
  }

  return start_ping(cptr);
}

/*
 * m_uping  -- by Run
 *
 * parv[0] = sender prefix
 * parv[1] = pinged server
 * parv[2] = port
 * parv[3] = hunted server
 * parv[4] = number of requested pings
 */
int m_uping(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  aConfItem *aconf;
  unsigned short int port;
  int fd, opt;
  char *p;

  if (!IsPrivileged(sptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return -1;
  }

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "UPING");
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
      if (isDigit(*parv[2]))
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
      if (isDigit(*parv[2]))
      {
	if (isDigit(*parv[3]))
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
  if (hunt_server(1, cptr, sptr,
      ":%s UPING %s %s %s %s", 3, parc, parv) != HUNTED_ISME)
    return 0;

  if (BadPtr(parv[4]) || atoi(parv[4]) <= 0)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Invalid number of packets: %s",
	  me.name, parv[0], parv[4]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: Invalid number of packets: %s",
	  NumServ(&me), NumNick(sptr), parv[4]);
    return 0;
  }

  /* Check if a CONNECT would be possible at all (adapted from m_connect) */
  if (parc > 2 && !BadPtr(parv[2]))
    p = strchr(parv[2], ':');
  else
    p = 0;
  if (p)
    *p = 0;
  for (aconf = conf; aconf; aconf = aconf->next)
    if (aconf->status == CONF_CONNECT_SERVER &&
	match(parv[1], aconf->name) == 0 &&
        (!p || match(parv[2], aconf->host) == 0 ||
	match(parv[2], strchr(aconf->host, '@') + 1) == 0))
      break;
  if (!aconf)
    for (aconf = conf; aconf; aconf = aconf->next)
      if (aconf->status == CONF_CONNECT_SERVER &&
	  (match(parv[1], aconf->host) == 0 ||
	  match(parv[1], strchr(aconf->host, '@') + 1) == 0))
	break;
  if (p)
    *p = ':';
  if (!aconf)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Host %s not listed in ircd.conf",
	  me.name, parv[0], parv[1]);
    else
      sendto_one(sptr,
	  "%s NOTICE %s%s :UPING: Host %s not listed in ircd.conf",
	  NumServ(&me), NumNick(sptr), parv[1]);
    return 0;
  }

  if (AskedPing(sptr))
    cancel_ping(sptr, sptr);	/* Cancel previous ping request */

  /*
   * Determine port: First user supplied, then default : 7007
   */
  if (!p || (port = atoi(p + 1)) <= 0)
    port = atoi(UDP_PORT);

  alarm(2);
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
  {
    int err = errno;
    alarm(0);
    sendto_ops("m_uping: socket: %s", (err != EAGAIN) ?
	strerror(err) : "No more sockets");
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Unable to create udp ping socket",
	  me.name, parv[0]);
    else
      sendto_one(sptr,
	  "%s NOTICE %s%s :UPING: Unable to create udp ping socket",
	  NumServ(&me), NumNick(sptr));
#ifdef	USE_SYSLOG
    syslog(LOG_ERR, "Unable to create udp ping socket");
#endif
    return 0;
  }
  alarm(0);

  if (fcntl(fd, F_SETFL, FNDELAY) == -1)
  {
    sendto_ops("m_uping: fcntl FNDELAY: %s", strerror(errno));
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Can't set fd non-blocking",
	  me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: Can't set fd non-blocking",
	  NumServ(&me), NumNick(sptr));
    close(fd);
    return 0;
  }
  /*
   * On some systems, receive and send buffers must be equal in size.
   * Others block select() when the buffers are too small
   * (Linux 1.1.50 blocks when < 2048) --Run
   */
  opt = 2048;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (OPT_TYPE *)&opt,
      sizeof(opt)) < 0 ||
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (OPT_TYPE *)&opt, sizeof(opt)) < 0)
  {
    int err = errno;
    sendto_ops("m_uping: setsockopt SO_SNDBUF|SO_RCVBUF: %s", strerror(err));
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: error in setsockopt: %s",
	  me.name, parv[0], strerror(err));
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: error in setsockopt: %s",
	  NumServ(&me), NumNick(sptr), strerror(err));
    close(fd);
    return 0;
  }

  if (fd >= MAXCONNECTIONS)
  {
    sendto_ops("Can't allocate fd for uping (all connections in use)");
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: All connections in use",
	  me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: All connections in use",
	  NumServ(&me), NumNick(sptr));
    close(fd);
    return 0;
  }
  if (bind(fd, (struct sockaddr *)&cserv, sizeof(cserv)) == -1)
  {
    sendto_ops("Failure binding fd for uping");
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: failure binding udp socket",
	  me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: failure binding udp socket",
	  NumServ(&me), NumNick(sptr));
    close(fd);
    return 0;
  }

  if (fd > highest_fd)
    highest_fd = fd;
  loc_clients[fd] = cptr = make_client(NULL, STAT_PING);
  cptr->confs = (Link *)RunMalloc(UPINGBUFSIZE);	/* Really a (char *) */
  cptr->fd = fd;
  cptr->port = port;
  cptr->hopcount = cptr->receiveB = cptr->sendB = MIN(20, atoi(parv[4]));
  strcpy(cptr->sockhost, aconf->host);
  cptr->acpt = sptr;
  SetAskedPing(sptr);
  memcpy(&cptr->ip, &aconf->ipnum, sizeof(struct in_addr));
  strcpy(cptr->name, aconf->name);
  cptr->firsttime = 0;

  switch (ping_server(cptr))
  {
    case 0:
      break;
    case -1:
      del_queries((char *)cptr);
      end_ping(cptr);
      break;
  }
  return 0;
}

void end_ping(aClient *cptr)
{
  Debug((DEBUG_DEBUG, "end_ping: %p", cptr));
  if (cptr->acpt)
  {
    if (MyUser(cptr->acpt)
	|| (IsServer(cptr->acpt->from) && Protocol(cptr->acpt->from) < 10))
    {
      if (cptr->firsttime)	/* Started at all ? */
      {
	if (cptr->receiveB != cptr->hopcount)	/* Received any pings at all? */
	{
	  sendto_one(cptr->acpt, ":%s NOTICE %s :UPING %s%s",
	      me.name, cptr->acpt->name, cptr->name, cptr->buffer);
	  sendto_one(cptr->acpt,
	      ":%s NOTICE %s :UPING Stats: sent %d recvd %d ; "
	      "min/avg/max = %u/%u/%u ms",
	      me.name, cptr->acpt->name, cptr->hopcount - cptr->sendB,
	      cptr->hopcount - cptr->receiveB, cptr->receiveK,
	      (2 * cptr->sendM + cptr->hopcount - cptr->receiveB) /
	      (2 * (cptr->hopcount - cptr->receiveB)), cptr->receiveM);
	}
	else
	  sendto_one(cptr->acpt,
	      ":%s NOTICE %s :UPING: no response from %s within %d seconds",
	      me.name, cptr->acpt->name, cptr->name,
	      (int)(now + cptr->since - cptr->firsttime));
      }
      else
	sendto_one(cptr->acpt,
	    ":%s NOTICE %s :UPING: Could not start ping to %s %u",
	    me.name, cptr->acpt->name, cptr->name, cptr->port);
    }
    else
    {
      if (cptr->firsttime)	/* Started at all ? */
      {
	if (cptr->receiveB != cptr->hopcount)	/* Received any pings at all? */
	{
	  sendto_one(cptr->acpt, "%s NOTICE %s%s :UPING %s%s",
	      NumServ(&me), NumNick(cptr->acpt), cptr->name, cptr->buffer);
	  sendto_one(cptr->acpt,
	      "%s NOTICE %s%s :UPING Stats: sent %d recvd %d ; "
	      "min/avg/max = %u/%u/%u ms",
	      NumServ(&me), NumNick(cptr->acpt), cptr->hopcount - cptr->sendB,
	      cptr->hopcount - cptr->receiveB, cptr->receiveK,
	      (2 * cptr->sendM + cptr->hopcount - cptr->receiveB) /
	      (2 * (cptr->hopcount - cptr->receiveB)), cptr->receiveM);
	}
	else
	  sendto_one(cptr->acpt,
	      "%s NOTICE %s%s :UPING: no response from %s within %d seconds",
	      NumServ(&me), NumNick(cptr->acpt), cptr->name,
	      (int)(now + cptr->since - cptr->firsttime));
      }
      else
	sendto_one(cptr->acpt,
	    "%s NOTICE %s%s :UPING: Could not start ping to %s %d",
	    NumServ(&me), NumNick(cptr->acpt), cptr->name, cptr->port);
    }
  }
  close(cptr->fd);
  loc_clients[cptr->fd] = NULL;
  if (cptr->acpt)
    ClearAskedPing(cptr->acpt);
  RunFree((char *)cptr->confs);
  free_client(cptr);
}

void cancel_ping(aClient *sptr, aClient *acptr)
{
  int i;
  aClient *cptr;

  Debug((DEBUG_DEBUG, "Cancelling uping for %p (%s)", sptr, sptr->name));
  for (i = highest_fd; i >= 0; i--)
    if ((cptr = loc_clients[i]) && IsPing(cptr) && cptr->acpt == sptr)
    {
      cptr->acpt = acptr;
      del_queries((char *)cptr);
      end_ping(cptr);
      break;
    }

  ClearAskedPing(sptr);
}
