/*
 * IRC - Internet Relay Chat, ircd/uping.c
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
 *
 * $Id$
 */
#include "uping.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "res.h"
#include "s_bsd.h"    /* vserv */
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define UPINGTIMEOUT 60   /* Timeout waiting for ping responses */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

static void ping_server(struct UPing*);

static struct UPing* pingList = 0;
int UPingListener = -1; /* UDP listener socket for upings */

/*
 * pings_begin - iterator function for ping list 
 */
struct UPing* uping_begin(void)
{
  return pingList;
}

/*
 * pings_erase - removes ping struct from ping list
 */
static void uping_erase(struct UPing* p)
{
  struct UPing* it;
  struct UPing* last = 0;

  assert(0 != p);
  
  for (it = pingList; it; last = it = it->next) {
    if (p == it) {
      if (last)
        last->next = p->next;
      else
        pingList = p->next;
      break;
    }
  }
}

/*
 * uping_dns_callback - this gets called when the resolver either
 * succeeds or fails to locate the servers address.
 * If the dns query failed hp will be 0, otherwise it
 * will contain the stuff a hostent normally contains.
 */
static void uping_dns_callback(void* v, struct DNSReply* r)
{
  struct UPing* ping = (struct UPing*) v;
  assert(valid_ptr((void*)ping, sizeof(struct UPing)));

  if (r) {
    memcpy(&ping->sin.sin_addr, r->hp->h_addr, sizeof(struct in_addr));
    ping_server(ping);
  }
  else
  {
    sendto_ops("UDP ping to %s failed: host lookup", ping->name);
    end_ping(ping);
  }
}


/*
 * Setup a UDP socket and listen for incoming packets
 */
int uping_init(void)
{
  struct sockaddr_in from;
  int fd;

  memset(&from, 0, sizeof(from));
#ifdef VIRTUAL_HOST
  from.sin_addr = vserv.sin_addr;
#else
  from.sin_addr.s_addr = htonl(INADDR_ANY);
#endif
  from.sin_port = htons(atoi(UDP_PORT));
  from.sin_family = AF_INET;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    Debug((DEBUG_ERROR, "UPING: UDP listener socket call failed: %s", strerror(errno)));
    return -1;
  }
  if (!os_set_reuseaddr(fd)) {
    ircd_log(L_ERROR, "UPING: setsockopt UDP listener: fd %d", fd);
    Debug((DEBUG_ERROR, "UPING: set reuseaddr on UDP listener failed: %s", strerror(errno)));
    close(fd);
    return -1;
  }
  if (bind(fd, (struct sockaddr*) &from, sizeof(from)) == -1) {
    ircd_log(L_ERROR, "UPING: bind UDP listener %d fd %d", htons(from.sin_port), fd);
    Debug((DEBUG_ERROR, "UPING: bind on UDP listener failed : %s", strerror(errno)));
    close(fd);
    return -1;
  }
  if (!os_set_nonblocking(fd)) {
    Debug((DEBUG_ERROR, "UPING: set non-blocking: %s", strerror(errno)));
    close(fd);
    return -1;
  }
  return fd;
}


/*
 * max # of pings set to 15/sec.
 */
void polludp(int udpfd)
{
  struct sockaddr_in from;
  unsigned int       len = 0;
  static time_t      last = 0;
  static int         counter = 0;
  char               buf[BUFSIZE + 1];

  Debug((DEBUG_DEBUG, "UPING: poll"));

  if (IO_SUCCESS != os_recvfrom_nonb(udpfd, buf, BUFSIZE, &len, &from))
    return;
  /*
   * count em even if we're getting flooded so we can tell we're getting
   * flooded.
   */
  ++ServerStats->uping_recv;
  if (CurrentTime == last) {
    if (++counter > 10)
      return;
  }
  else {
    counter = 0;
    last    = CurrentTime;
  }
  if (len < 19)
    return;
  sendto(udpfd, buf, len, 0, (struct sockaddr *)&from, sizeof(from));
}


/*
 * start_ping
 */
static void start_ping(struct UPing* pptr)
{
  assert(valid_ptr((void*) pptr, sizeof(struct UPing)));

  if (MyUser(pptr->client) || Protocol(pptr->client->from) < 10) {
    sendto_one(pptr->client,
	":%s NOTICE %s :Sending %d ping%s to %s[%s] port %d",
	me.name, pptr->client->name, pptr->count,
	(pptr->count == 1) ? "" : "s", pptr->name,
	ircd_ntoa((const char*) &pptr->sin.sin_addr), ntohs(pptr->sin.sin_port));
  }
  else
  {
    sendto_one(pptr->client,
	"%s NOTICE %s%s :Sending %d ping%s to %s[%s] port %d",
	NumServ(&me), NumNick(pptr->client), pptr->count,
	(pptr->count == 1) ? "" : "s", pptr->name,
	ircd_ntoa((const char*) &pptr->sin.sin_addr), ntohs(pptr->sin.sin_port));
  }
  pptr->timeout = CurrentTime + UPINGTIMEOUT;
  pptr->active = 1;
}

/*
 * ping_server - get the server host address if not valid
 * then call start_ping
 */
static void ping_server(struct UPing* pptr)
{
  if (INADDR_NONE == pptr->sin.sin_addr.s_addr) {
    char *s;

    if ((s = strchr(pptr->name, '@')))
      ++s;			
    else
      s = pptr->name;

    if (INADDR_NONE == (pptr->sin.sin_addr.s_addr = inet_addr(s))) {
      struct DNSQuery query;
      struct DNSReply* rpl;

      query.vptr = (void*) pptr;
      query.callback = uping_dns_callback;
      if (0 == (rpl = gethost_byname(s, &query)))
	return;
      memcpy(&pptr->sin.sin_addr, rpl->hp->h_addr, sizeof(struct in_addr));
    }
  }
  start_ping(pptr);
}


/*
 * send_ping
 *
 */
void send_ping(struct UPing* pptr)
{
  struct timeval tv;
  char buf[BUFSIZE + 1];

  assert(0 != pptr);
  memset(buf, 0, sizeof(buf));

  gettimeofday(&tv, NULL);
  sprintf(buf, " %10lu%c%6lu", tv.tv_sec, '\0', tv.tv_usec);

  Debug((DEBUG_SEND, "send_ping: sending [%s %s] to %s.%d on %d",
	  buf, &buf[12],
	  ircd_ntoa((const char*) &pptr->sin.sin_addr), ntohs(pptr->sin.sin_port),
	  pptr->fd));

  if (sendto(pptr->fd, buf, BUFSIZE, 0, (struct sockaddr*) &pptr->sin,
             sizeof(struct sockaddr_in)) != BUFSIZE)
  {
    int err = errno;
    if (pptr->client)
    {
      if (MyUser(pptr->client)
#ifndef NO_PROTOCOL9
	  || (IsServer(pptr->client->from) && Protocol(pptr->client->from) < 10)
#endif
	  )
	sendto_one(pptr->client, ":%s NOTICE %s :UPING: sendto() failed: %s",
	           me.name, pptr->client->name, strerror(errno));
      else
	sendto_one(pptr->client, "%s NOTICE %s%s :UPING: sendto() failed: %s",
	           NumServ(&me), NumNick(pptr->client), strerror(errno));
    }
    Debug((DEBUG_DEBUG, "UPING: send_ping: sendto failed on %d: %s", pptr->fd, strerror(err)));
    end_ping(pptr);
    return;
  }
  ++pptr->sent;
}

/*
 * read_ping
 */
void read_ping(struct UPing* pptr)
{
  struct sockaddr_in sin;
  struct timeval     tv;
  unsigned int       len;
  unsigned int       pingtime;
  char*              s;
  char               buf[BUFSIZE + 1];
  IOResult           ior;

  assert(0 != pptr);

  gettimeofday(&tv, NULL);

  ior = os_recvfrom_nonb(pptr->fd, buf, BUFSIZE, &len, &sin);
  if (IO_BLOCKED == ior)
    return;
  else if (IO_FAILURE == ior) {
    int err = errno;
    if (MyUser(pptr->client)
#ifndef NO_PROTOCOL9
        || (IsServer(pptr->client->from) && Protocol(pptr->client->from) < 10)
#endif
        )
      sendto_one(pptr->client, ":%s NOTICE %s :UPING: recvfrom: %s",
                 me.name, pptr->client->name, strerror(err));
    else
      sendto_one(pptr->client, "%s NOTICE %s%s :UPING: recvfrom: %s",
                 NumServ(&me), NumNick(pptr->client), strerror(err));
    Debug((DEBUG_SEND, "UPING: read_ping: recvfrom: %d", err));
    end_ping(pptr);
    return;
  }    

  if (len < 19)
    return;			/* Broken packet */

  ++pptr->received;
  pingtime = (tv.tv_sec - atol(&buf[1])) * 1000
             + (tv.tv_usec - atol(buf + strlen(buf) + 1)) / 1000;

  pptr->ms_ave += pingtime;
  if (!(pptr->ms_min) || (pptr->ms_min > pingtime))
    pptr->ms_min = pingtime;
  if (pingtime > pptr->ms_max)
    pptr->ms_max = pingtime;
  
  pptr->timeout = CurrentTime + UPINGTIMEOUT;

  Debug((DEBUG_SEND, "read_ping: %d bytes, ti %lu: [%s %s] %lu ms",
      len, pptr->timeout, buf, (buf + strlen(buf) + 1), pingtime));

  s = pptr->buf + strlen(pptr->buf);
  sprintf(s, " %u", pingtime);

  if (pptr->received == pptr->count)
    end_ping(pptr);
  return;
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
int m_uping(struct Client* cptr, struct Client *sptr, int parc, char *parv[])
{
  struct ConfItem *aconf;
  int port;
  int fd;
  struct UPing* pptr = 0;

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
  if (hunt_server(1, cptr, sptr,
      ":%s UPING %s %s %s %s", 3, parc, parv) != HUNTED_ISME)
    return 0;

  if (BadPtr(parv[4]) || atoi(parv[4]) <= 0)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Illegal number of packets: %s",
	  me.name, parv[0], parv[4]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: Illegal number of packets: %s",
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
      sendto_one(sptr, ":%s NOTICE %s :UPING: Host %s not listed in ircd.conf",
	  me.name, parv[0], parv[1]);
    else
      sendto_one(sptr,
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
    sendto_ops("m_uping: socket: %s", (err != EMFILE) 
                ? strerror(err) : "No more sockets");
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, 
                 ":%s NOTICE %s :UPING: Unable to create udp ping socket",
                 me.name, parv[0]);
    else
      sendto_one(sptr,
                 "%s NOTICE %s%s :UPING: Unable to create udp ping socket",
                 NumServ(&me), NumNick(sptr));
    ircd_log(L_ERROR, "UPING: Unable to create UDP socket");
    return 0;
  }

  if (!os_set_nonblocking(fd)) {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :UPING: Can't set fd non-blocking",
            me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :UPING: Can't set fd non-blocking",
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

void end_ping(struct UPing* pptr)
{
  Debug((DEBUG_DEBUG, "end_ping: %p", pptr));
  delete_resolver_queries((void*) pptr);
  if (pptr->client)
  {
    if (MyUser(pptr->client)
        || (IsServer(pptr->client->from) && Protocol(pptr->client->from) < 10))
    {
      if (pptr->lastsent)	/* Started at all ? */
      {
	if (0 < pptr->received)	/* Received any pings at all? */
	{
	  sendto_one(pptr->client, ":%s NOTICE %s :UPING %s%s",
	      me.name, pptr->client->name, pptr->name, pptr->buf);
          /* XXX - warning long unsigned int format, unsigned int arg (7, 8, 9) */
	  sendto_one(pptr->client,
	      ":%s NOTICE %s :UPING Stats: sent %d recvd %d ; "
	      "min/avg/max = %1lu/%1lu/%1lu ms",
	      me.name, pptr->client->name, pptr->sent,
	      pptr->received, pptr->ms_min,
	      (2 * pptr->ms_ave) / (2 * pptr->received), 
              pptr->ms_max);
	}
	else
	  sendto_one(pptr->client,
	      ":%s NOTICE %s :UPING: no response from %s within %d seconds",
	      me.name, pptr->client->name, pptr->name,
	      UPINGTIMEOUT);
      }
      else
	sendto_one(pptr->client,
	    ":%s NOTICE %s :UPING: Could not start ping to %s %d",
	    me.name, pptr->client->name, pptr->name, ntohs(pptr->sin.sin_port));
    }
    else
    {
      if (pptr->lastsent)	/* Started at all ? */
      {
	if (0 < pptr->received)	/* Received any pings at all? */
	{
	  sendto_one(pptr->client, "%s NOTICE %s%s :UPING %s%s",
	      NumServ(&me), NumNick(pptr->client), pptr->name, pptr->buf);
          /* XXX - warning: long unsigned int format, unsigned int arg(9, 10, 11) */
	  sendto_one(pptr->client,
	      "%s NOTICE %s%s :UPING Stats: sent %d recvd %d ; "
	      "min/avg/max = %1lu/%1lu/%1lu ms",
	      NumServ(&me), NumNick(pptr->client), pptr->sent,
	      pptr->received, pptr->ms_min,
	      (2 * pptr->ms_ave) / (2 * pptr->received), 
              pptr->ms_max);
	}
	else
	  sendto_one(pptr->client,
	      "%s NOTICE %s%s :UPING: no response from %s within %d seconds",
	      NumServ(&me), NumNick(pptr->client), pptr->name,
	      UPINGTIMEOUT);
      }
      else
	sendto_one(pptr->client,
	    "%s NOTICE %s%s :UPING: Could not start ping to %s %d",
	    NumServ(&me), NumNick(pptr->client), pptr->name, 
            ntohs(pptr->sin.sin_port));
    }
  }
  close(pptr->fd);
  pptr->fd = -1;
  uping_erase(pptr);
  if (pptr->client)
    ClearUPing(pptr->client);
  MyFree(pptr);
}

void cancel_ping(struct Client *sptr, struct Client* acptr)
{
  struct UPing* ping;
  struct UPing* ping_next;

  Debug((DEBUG_DEBUG, "UPING: cancelling uping for %s", sptr->name));
  for (ping = pingList; ping; ping = ping_next) {
    ping_next = ping->next;
    if (sptr == ping->client) {
      ping->client = acptr;
      end_ping(ping);
    }
  }
  ClearUPing(sptr);
}

