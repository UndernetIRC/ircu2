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
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
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

static struct UPing* pingList = 0;
int UPingFileDescriptor       = -1; /* UDP listener socket for upings */

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
  
  for (it = pingList; it; last = it, it = it->next) {
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
 * Setup a UDP socket and listen for incoming packets
 */
int uping_init(void)
{
  struct sockaddr_in from = { 0 };
  int fd;

  memset(&from, 0, sizeof(from));
  from.sin_addr = VirtualHost.sin_addr;
  from.sin_port = htons(atoi(UDP_PORT));
  from.sin_family = AF_INET;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    Debug((DEBUG_ERROR, "UPING: UDP listener socket call failed: %s", 
           (strerror(errno)) ? strerror(errno) : "Unknown error"));
    return -1;
  }
  if (!os_set_reuseaddr(fd)) {
    ircd_log(L_ERROR, "UPING: setsockopt UDP listener: fd %d", fd);
    Debug((DEBUG_ERROR, "UPING: set reuseaddr on UDP listener failed: %s",
           (strerror(errno)) ? strerror(errno) : "Unknown error"));
    close(fd);
    return -1;
  }
  if (bind(fd, (struct sockaddr*) &from, sizeof(from)) == -1) {
    ircd_log(L_ERROR, "UPING: bind UDP listener %d fd %d", htons(from.sin_port), fd);
    Debug((DEBUG_ERROR, "UPING: bind on UDP listener failed : %s",
           (strerror(errno)) ? strerror(errno) : "Unknown error"));
    close(fd);
    return -1;
  }
  if (!os_set_nonblocking(fd)) {
    Debug((DEBUG_ERROR, "UPING: set non-blocking: %s",
           (strerror(errno)) ? strerror(errno) : "Unknown error"));
    close(fd);
    return -1;
  }
  UPingFileDescriptor = fd;
  return fd;
}


/*
 * max # of pings set to 15/sec.
 */
void uping_echo()
{
  struct sockaddr_in from = { 0 };
  unsigned int       len;
  static time_t      last = 0;
  static int         counter = 0;
  char               buf[BUFSIZE + 1];

  Debug((DEBUG_DEBUG, "UPING: uping_echo"));

  if (IO_SUCCESS != os_recvfrom_nonb(UPingFileDescriptor, buf, BUFSIZE, &len, &from))
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
  sendto(UPingFileDescriptor, buf, len, 0, (struct sockaddr*) &from, sizeof(from));
}


/*
 * start_ping
 */
static void uping_start(struct UPing* pptr)
{
  assert(0 != pptr);

  if (MyUser(pptr->client)) {
    sendto_one(pptr->client,
	       ":%s NOTICE %s :Sending %d ping%s to %s",
	       me.name, pptr->client->name, pptr->count,
	       (pptr->count == 1) ? "" : "s", pptr->name);
  }
  else {
    sendto_one(pptr->client,
	       "%s NOTICE %s%s :Sending %d ping%s to %s",
	       NumServ(&me), NumNick(pptr->client), pptr->count,
	       (pptr->count == 1) ? "" : "s", pptr->name);
  }
  pptr->timeout = CurrentTime + UPINGTIMEOUT;
  pptr->active = 1;
}

/*
 * uping_send
 *
 */
void uping_send(struct UPing* pptr)
{
  struct timeval tv;
  char buf[BUFSIZE + 1];

  assert(0 != pptr);
  if (pptr->sent == pptr->count)
    return;
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
    const char* msg = strerror(errno);
    if (!msg)
      msg = "Unknown error";
    if (pptr->client) {
      if (MyUser(pptr->client))
	sendto_one(pptr->client, ":%s NOTICE %s :UPING: send failed: %s",
	           me.name, pptr->client->name, msg);
      else
	sendto_one(pptr->client, "%s NOTICE %s%s :UPING: sendto() failed: %s",
	           NumServ(&me), NumNick(pptr->client), msg);
    }
    Debug((DEBUG_DEBUG, "UPING: send_ping: sendto failed on %d: %s", pptr->fd, msg));
    uping_end(pptr);
    return;
  }
  ++pptr->sent;
}

/*
 * read_ping
 */
void uping_read(struct UPing* pptr)
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
    const char* msg = strerror(errno);
    if (!msg)
      msg = "Unknown error";
    if (MyUser(pptr->client))
      sendto_one(pptr->client, ":%s NOTICE %s :UPING: receive error: %s",
                 me.name, pptr->client->name, msg);
    else
      sendto_one(pptr->client, "%s NOTICE %s%s :UPING: receive error: %s",
                 NumServ(&me), NumNick(pptr->client), msg);
    uping_end(pptr);
    return;
  }    

  if (len < 19)
    return;			/* Broken packet */
   
  ++pptr->received;

  buf[len] = 0;
  pingtime = (tv.tv_sec - atol(&buf[1])) * 1000
             + (tv.tv_usec - atol(buf + strlen(buf) + 1)) / 1000;

  pptr->ms_ave += pingtime;
  if (!pptr->ms_min || pptr->ms_min > pingtime)
    pptr->ms_min = pingtime;
  if (pingtime > pptr->ms_max)
    pptr->ms_max = pingtime;
  
  pptr->timeout = CurrentTime + UPINGTIMEOUT;

  Debug((DEBUG_SEND, "read_ping: %d bytes, ti %lu: [%s %s] %lu ms",
         len, pptr->timeout, buf, (buf + strlen(buf) + 1), pingtime));

  s = pptr->buf + strlen(pptr->buf);
  sprintf(s, " %u", pingtime);

  if (pptr->received == pptr->count)
    uping_end(pptr);
  return;
}

int uping_server(struct Client* sptr, struct ConfItem* aconf, int port, int count)
{
  int fd;
  struct UPing* pptr;

  assert(0 != sptr);
  assert(0 != aconf);

  if (INADDR_NONE == aconf->ipnum.s_addr) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :UPING: Host lookup failed for %s",
                 me.name, sptr->name, aconf->name);
    else
      sendto_one(sptr, "%s " TOK_NOTICE " %s%s :UPING: Host lookup failed for %s",
                 NumServ(&me), NumNick(sptr), aconf->name);
  }

  if (IsUPing(sptr))
    uping_cancel(sptr, sptr);  /* Cancel previous ping request */

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :UPING: Unable to create udp ping socket",
                 me.name, sptr->name);
    else
      sendto_one(sptr, "%s " TOK_NOTICE " %s%s :UPING: Unable to create udp ping socket",
                 NumServ(&me), NumNick(sptr));
    return 0;
  }

  if (!os_set_nonblocking(fd)) {
    if (MyUser(sptr))
      sendto_one(sptr, ":%s NOTICE %s :UPING: Can't set fd non-blocking",
                 me.name, sptr->name);
    else
      sendto_one(sptr, "%s " TOK_NOTICE " %s%s :UPING: Can't set fd non-blocking",
                 NumServ(&me), NumNick(sptr));
    close(fd);
    return 0;
  }
  pptr = (struct UPing*) MyMalloc(sizeof(struct UPing));
  assert(0 != pptr);
  memset(pptr, 0, sizeof(struct UPing));

  pptr->fd                  = fd;
  pptr->sin.sin_port        = htons(port);
  pptr->sin.sin_addr.s_addr = aconf->ipnum.s_addr;
  pptr->sin.sin_family      = AF_INET;
  pptr->count               = IRCD_MIN(20, count);
  pptr->client              = sptr;
  pptr->index               = -1;
  strcpy(pptr->name, aconf->name);

  pptr->next = pingList;
  pingList   = pptr;

  SetUPing(sptr);
  uping_start(pptr);
  return 0;
}


void uping_end(struct UPing* pptr)
{
  Debug((DEBUG_DEBUG, "uping_end: %p", pptr));

  if (pptr->client) {
    if (MyUser(pptr->client)) {
      if (pptr->lastsent) { 
	if (0 < pptr->received)	{
	  sendto_one(pptr->client, ":%s NOTICE %s :UPING %s%s",
	             me.name, pptr->client->name, pptr->name, pptr->buf);
          /*
           * XXX - warning long unsigned int format, unsigned int arg (7, 8, 9)
           */
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
	           ":%s NOTICE %s :UPING: Could not start ping to %s",
	           me.name, pptr->client->name, pptr->name);
    }
    else {
      if (pptr->lastsent) {
	if (0 < pptr->received) {
	  sendto_one(pptr->client, "%s NOTICE %s%s :UPING %s%s",
	             NumServ(&me), NumNick(pptr->client), pptr->name, pptr->buf);
          /* XXX - warning: long unsigned int format, unsigned int arg(9, 10, 11) */
	  sendto_one(pptr->client,
	             "%s " TOK_NOTICE " %s%s :UPING Stats: sent %d recvd %d ; "
	             "min/avg/max = %1lu/%1lu/%1lu ms",
	             NumServ(&me), NumNick(pptr->client), pptr->sent,
	             pptr->received, pptr->ms_min,
	             (2 * pptr->ms_ave) / (2 * pptr->received), 
                     pptr->ms_max);
	}
	else
	  sendto_one(pptr->client,
	             "%s " TOK_NOTICE " %s%s :UPING: no response from %s within %d seconds",
	             NumServ(&me), NumNick(pptr->client), pptr->name, UPINGTIMEOUT);
      }
      else
	sendto_one(pptr->client,
	           "%s " TOK_NOTICE " %s%s :UPING: Could not start ping to %s",
	           NumServ(&me), NumNick(pptr->client), pptr->name);
    }
  }
  close(pptr->fd);
  pptr->fd = -1;
  uping_erase(pptr);
  if (pptr->client)
    ClearUPing(pptr->client);
  MyFree(pptr);
}

void uping_cancel(struct Client *sptr, struct Client* acptr)
{
  struct UPing* ping;
  struct UPing* ping_next;

  Debug((DEBUG_DEBUG, "UPING: cancelling uping for %s", sptr->name));
  for (ping = pingList; ping; ping = ping_next) {
    ping_next = ping->next;
    if (sptr == ping->client) {
      ping->client = acptr;
      uping_end(ping);
    }
  }
  ClearUPing(sptr);
}


