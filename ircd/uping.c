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
#include "config.h"

#include "uping.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"    /* VirtualHost */
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

static struct Socket upingSock;

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

/* Called when the event engine detects activity on the UPing socket */
static void uping_echo_callback(struct Event* ev)
{
  assert(ev_type(ev) == ET_READ || ev_type(ev) == ET_ERROR);

  uping_echo();
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
    log_write(LS_SOCKET, L_ERROR, 0,
	      "UPING: set reuseaddr on UDP listener failed: %m (fd %d)", fd);
    Debug((DEBUG_ERROR, "UPING: set reuseaddr on UDP listener failed: %s",
           (strerror(errno)) ? strerror(errno) : "Unknown error"));
    close(fd);
    return -1;
  }
  if (bind(fd, (struct sockaddr*) &from, sizeof(from)) == -1) {
    log_write(LS_SOCKET, L_ERROR, 0,
	      "UPING: bind on UDP listener (%d fd %d) failed: %m",
	      htons(from.sin_port), fd);
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
  if (!socket_add(&upingSock, uping_echo_callback, 0, SS_DATAGRAM,
		  SOCK_EVENT_READABLE, fd)) {
    Debug((DEBUG_ERROR, "UPING: Unable to queue fd to event system"));
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
  unsigned int       len = 0;
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


/* Callback when socket has data to read */
static void uping_read_callback(struct Event* ev)
{
  struct UPing *pptr;

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  pptr = s_data(ev_socket(ev));

  Debug((DEBUG_SEND, "uping_read_callback called, %p (%d)", pptr,
	 ev_type(ev)));

  if (ev_type(ev) == ET_DESTROY) { /* being destroyed */
    pptr->freeable &= ~UPING_PENDING_SOCKET;

    if (!pptr->freeable)
      MyFree(pptr); /* done with it, finally */
  } else {
    assert(ev_type(ev) == ET_READ || ev_type(ev) == ET_ERROR);

    uping_read(pptr); /* read uping response */
  }
}

/* Callback to send another ping */
static void uping_sender_callback(struct Event* ev)
{
  struct UPing *pptr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  pptr = t_data(ev_timer(ev));

  Debug((DEBUG_SEND, "uping_sender_callback called, %p (%d)", pptr,
	 ev_type(ev)));

  if (ev_type(ev) == ET_DESTROY) { /* being destroyed */
    pptr->freeable &= ~UPING_PENDING_SENDER;

    if (!pptr->freeable)
      MyFree(pptr); /* done with it, finally */
  } else {
    assert(ev_type(ev) == ET_EXPIRE);

    pptr->lastsent = CurrentTime; /* store last ping time */
    uping_send(pptr); /* send a ping */

    if (pptr->sent == pptr->count) /* done sending pings, don't send more */
      timer_del(ev_timer(ev));
  }
}

/* Callback to kill a ping */
static void uping_killer_callback(struct Event* ev)
{
  struct UPing *pptr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  pptr = t_data(ev_timer(ev));

  Debug((DEBUG_SEND, "uping_killer_callback called, %p (%d)", pptr,
	 ev_type(ev)));

  if (ev_type(ev) == ET_DESTROY) { /* being destroyed */
    pptr->freeable &= ~UPING_PENDING_KILLER;

    if (!pptr->freeable)
      MyFree(pptr); /* done with it, finally */
  } else {
    assert(ev_type(ev) == ET_EXPIRE);

    uping_end(pptr); /* <FUDD>kill the uping, kill the uping!</FUDD> */
  }
}

/*
 * start_ping
 */
static void uping_start(struct UPing* pptr)
{
  assert(0 != pptr);

  timer_add(timer_init(&pptr->sender), uping_sender_callback, (void*) pptr,
	    TT_PERIODIC, 1);
  timer_add(timer_init(&pptr->killer), uping_killer_callback, (void*) pptr,
	    TT_RELATIVE, UPINGTIMEOUT);
  pptr->freeable |= UPING_PENDING_SENDER | UPING_PENDING_KILLER;

  sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :Sending %d ping%s to %s",
		pptr->client, pptr->count, (pptr->count == 1) ? "" : "s",
		pptr->name);
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
    if (pptr->client)
      sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING: send failed: "
		    "%s", pptr->client, msg);
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
    sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING: receive error: "
		  "%s", pptr->client, msg);
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

  timer_chg(&pptr->killer, TT_RELATIVE, UPINGTIMEOUT);

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
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Host lookup failed for "
		  "%s", sptr, aconf->name);
    return 0;
  }

  if (IsUPing(sptr))
    uping_cancel(sptr, sptr);  /* Cancel previous ping request */

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Unable to create udp "
		  "ping socket", sptr);
    return 0;
  }

  if (!os_set_nonblocking(fd)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Can't set fd non-"
		  "blocking", sptr);
    close(fd);
    return 0;
  }
  pptr = (struct UPing*) MyMalloc(sizeof(struct UPing));
  assert(0 != pptr);
  memset(pptr, 0, sizeof(struct UPing));

  if (!socket_add(&pptr->socket, uping_read_callback, (void*) pptr,
		  SS_DATAGRAM, SOCK_EVENT_READABLE, fd)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Can't queue fd for "
		  "reading", sptr);
    close(fd);
    MyFree(pptr);
    return 0;
  }

  pptr->fd                  = fd;
  pptr->sin.sin_port        = htons(port);
  pptr->sin.sin_addr.s_addr = aconf->ipnum.s_addr;
  pptr->sin.sin_family      = AF_INET;
  pptr->count               = IRCD_MIN(20, count);
  pptr->client              = sptr;
  pptr->index               = -1;
  pptr->freeable            = UPING_PENDING_SOCKET;
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
    if (pptr->lastsent) {
      if (0 < pptr->received) {
	sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING %s%s",
		      pptr->client, pptr->name, pptr->buf);
	sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING Stats: "
		      "sent %d recvd %d ; min/avg/max = %1lu/%1lu/%1lu ms",
		      pptr->client, pptr->sent, pptr->received, pptr->ms_min,
		      (2 * pptr->ms_ave) / (2 * pptr->received), pptr->ms_max);
      } else
	sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING: no response "
		      "from %s within %d seconds", pptr->client, pptr->name,
		      UPINGTIMEOUT);
    } else
      sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING: Could not "
		    "start ping to %s", pptr->client, pptr->name);
  }

  close(pptr->fd);
  pptr->fd = -1;
  uping_erase(pptr);
  if (pptr->client)
    ClearUPing(pptr->client);
  if (pptr->freeable & UPING_PENDING_SOCKET)
    socket_del(&pptr->socket);
  if (pptr->freeable & UPING_PENDING_SENDER)
    timer_del(&pptr->sender);
  if (pptr->freeable & UPING_PENDING_KILLER)
    timer_del(&pptr->killer);
}

void uping_cancel(struct Client *sptr, struct Client* acptr)
{
  struct UPing* ping;
  struct UPing* ping_next;

  Debug((DEBUG_DEBUG, "UPING: cancelling uping for %s", cli_name(sptr)));
  for (ping = pingList; ping; ping = ping_next) {
    ping_next = ping->next;
    if (sptr == ping->client) {
      ping->client = acptr;
      uping_end(ping);
    }
  }
  ClearUPing(sptr);
}


