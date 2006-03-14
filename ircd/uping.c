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
 */
/** @file
 * @brief UDP ping implementation.
 * @version $Id$
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

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define UPINGTIMEOUT 60   /**< Timeout waiting for ping responses */

static struct UPing* pingList = 0; /**< Linked list of UPing structs */
static struct Socket upingSock_v4; /**< Socket struct for IPv4 upings */
static struct Socket upingSock_v6; /**< Socket struct for IPv6 upings */

/** Start iteration of uping list.
 * @return Start of uping list.
 */
struct UPing* uping_begin(void)
{
  return pingList;
}

/** Removes \a p from uping list.
 * @param[in,out] p UPing to remove from list.
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

/** Callback for uping listener socket.
 * Reads a uping from the socket and respond, but not more than 10
 * times per second.
 * @param[in] ev I/O event for uping socket.
 */
static void uping_echo_callback(struct Event* ev)
{
  struct Socket      *sock;
  struct irc_sockaddr from;
  unsigned int       len = 0;
  static time_t      last = 0;
  static int         counter = 0;
  char               buf[BUFSIZE + 1];

  assert(ev_type(ev) == ET_READ || ev_type(ev) == ET_ERROR);
  sock = ev_socket(ev);
  assert(sock == &upingSock_v4 || sock == &upingSock_v6);

  Debug((DEBUG_DEBUG, "UPING: uping_echo"));

  if (IO_SUCCESS != os_recvfrom_nonb(s_fd(sock), buf, BUFSIZE, &len, &from))
    return;
  /*
   * count em even if we're getting flooded so we can tell we're getting
   * flooded.
   */
  ++ServerStats->uping_recv;
  if (len < 19)
    return;
  else if (CurrentTime != last) {
    counter = 0;
    last = CurrentTime;
  } else if (++counter > 10)
    return;
  os_sendto_nonb(s_fd(sock), buf, len, NULL, 0, &from);
}

/** Initialize a UDP socket for upings.
 * @returns 0 on success, -1 on error.
 */
int uping_init(void)
{
  struct irc_sockaddr from;
  int fd;

  memcpy(&from, &VirtualHost_v4, sizeof(from));
  from.port = atoi(UDP_PORT);

  fd = os_socket(&from, SOCK_DGRAM, "IPv4 uping listener", AF_INET);
  if (fd < 0)
    return -1;
  if (!socket_add(&upingSock_v4, uping_echo_callback, 0, SS_DATAGRAM,
                  SOCK_EVENT_READABLE, fd)) {
    Debug((DEBUG_ERROR, "UPING: Unable to queue fd to event system"));
    close(fd);
    return -1;
  }

#ifdef AF_INET6
  memcpy(&from, &VirtualHost_v6, sizeof(from));
  from.port = atoi(UDP_PORT);

  fd = os_socket(&from, SOCK_DGRAM, "IPv6 uping listener", AF_INET6);
  if (fd < 0)
    return -1;
  if (!socket_add(&upingSock_v6, uping_echo_callback, 0, SS_DATAGRAM,
                  SOCK_EVENT_READABLE, fd)) {
    Debug((DEBUG_ERROR, "UPING: Unable to queue fd to event system"));
    close(fd);
    return -1;
  }
#endif

  return 0;
}


/** Callback for socket activity on an outbound uping socket.
 * @param[in] ev I/O event for socket.
 */
static void uping_read_callback(struct Event* ev)
{
  struct UPing *pptr;

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  pptr = (struct UPing*) s_data(ev_socket(ev));

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

/** Timer callback to send another outbound uping.
 * @param[in] ev Event for uping timer.
 */
static void uping_sender_callback(struct Event* ev)
{
  struct UPing *pptr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  pptr = (struct UPing*) t_data(ev_timer(ev));

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

/** Timer callback to stop upings.
 * @param[in] ev Event for uping expiration.
 */
static void uping_killer_callback(struct Event* ev)
{
  struct UPing *pptr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  pptr = (struct UPing*) t_data(ev_timer(ev));

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

/** Start a uping.
 * This sets up the timers, UPing flags, and sends a notice to the
 * requesting client.
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

/** Send a uping to another server.
 * @param[in] pptr Descriptor for uping.
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
  sprintf(buf, " %10lu%c%6lu", (unsigned long)tv.tv_sec, '\0', (unsigned long)tv.tv_usec);

  Debug((DEBUG_SEND, "send_ping: sending [%s %s] to %s.%d on %d",
	  buf, &buf[12],
          ircd_ntoa(&pptr->addr.addr), pptr->addr.port,
	  pptr->fd));

  if (os_sendto_nonb(pptr->fd, buf, BUFSIZE, NULL, 0, &pptr->addr) != IO_SUCCESS)
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

/** Read the response from an outbound uping.
 * @param[in] pptr UPing to check.
 */
void uping_read(struct UPing* pptr)
{
  struct irc_sockaddr sin;
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

/** Start sending upings to a server.
 * @param[in] sptr Client requesting the upings.
 * @param[in] aconf ConfItem containing the address to ping.
 * @param[in] port Port number to ping.
 * @param[in] count Number of times to ping (should be at least 20).
 * @return Zero.
 */
int uping_server(struct Client* sptr, struct ConfItem* aconf, int port, int count)
{
  int fd;
  int family = 0;
  struct UPing* pptr;
  struct irc_sockaddr *local;

  assert(0 != sptr);
  assert(0 != aconf);

  if (!irc_in_addr_valid(&aconf->address.addr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :UPING: Host lookup failed for "
		  "%s", sptr, aconf->name);
    return 0;
  }

  if (IsUPing(sptr))
    uping_cancel(sptr, sptr);  /* Cancel previous ping request */

  if (irc_in_addr_is_ipv4(&aconf->address.addr)) {
    local = &VirtualHost_v4;
    family = AF_INET;
  } else {
    local = &VirtualHost_v6;
  }
  fd = os_socket(local, SOCK_DGRAM, "Outbound uping socket", family);
  if (fd < 0)
    return 0;

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
  memcpy(&pptr->addr.addr, &aconf->address.addr, sizeof(pptr->addr.addr));
  pptr->addr.port           = port;
  pptr->count               = IRCD_MIN(20, count);
  pptr->client              = sptr;
  pptr->freeable            = UPING_PENDING_SOCKET;
  strcpy(pptr->name, aconf->name);

  pptr->next = pingList;
  pingList   = pptr;

  SetUPing(sptr);
  uping_start(pptr);
  return 0;
}

/** Clean up a UPing structure, reporting results to the requester.
 * @param[in,out] pptr UPing results.
 */
void uping_end(struct UPing* pptr)
{
  Debug((DEBUG_DEBUG, "uping_end: %p", pptr));

  if (pptr->client) {
    if (pptr->lastsent) {
      if (0 < pptr->received) {
	sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING %s%s",
		      pptr->client, pptr->name, pptr->buf);
	sendcmdto_one(&me, CMD_NOTICE, pptr->client, "%C :UPING Stats: "
		      "sent %d recvd %d ; min/avg/max = %u/%u/%u ms",
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

/** Change notifications for any upings by \a sptr.
 * @param[in] sptr Client to stop notifying.
 * @param[in] acptr New client to notify (or NULL).
 */
void uping_cancel(struct Client *sptr, struct Client* acptr)
{
  struct UPing* ping;
  struct UPing* ping_next;

  Debug((DEBUG_DEBUG, "UPING: canceling uping for %s", cli_name(sptr)));
  for (ping = pingList; ping; ping = ping_next) {
    ping_next = ping->next;
    if (sptr == ping->client) {
      ping->client = acptr;
      uping_end(ping);
    }
  }
  ClearUPing(sptr);
}
