/************************************************************************
 *   IRC - Internet Relay Chat, src/listener.c
 *   Copyright (C) 1999 Thomas Helvey <tomh@inxpress.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Implementation for handling listening sockets.
 * @version $Id$
 */
#include "config.h"

#include "listener.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

/** List of listening sockets. */
static struct Listener* ListenerPollList = 0;

static void accept_connection(struct Event* ev);

/** Allocate and initialize a new Listener structure for a particular
 * socket address.
 * @param[in] port Port number to listen on.
 * @param[in] addr Local address to listen on.
 * @return Newly allocated and initialized Listener.
 */
static struct Listener* make_listener(int port, const struct irc_in_addr *addr)
{
  struct Listener* listener =
    (struct Listener*) MyMalloc(sizeof(struct Listener));
  assert(0 != listener);

  memset(listener, 0, sizeof(struct Listener));

  listener->fd          = -1;
  listener->addr.port   = port;
  memcpy(&listener->addr.addr, addr, sizeof(listener->addr.addr));

#ifdef NULL_POINTER_NOT_ZERO
  listener->next = NULL;
  listener->conf = NULL;
#endif
  return listener;
}

/** Deallocate a Listener structure.
 * @param[in] listener Listener to be freed.
 */
static void free_listener(struct Listener* listener)
{
  assert(0 != listener);
  MyFree(listener);
}

/** Maximum length for a port number. */
#define PORTNAMELEN 10  /* ":31337" */

/** Return displayable listener name and port.
 * @param[in] listener %Listener to format as a text string.
 * @return Pointer to a static buffer that contains "server.name:6667".
 */
static
const char* get_listener_name(const struct Listener* listener)
{
  static char buf[HOSTLEN + PORTNAMELEN + 4];
  assert(0 != listener);
  ircd_snprintf(0, buf, sizeof(buf), "%s:%u", cli_name(&me), listener->addr.port);
  return buf;
}

/** Count allocated listeners and the memory they use.
 * @param[out] count_out Receives number of allocated listeners.
 * @param[out] size_out Receives bytes used by listeners.
 */
void count_listener_memory(int* count_out, size_t* size_out)
{
  struct Listener* l;
  int              count = 0;
  assert(0 != count_out);
  assert(0 != size_out);
  for (l = ListenerPollList; l; l = l->next)
    ++count;
  *count_out = count;
  *size_out  = count * sizeof(struct Listener);
}

/** Report listening ports to a client.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (port number to search for).
 */
void show_ports(struct Client* sptr, const struct StatDesc* sd,
                char* param)
{
  struct Listener *listener = 0;
  char flags[8];
  int show_hidden = IsOper(sptr);
  int count = (IsOper(sptr) || MyUser(sptr)) ? 100 : 8;
  int port = 0;

  assert(0 != sptr);

  if (param)
    port = atoi(param);

  for (listener = ListenerPollList; listener; listener = listener->next) {
    if (port && port != listener->addr.port)
      continue;
    flags[0] = (listener->server) ? 'S' : 'C';
    if (listener->hidden) {
      if (!show_hidden)
        continue;
      flags[1] = 'H';
      flags[2] = '\0';
    }
    else
      flags[1] = '\0';

    send_reply(sptr, RPL_STATSPLINE, listener->addr.port, listener->ref_count,
	       flags, (listener->active) ? "active" : "disabled");
    if (--count == 0)
      break;
  }
}

/*
 * inetport - create a listener socket in the AF_INET domain, 
 * bind it to the port given in 'port' and listen to it  
 * returns true (1) if successful false (0) on error.
 *
 * If the operating system has a define for SOMAXCONN, use it, otherwise
 * use HYBRID_SOMAXCONN -Dianora
 * NOTE: Do this in os_xxxx.c files
 */
#ifdef SOMAXCONN
#define HYBRID_SOMAXCONN SOMAXCONN
#else
/** Maximum length of socket connection backlog. */
#define HYBRID_SOMAXCONN 64
#endif

/** Open listening socket for \a listener.
 * @param[in,out] listener Listener to make a socket for.
 * @return Non-zero on success, zero on failure.
 */
static int inetport(struct Listener* listener)
{
  int                fd;

  /*
   * At first, open a new socket
   */
  fd = os_socket(&listener->addr, SOCK_STREAM, get_listener_name(listener), 0);
  if (fd < 0)
    return 0;
  /*
   * Set the buffer sizes for the listener. Accepted connections
   * inherit the accepting sockets settings for SO_RCVBUF S_SNDBUF
   * The window size is set during the SYN ACK so setting it anywhere
   * else has no effect whatsoever on the connection.
   * NOTE: this must be set before listen is called
   */
  if (!os_set_sockbufs(fd,
                       (listener->server) ? feature_int(FEAT_SOCKSENDBUF) : CLIENT_TCP_WINDOW,
                       (listener->server) ? feature_int(FEAT_SOCKRECVBUF) : CLIENT_TCP_WINDOW)) {
    report_error(SETBUFS_ERROR_MSG, get_listener_name(listener), errno);
    close(fd);
    return 0;
  }
  if (!os_set_listen(fd, HYBRID_SOMAXCONN)) {
    report_error(LISTEN_ERROR_MSG, get_listener_name(listener), errno);
    close(fd);
    return 0;
  }
  /*
   * Set the TOS bits - this is nonfatal if it doesn't stick.
   */
  if (!os_set_tos(fd,feature_int((listener->server)?FEAT_TOS_SERVER : FEAT_TOS_CLIENT))) {
    report_error(TOS_ERROR_MSG, get_listener_name(listener), errno);
  }

  if (!socket_add(&listener->socket, accept_connection, (void*) listener,
		  SS_LISTENING, 0, fd)) {
    /* Error should already have been reported to the logs */
    close(fd);
    return 0;
  }

  listener->fd = fd;

  return 1;
}

/** Find the listener (if any) for a particular port and address.
 * @param[in] port Port number to search for.
 * @param[in] addr Local address to search for.
 * @return Listener that matches (or NULL if none match).
 */
static struct Listener* find_listener(int port, const struct irc_in_addr *addr)
{
  struct Listener* listener;
  for (listener = ListenerPollList; listener; listener = listener->next) {
    if (port == listener->addr.port && !memcmp(addr, &listener->addr.addr, sizeof(*addr)))
      return listener;
  }
  return 0;
}

/** Make sure we have a listener for \a port on \a vhost_ip.
 * If one does not exist, create it.  Then mark it as active and set
 * the peer mask, server, and hidden flags according to the other
 * arguments.
 * @param[in] port Port number to listen on.
 * @param[in] vhost_ip Local address to listen on.
 * @param[in] mask Address mask to accept connections from.
 * @param[in] is_server Non-zero if the port should only accept server connections.
 * @param[in] is_hidden Non-zero if the port should be hidden from /STATS P output.
 */
void add_listener(int port, const char* vhost_ip, const char* mask,
                  int is_server, int is_hidden)
{
  struct Listener* listener;
  struct irc_in_addr vaddr;

  /*
   * if no port in conf line, don't bother
   */
  if (0 == port)
    return;

  memset(&vaddr, 0, sizeof(vaddr));

  if (!EmptyString(vhost_ip)
      && strcmp(vhost_ip, "*")
      && !ircd_aton(&vaddr, vhost_ip))
      return;

  listener = find_listener(port, &vaddr);
  if (!listener)
    listener = make_listener(port, &vaddr);
  listener->active = 1;
  listener->hidden = is_hidden;
  listener->server = is_server;
  if (mask)
    ipmask_parse(mask, &listener->mask, &listener->mask_bits);
  else
    listener->mask_bits = 0;

  if (listener->fd >= 0) {
    /* If the listener is already open, do not try to re-open. */
  }
  else if (inetport(listener)) {
    listener->next   = ListenerPollList;
    ListenerPollList = listener;
  }
  else
    free_listener(listener);
}

/** Mark all listeners as closing (inactive).
 * This is done so unused listeners are closed after a rehash.
 */
void mark_listeners_closing(void)
{
  struct Listener* listener;
  for (listener = ListenerPollList; listener; listener = listener->next)
    listener->active = 0;
}

/** Close a single listener.
 * @param[in] listener Listener to close.
 */
static
void close_listener(struct Listener* listener)
{
  assert(0 != listener);
  /*
   * remove from listener list
   */
  if (listener == ListenerPollList)
    ListenerPollList = listener->next;
  else {
    struct Listener* prev = ListenerPollList;
    for ( ; prev; prev = prev->next) {
      if (listener == prev->next) {
        prev->next = listener->next;
        break; 
      }
    }
  }
  if (-1 < listener->fd)
    close(listener->fd);
  socket_del(&listener->socket);
}

/** Close all inactive listeners. */
void close_listeners(void)
{
  struct Listener* listener;
  struct Listener* listener_next = 0;
  /*
   * close all 'extra' listening ports we have
   */
  for (listener = ListenerPollList; listener; listener = listener_next) {
    listener_next = listener->next;
    if (0 == listener->active && 0 == listener->ref_count)
      close_listener(listener);
  }
}

/** Dereference the listener previously associated with a client.
 * @param[in] listener Listener to dereference.
 */
void release_listener(struct Listener* listener)
{
  assert(0 != listener);
  assert(0 < listener->ref_count);
  if (0 == --listener->ref_count && !listener->active)
    close_listener(listener);
}

/** Accept a connection on a listener.
 * @param[in] ev Socket callback structure.
 */
static void accept_connection(struct Event* ev)
{
  struct Listener*    listener;
  struct irc_sockaddr addr;
  int                 fd;

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  listener = (struct Listener*) s_data(ev_socket(ev));

  if (ev_type(ev) == ET_DESTROY) /* being destroyed */
    free_listener(listener);
  else {
    assert(ev_type(ev) == ET_ACCEPT || ev_type(ev) == ET_ERROR);

    listener->last_accept = CurrentTime;
    /*
     * There may be many reasons for error return, but
     * in otherwise correctly working environment the
     * probable cause is running out of file descriptors
     * (EMFILE, ENFILE or others?). The man pages for
     * accept don't seem to list these as possible,
     * although it's obvious that it may happen here.
     * Thus no specific errors are tested at this
     * point, just assume that connections cannot
     * be accepted until some old is closed first.
     *
     * This piece of code implements multi-accept, based
     * on the idea that poll/select can only be efficient,
     * if we succeed in handling all available events,
     * i.e. accept all pending connections.
     *
     * http://www.hpl.hp.com/techreports/2000/HPL-2000-174.html
     */
    while (1)
    {
      if ((fd = os_accept(listener->fd, &addr)) == -1)
      {
        if (errno == EAGAIN ||
#ifdef EWOULDBLOCK
            errno == EWOULDBLOCK)
#endif
          return;
      /* Lotsa admins seem to have problems with not giving enough file
       * descriptors to their server so we'll add a generic warning mechanism
       * here.  If it turns out too many messages are generated for
       * meaningless reasons we can filter them back.
       */
      sendto_opmask(0, SNO_TCPCOMMON,
                    "Unable to accept connection: %m");
      return;
      }
      /*
       * check for connection limit. If this fd exceeds the limit,
       * all further accept()ed connections will also exceed it.
       * Enable the server to clear out other connections before
       * continuing to accept() new connections.
       */
      if (fd >= maxclients)
      {
        ++ServerStats->is_ref;
        send(fd, "ERROR :All connections in use\r\n", 32, 0);
        close(fd);
        return;
      }
      /*
       * check to see if listener is shutting down. Continue
       * to accept(), because it makes sense to clear our the
       * socket's queue as fast as possible.
       */
      if (!listener->active)
      {
        ++ServerStats->is_ref;
        send(fd, "ERROR :Use another port\r\n", 25, 0);
        close(fd);
        continue;
      }
      /*
       * check to see if connection is allowed for this address mask
       */
      if (!ipmask_check(&addr.addr, &listener->mask, listener->mask_bits))
      {
        ++ServerStats->is_ref;
        send(fd, "ERROR :Use another port\r\n", 25, 0);
        close(fd);
        continue;
      }
      ++ServerStats->is_ac;
      /* nextping = CurrentTime; */
      add_connection(listener, fd);
    }
  }
}
