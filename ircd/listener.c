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
#include "sys.h"         /* MAXCLIENTS */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

/** List of listening sockets. */
struct Listener* ListenerPollList = 0;

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

  listener->fd_v4       = -1;
  listener->fd_v6       = -1;
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
  int len;

  assert(0 != sptr);

  if (param)
    port = atoi(param);

  for (listener = ListenerPollList; listener; listener = listener->next) {
    if (port && port != listener->addr.port)
      continue;
    len = 0;
    flags[len++] = listener_server(listener) ? 'S'
        : listener_webirc(listener) ? 'W'
        : 'C';
    if (FlagHas(&listener->flags, LISTEN_HIDDEN))
    {
      if (!show_hidden)
        continue;
      flags[len++] = 'H';
    }
    if (FlagHas(&listener->flags, LISTEN_IPV4))
    {
      flags[len++] = '4';
      if (listener->fd_v4 < 0)
        flags[len++] = '-';
    }
    if (FlagHas(&listener->flags, LISTEN_IPV6))
    {
      flags[len++] = '6';
      if (listener->fd_v6 < 0)
        flags[len++] = '-';
    }
    flags[len] = '\0';

    send_reply(sptr, RPL_STATSPLINE, listener->addr.port, listener->ref_count,
	       flags, listener_active(listener) ? "active" : "disabled");
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

/** Set or update socket options for \a listener.
 * @param[in] listener Listener to determine socket option values.
 * @param[in] fd File descriptor being updated.
 * @param[in] family Address family for \a fd.
 * @return Non-zero on success, zero on failure.
 */
static int set_listener_options(struct Listener *listener, int fd, int family)
{
  int is_server;

  is_server = listener_server(listener);
  /*
   * Set the buffer sizes for the listener. Accepted connections
   * inherit the accepting sockets settings for SO_RCVBUF S_SNDBUF
   * The window size is set during the SYN ACK so setting it anywhere
   * else has no effect whatsoever on the connection.
   * NOTE: this must be set before listen is called
   */
  if (!os_set_sockbufs(fd,
                       is_server ? feature_int(FEAT_SOCKSENDBUF) : CLIENT_TCP_WINDOW,
                       is_server ? feature_int(FEAT_SOCKRECVBUF) : CLIENT_TCP_WINDOW)) {
    report_error(SETBUFS_ERROR_MSG, get_listener_name(listener), errno);
    close(fd);
    return 0;
  }

  /*
   * Set the TOS bits - this is nonfatal if it doesn't stick.
   */
  if (!os_set_tos(fd, feature_int(is_server ? FEAT_TOS_SERVER : FEAT_TOS_CLIENT), family)) {
    report_error(TOS_ERROR_MSG, get_listener_name(listener), errno);
  }

  return 1;
}

/** Open listening socket for \a listener.
 * @param[in,out] listener Listener to make a socket for.
 * @param[in] family Socket address family to use.
 * @return Negative on failure, file descriptor on success.
 */
static int inetport(struct Listener* listener, int family)
{
  struct Socket *sock;
  int fd;

  /*
   * At first, open a new socket
   */
  fd = os_socket(&listener->addr, SOCK_STREAM, get_listener_name(listener), family);
  if (fd < 0)
    return -1;
  if (!os_set_listen(fd, HYBRID_SOMAXCONN)) {
    report_error(LISTEN_ERROR_MSG, get_listener_name(listener), errno);
    close(fd);
    return -1;
  }
  if (!set_listener_options(listener, fd, family))
    return -1;
  sock = (family == AF_INET) ? &listener->socket_v4 : &listener->socket_v6;
  if (!socket_add(sock, accept_connection, (void*) listener,
		  SS_LISTENING, 0, fd)) {
    /* Error should already have been reported to the logs */
    close(fd);
    return -1;
  }

  return fd;
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
 * @param[in] flags Flags describing listener options.
 */
void add_listener(int port, const char* vhost_ip, const char* mask,
                  const struct ListenerFlags *flags)
{
  struct Listener* listener;
  struct irc_in_addr vaddr;
  int okay = 0;
  int new_listener = 0;
  int fd;

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
  {
    new_listener = 1;
    listener = make_listener(port, &vaddr);
  }
  memcpy(&listener->flags, flags, sizeof(listener->flags));
  FlagSet(&listener->flags, LISTEN_ACTIVE);
  if (mask)
    ipmask_parse(mask, &listener->mask, &listener->mask_bits);
  else
    listener->mask_bits = 0;

#ifdef IPV6
  if (FlagHas(&listener->flags, LISTEN_IPV6)
      && (irc_in_addr_unspec(&vaddr) || !irc_in_addr_is_ipv4(&vaddr))) {
    if (listener->fd_v6 >= 0) {
      set_listener_options(listener, listener->fd_v6, AF_INET6);
      okay = 1;
    } else if ((fd = inetport(listener, AF_INET6)) >= 0) {
      listener->fd_v6 = fd;
      okay = 1;
    }
  } else if (-1 < listener->fd_v6) {
    close(listener->fd_v6);
    socket_del(&listener->socket_v6);
    listener->fd_v6 = -1;
  }
#endif

  if (FlagHas(&listener->flags, LISTEN_IPV4)
      && (irc_in_addr_unspec(&vaddr) || irc_in_addr_is_ipv4(&vaddr))) {
    if (listener->fd_v4 >= 0) {
      set_listener_options(listener, listener->fd_v4, AF_INET);
      okay = 1;
    } else if ((fd = inetport(listener, AF_INET)) >= 0) {
      listener->fd_v4 = fd;
      okay = 1;
    }
  } else if (-1 < listener->fd_v4) {
    close(listener->fd_v4);
    socket_del(&listener->socket_v4);
    listener->fd_v4 = -1;
  }

  if (!okay)
    free_listener(listener);
  else if (new_listener) {
    listener->next   = ListenerPollList;
    ListenerPollList = listener;
  }
}

/** Mark all listeners as closing (inactive).
 * This is done so unused listeners are closed after a rehash.
 */
void mark_listeners_closing(void)
{
  struct Listener* listener;
  for (listener = ListenerPollList; listener; listener = listener->next)
    FlagClr(&listener->flags, LISTEN_ACTIVE);
}

/** Close a single listener.
 * @param[in] listener Listener to close.
 */
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
  if (-1 < listener->fd_v4) {
    close(listener->fd_v4);
    socket_del(&listener->socket_v4);
    listener->fd_v4 = -1;
  }
  if (-1 < listener->fd_v6) {
    close(listener->fd_v6);
    socket_del(&listener->socket_v6);
    listener->fd_v6 = -1;
  }
  free_listener(listener);
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
    if (!listener_active(listener) && 0 == listener->ref_count)
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
  if (0 == --listener->ref_count && !listener_active(listener))
    close_listener(listener);
}

/** Accept a connection on a listener.
 * @param[in] ev Socket callback structure.
 */
static void accept_connection(struct Event* ev)
{
  struct Listener*    listener;
  struct irc_sockaddr addr;
  const char*         msg;
  int                 fd;
  int                 len;
  char                msgbuf[BUFSIZE];

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  listener = (struct Listener*) s_data(ev_socket(ev));

  if (ev_type(ev) == ET_DESTROY) /* being destroyed */
    return;
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
      if ((fd = os_accept(s_fd(ev_socket(ev)), &addr)) == -1)
      {
        if (errno == EAGAIN) return;
#ifdef EWOULDBLOCK
	if (errno == EWOULDBLOCK) return;
#endif
      /* Lotsa admins seem to have problems with not giving enough file
       * descriptors to their server so we'll add a generic warning mechanism
       * here.  If it turns out too many messages are generated for
       * meaningless reasons we can filter them back.
       */
      sendto_opmask_butone(0, SNO_TCPCOMMON,
			   "Unable to accept connection: %m");
      return;
      }
      /*
       * check for connection limit. If this fd exceeds the limit,
       * all further accept()ed connections will also exceed it.
       * Enable the server to clear out other connections before
       * continuing to accept() new connections.
       */
      if (fd > MAXCLIENTS - 1)
      {
        msg = "All connections in use";
        ++ServerStats->is_all_inuse;
      reject:
        len = snprintf(msgbuf, sizeof(msgbuf), ":%s ERROR :%s\r\n",
          cli_name(&me), msg);
        if (len < sizeof(msgbuf))
          send(fd, msgbuf, len, 0);
        close(fd);
        return;
      }
      /*
       * check to see if listener is shutting down. Continue
       * to accept(), because it makes sense to clear our the
       * socket's queue as fast as possible.
       */
      if (!listener_active(listener))
      {
        msg = "Use another port";
        ++ServerStats->is_inactive;
        goto reject;
      }
      /*
       * check to see if connection is allowed for this address mask
       */
      if (!ipmask_check(&addr.addr, &listener->mask, listener->mask_bits))
      {
        msg = "Use another port";
        ++ServerStats->is_bad_ip;
        goto reject;
      }
      ++ServerStats->is_ac;
      /* nextping = CurrentTime; */
      add_connection(listener, fd);
    }
  }
}
