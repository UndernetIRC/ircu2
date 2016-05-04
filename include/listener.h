/* - Internet Relay Chat, include/listener.h
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
 * @brief Interface and declarations for handling listening sockets.
 * @version $Id$
 */
#ifndef INCLUDED_listener_h
#define INCLUDED_listener_h
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"       /* HOSTLEN */
#endif
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif
#ifndef INCLUDED_res_h
#include "res.h"
#endif
#ifndef INCLUDED_client_h
#include "client.h" /* flagset stuff.  oh well. */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>       /* size_t, broken BSD system headers */
#define INCLUDED_sys_types_h
#endif

struct Client;
struct StatDesc;

enum ListenerFlag {
  /** Port is currently accepting connections. */
  LISTEN_ACTIVE,
  /** Port is hidden from /STATS P output. */
  LISTEN_HIDDEN,
  /** Port accepts only server connections. */
  LISTEN_SERVER,
  /** Port listens for IPv4 connections. */
  LISTEN_IPV4,
  /** Port listens for IPv6 connections. */
  LISTEN_IPV6,
  /** Port accepts only webirc connections. */
  LISTEN_WEBIRC,
  /** Sentinel for counting listener flags. */
  LISTEN_LAST_FLAG
};

DECLARE_FLAGSET(ListenerFlags, LISTEN_LAST_FLAG);

/** Describes a single listening port. */
struct Listener {
  struct Listener* next;               /**< list node pointer */
  struct ListenerFlags flags;          /**< on-off flags for listener */
  int              fd_v4;              /**< file descriptor for IPv4 */
  int              fd_v6;              /**< file descriptor for IPv6 */
  int              ref_count;          /**< number of connection references */
  unsigned char    mask_bits;          /**< number of bits in mask address */
  int              index;              /**< index into poll array */
  time_t           last_accept;        /**< last time listener accepted */
  struct irc_sockaddr addr;            /**< virtual address and port */
  struct irc_in_addr mask;             /**< listener hostmask */
  struct Socket    socket_v4;          /**< describe IPv4 socket to event system */
  struct Socket    socket_v6;          /**< describe IPv6 socket to event system */
};

#define listener_server(LISTENER) FlagHas(&(LISTENER)->flags, LISTEN_SERVER)
#define listener_active(LISTENER) FlagHas(&(LISTENER)->flags, LISTEN_ACTIVE)
#define listener_webirc(LISTENER) FlagHas(&(LISTENER)->flags, LISTEN_WEBIRC)

extern void        add_listener(int port, const char* vaddr_ip, 
                                const char* mask,
                                const struct ListenerFlags *flags);
extern void        close_listener(struct Listener* listener);
extern void        close_listeners(void);
extern void        count_listener_memory(int* count_out, size_t* size_out);
extern const char* get_listener_name(const struct Listener* listener);
extern void        mark_listeners_closing(void);
extern void show_ports(struct Client* client, const struct StatDesc* sd,
                       char* param);
extern void        release_listener(struct Listener* listener);

#endif /* INCLUDED_listener_h */

