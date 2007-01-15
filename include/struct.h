/*
 * IRC - Internet Relay Chat, include/struct.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
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
 * @brief Structure definitions for users and servers.
 * @version $Id$
 */
#ifndef INCLUDED_struct_h
#define INCLUDED_struct_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>      /* time_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"       /* sizes */
#endif

struct DLink;
struct Client;
struct User;
struct Membership;
struct SLink;

/** Describes a server on the network. */
struct Server {
  struct Client*  up;           /**< Server one closer to me */
  struct DLink*   down;         /**< List with downlink servers */
  struct DLink*   updown;       /**< own Dlink in up->serv->down struct */
  struct Client** client_list;  /**< List with client pointers on this server */
  struct User*    user;         /**< who activated this connection */
  time_t          timestamp;    /**< Remotely determined connect try time */
  time_t          ghost;        /**< Local time at which a new server
                                   caused a Ghost */
  int             lag;          /**< Approximation of the amount of lag to this server */
  unsigned int    clients;      /**< Number of clients on the server */
  unsigned short  prot;         /**< Major protocol */
  unsigned int    nn_mask;      /**< Number of clients supported by server, minus 1 */
  char          nn_capacity[4]; /**< Numeric representation of server capacity */

  int            asll_rtt;      /**< AsLL round-trip time */
  int            asll_to;       /**< AsLL upstream lag */
  int            asll_from;     /**< AsLL downstream lag */
  time_t         asll_last;     /**< Last time we sent or received an AsLL ping */

  char *last_error_msg;         /**< Allocated memory with last message receive with an ERROR */
  char by[NICKLEN + 1];         /**< Numnick of client who requested the link */
};

/** Describes a user on the network. */
struct User {
  struct Client*     server;         /**< client structure of server */
  struct Membership* channel;        /**< chain of channel pointer blocks */
  struct SLink*      invited;        /**< chain of invite pointer blocks */
  struct Ban*        silence;        /**< chain of silence pointer blocks */
  char*              away;           /**< pointer to away message */
  time_t             last;           /**< last time user sent a message */
  unsigned int       refcnt;         /**< Number of times this block is referenced */
  unsigned int       joined;         /**< number of channels joined */
  unsigned int       invites;        /**< Number of channels we've been invited to */
  /** Remote account name.  Before registration is complete, this is
   * either empty or contains the username from the USER command.
   * After registration, that may be prefixed with ~ or it may be
   * overwritten with the ident response.
   */
  char               username[USERLEN + 1];
  char               host[HOSTLEN + 1];       /**< displayed hostname */
  char               realhost[HOSTLEN + 1];   /**< actual hostname */
  char               account[ACCOUNTLEN + 1]; /**< IRC account name */
  time_t	     acc_create;              /**< IRC account timestamp */
};

#endif /* INCLUDED_struct_h */
