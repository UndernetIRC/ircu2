/*
 * IRC - Internet Relay Chat, include/ircd_handler.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief Message handler types and definitions.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_handler_h
#define INCLUDED_ircd_handler_h

struct Client;

/*
 * MessageHandler
 */
/** Enumerated type for client message handlers. */
typedef enum HandlerType {
  UNREGISTERED_HANDLER, /**< Used for unregistered clients. */
  CLIENT_HANDLER,       /**< Used for local users. */
  SERVER_HANDLER,       /**< Used for server conections. */
  OPER_HANDLER,         /**< Used for IRC operators. */
  SERVICE_HANDLER,      /**< Used for services connections. */
  LAST_HANDLER_TYPE     /**< NUmber of handler types. */
} HandlerType;

/**
 * MessageHandler function.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
typedef int (*MessageHandler)(struct Client* cptr, struct Client* sptr, int parc, char*parv[]);


#endif /* INCLUDED_ircd_handler_h */

