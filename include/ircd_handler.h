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
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_handler_h
#define INCLUDED_ircd_handler_h

struct Client;

/*
 * MessageHandler
 */
typedef enum HandlerType {
  UNREGISTERED_HANDLER,
  CLIENT_HANDLER,
  SERVER_HANDLER,
  OPER_HANDLER,
  SERVICE_HANDLER,
  LAST_HANDLER_TYPE
} HandlerType;

/*
 * MessageHandler function
 * Params:
 * struct Client* cptr   - connection message originated from
 * struct Client* sptr   - source of message, may be different from cptr
 * int            parc   - parameter count
 * char*          parv[] - parameter vector
 */
typedef int (*MessageHandler)(struct Client*, struct Client*, int, char*[]);


#endif /* INCLUDED_ircd_handler_h */

