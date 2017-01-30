/*
 * IRC - Internet Relay Chat, ircd/m_tmpl.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a message from a normal client.
 *
 * \a parv has the following elements:
 * \li \a parv[1] ...
 * \li \a parv[2] et cetera
 * \li \a parv[\a parc - 1] and so forth
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_tmpl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return 0;
}

/** Handle a message from a server
 *
 * \a parv has the following elements:
 * \li \a parv[1] ...
 * \li \a parv[2] et cetera
 * \li \a parv[\a parc - 1] and so forth
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_tmpl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return 0;
}

/** Handle a message from an operator
 *
 * \a parv has the following elements:
 * \li \a parv[1] ...
 * \li \a parv[2] et cetera
 * \li \a parv[\a parc - 1] and so forth
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_tmpl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return 0;
}

/** Handle a message from a service
 *
 * \a parv has the following elements:
 * \li \a parv[1] ...
 * \li \a parv[2] et cetera
 * \li \a parv[\a parc - 1] and so forth
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mv_tmpl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return 0;
}

/** Handle a message from an unregistered client
 *
 * \a parv has the following elements:
 * \li \a parv[1] ...
 * \li \a parv[2] et cetera
 * \li \a parv[\a parc - 1] and so forth
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mr_tmpl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return 0;
}
