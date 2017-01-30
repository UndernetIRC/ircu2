/*
 * IRC - Internet Relay Chat, ircd/m_cprivmsg.c
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
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a CPRIVMSG from some client.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the nickname of the client being sent to
 * \li \a parv[2] is a channel where \a sptr is an op and \a parv[1] has joined
 * \li \a parv[\a parc - 1] is the message to send
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_cprivmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 4 || EmptyString(parv[3]))
    return need_more_params(sptr, "CPRIVMSG");

  return whisper(sptr, parv[1], parv[2], parv[parc - 1], 0);
}

/** Handle a CNOTICE from some client.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the nickname of the client being sent to
 * \li \a parv[2] is a channel where \a sptr is an op and \a parv[1] has joined
 * \li \a parv[\a parc - 1] is the message to send
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_cnotice(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 4 || EmptyString(parv[3]))
    return need_more_params(sptr, "CNOTICE");

  return whisper(sptr, parv[1], parv[2], parv[parc - 1], 1);
}


