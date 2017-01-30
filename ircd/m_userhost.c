/*
 * IRC - Internet Relay Chat, ircd/m_userhost.c
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
#include "msgq.h"
#include "numeric.h"
#include "s_user.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Prepare one client's hostname information for another client.
 * @param[in] cptr Client whose information should be displayed
 * @param[in] sptr Client who should get the information
 * @param[in,out] mb Message buffer to append display to.
 */
static void userhost_formatter(struct Client* cptr, struct Client *sptr, struct MsgBuf* mb)
{
  assert(IsUser(cptr));
  msgq_append(0, mb, "%s%s=%c%s@%s", cli_name(cptr),
              SeeOper(sptr,cptr) ? "*" : "",
	      cli_user(cptr)->away ? '-' : '+', cli_user(cptr)->username,
	      /* Do not *EVER* change this to give opers the real host.
	       * Too many scripts rely on this data and can inadvertently
	       * publish the user's real host, thus breaking the security
	       * of +x.  If an oper wants the real host, he should go to
	       * /whois to get it.
	       */
	      HasHiddenHost(cptr) && (sptr != cptr) ?
	      cli_user(cptr)->host : cli_user(cptr)->realhost);
}

/** Handle a USERHOST message from a local client.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is a comma-separated list of nicknames to search for
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_userhost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(sptr == cptr);

  if (parc < 2)
    return need_more_params(sptr, "USERHOST");

  send_user_info(sptr, parv[1], RPL_USERHOST, userhost_formatter);
  return 0;
}
