/*
 * IRC - Internet Relay Chat, ircd/m_error.c
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
 *
 * $Id$
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Handle an ERROR message from an unregistered client.
 * The most common normal cause for this is a server password mismatch.
 *
 * \a parv has the following elements:
 * \li \a parv[\a parc - 1] is the error message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mr_error(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *para;

  if (!IsHandshake(cptr) && !IsConnecting(cptr))
    return 0; /* ignore ERROR from regular clients */

  para = (parc > 1 && *parv[parc - 1] != '\0') ? parv[parc - 1] : "<>";

  Debug((DEBUG_ERROR, "Received ERROR message from %s: %s", cli_name(sptr), para));

  if (cptr == sptr)
    sendto_opmask_butone(0, SNO_OLDSNO, "ERROR :from %C -- %s", cptr, para);
  else
    sendto_opmask_butone(0, SNO_OLDSNO, "ERROR :from %C via %C -- %s", sptr,
			 cptr, para);

  if (cli_serv(sptr))
  {
    MyFree(cli_serv(sptr)->last_error_msg);
    DupString(cli_serv(sptr)->last_error_msg, para);
  }

  return 0;
}

/** Handle an ERROR message from a server.
 *
 * \a parv has the following elements:
 * \li \a parv[\a parc - 1] is the error message
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_error(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *para;

  para = (parc > 1 && *parv[parc - 1] != '\0') ? parv[parc - 1] : "<>";

  Debug((DEBUG_ERROR, "Received ERROR message from %s: %s", cli_name(sptr), para));

  if (cptr == sptr)
    sendto_opmask_butone(0, SNO_OLDSNO, "ERROR :from %C -- %s", cptr, para);
  else
    sendto_opmask_butone(0, SNO_OLDSNO, "ERROR :from %C via %C -- %s", sptr,
			 cptr, para);

  if (cli_serv(sptr))
  {
    MyFree(cli_serv(sptr)->last_error_msg);
    DupString(cli_serv(sptr)->last_error_msg, para);
  }

  return 0;
}
