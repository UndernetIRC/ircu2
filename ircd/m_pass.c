/*
 * IRC - Internet Relay Chat, ircd/m_pass.c
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
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "s_auth.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a PASS message from an unregistered connection.
 *
 * \a parv[1..\a parc-1] is a possibly broken-up password.  Since some
 * clients do not prefix the password with ':', this functions stitches
 * the elements back together before using it.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mr_pass(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char password[BUFSIZE];
  int arg, len;

  assert(0 != cptr);
  assert(cptr == sptr);
  assert(!IsRegistered(sptr));

  /* Some clients (brokenly) send "PASS x y" rather than "PASS :x y"
   * when the user enters "x y" as the password.  Unsplit arguments to
   * work around this.
   */
  for (arg = 1, len = 0; arg < parc; ++arg)
  {
    ircd_strncpy(password + len, parv[arg], sizeof(password) - len);
    len += strlen(parv[arg]);
    password[len++] = ' ';
  }
  if (len > 0)
    --len;
  password[len] = '\0';

  if (EmptyString(password))
    return need_more_params(cptr, "PASS");

  ircd_strncpy(cli_passwd(cptr), password, PASSWDLEN);
  return cli_auth(cptr) ? auth_set_password(cli_auth(cptr), password) : 0;
}
