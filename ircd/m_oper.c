/*
 * IRC - Internet Relay Chat, ircd/m_oper.c
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
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Check whether an oper password matches.
 * @param[in] to_match The configured password field.
 * @param[in] passwd The user's asserted password.
 * @return Non-zero on match, zero on mismatch.
 */
static
int oper_password_match(const char* to_match, const char* passwd)
{
  char *crypted;
  int res;
  /*
   * use first two chars of the password they send in as salt
   *
   * passwd may be NULL. Head it off at the pass...
   */
  if (!to_match || !passwd)
    return 0;

  /* we no longer do a CRYPT_OPER_PASSWORD check because a clear 
     text passwords just handled by a fallback mechanism called 
     crypt_clear if it's enabled -- hikari */
  crypted = ircd_crypt(to_match, passwd);

  if (!crypted)
   return 0;
  res = strcmp(crypted, passwd);
  MyFree(crypted);
  return 0 == res;
}

/** Handle an OPER message from a local connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the operator identifier string
 * \li \a parv[2] is the password
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem* aconf;
  char*            name;
  char*            password;

  assert(0 != cptr);
  assert(cptr == sptr);

  name     = parc > 1 ? parv[1] : 0;
  password = parc > 2 ? parv[2] : 0;

  if (EmptyString(name) || EmptyString(password))
    return need_more_params(sptr, "OPER");

  aconf = find_conf_exact(name, sptr, CONF_OPERATOR);
  if (!aconf || IsIllegal(aconf))
  {
    send_reply(sptr, ERR_NOOPERHOST);
    sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s)",
			 parv[0], cli_user(sptr)->username, cli_sockhost(sptr));
    return 0;
  }
  assert(0 != (aconf->status & CONF_OPERATOR));

  if (oper_password_match(password, aconf->passwd))
  {
    struct Flags old_mode = cli_flags(sptr);

    if (ACR_OK != attach_conf(sptr, aconf)) {
      send_reply(sptr, ERR_NOOPERHOST);
      sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s "
			   "(%s@%s)", parv[0], cli_user(sptr)->username,
			   cli_sockhost(sptr));
      return 0;
    }
    SetLocOp(sptr);
    client_set_privs(sptr, aconf);
    if (HasPriv(sptr, PRIV_PROPAGATE))
    {
      ClearLocOp(sptr);
      SetOper(sptr);
      ++UserStats.opers;
    }
    cli_handler(cptr) = OPER_HANDLER;

    SetFlag(sptr, FLAG_WALLOP);
    SetFlag(sptr, FLAG_SERVNOTICE);
    SetFlag(sptr, FLAG_DEBUG);
    
    set_snomask(sptr, SNO_OPERDEFAULT, SNO_ADD);
    cli_max_sendq(sptr) = 0; /* Get the sendq from the oper's class */
    send_umode_out(cptr, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
    send_reply(sptr, RPL_YOUREOPER);

    sendto_opmask_butone(0, SNO_OLDSNO, "%s (%s@%s) is now operator (%c)",
			 parv[0], cli_user(sptr)->username, cli_sockhost(sptr),
			 IsOper(sptr) ? 'O' : 'o');

    log_write(LS_OPER, L_INFO, 0, "OPER (%s) by (%#C)", name, sptr);
  }
  else
  {
    send_reply(sptr, ERR_PASSWDMISMATCH);
    sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s)",
			 parv[0], cli_user(sptr)->username, cli_sockhost(sptr));
  }
  return 0;
}

/** Handle an OPER message from a server connection.
 * Usually, a server will just send a MODE <numnick> +o message
 * instead.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the operator identifier string
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(IsServer(cptr));
  /*
   * if message arrived from server, trust it, and set to oper
   */
  if (!IsServer(sptr) && !IsOper(sptr))
  {
    ++UserStats.opers;
    SetFlag(sptr, FLAG_OPER);
    sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s :+o", parv[0]);
  }
  return 0;
}

/** Handle an OPER message from an operator.
 *
 * \a parv is ignored.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  send_reply(sptr, RPL_YOUREOPER);
  return 0;
}
