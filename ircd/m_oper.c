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

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_xopen.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int oper_password_match(const char* to_match, const char* passwd)
{
  /*
   * use first two chars of the password they send in as salt
   *
   * passwd may be NULL. Head it off at the pass...
   */
  if (!to_match || !passwd)
    return 0;

  if (feature_bool(FEAT_CRYPT_OPER_PASSWORD))
    to_match = ircd_crypt(to_match, passwd);

  return (0 == strcmp(to_match, passwd));
}

/*
 * m_oper - generic message handler
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

  aconf = find_conf_exact(name, cli_username(sptr), cli_sockhost(sptr), CONF_OPS);
  if (!aconf) 
    aconf = find_conf_exact(name, cli_username(sptr),
                            ircd_ntoa((const char*) &(cli_ip(cptr))), CONF_OPS);

  if (!aconf || IsIllegal(aconf)) {
    send_reply(sptr, ERR_NOOPERHOST);
    sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s)",
			 parv[0], cli_user(sptr)->username, cli_sockhost(sptr));
    return 0;
  }
  assert(0 != (aconf->status & CONF_OPS));

  if (oper_password_match(password, aconf->passwd)) {
    struct Flags old_mode = cli_flags(sptr);

    if (ACR_OK != attach_conf(sptr, aconf)) {
      send_reply(sptr, ERR_NOOPERHOST);
      sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s "
			   "(%s@%s)", parv[0], cli_user(sptr)->username,
			   cli_sockhost(sptr));
      return 0;
    }
    if (CONF_LOCOP == aconf->status) {
      ClearOper(sptr);
      SetLocOp(sptr);
    }
    else {
      /*
       * prevent someone from being both oper and local oper
       */
      ClearLocOp(sptr);
      SetOper(sptr);
      ++UserStats.opers;
    }
    cli_handler(cptr) = OPER_HANDLER;

    SetFlag(sptr, FLAG_WALLOP);
    SetFlag(sptr, FLAG_SERVNOTICE);
    SetFlag(sptr, FLAG_DEBUG);

    set_snomask(sptr, SNO_OPERDEFAULT, SNO_ADD);
    client_set_privs(sptr);
    cli_max_sendq(sptr) = 0; /* Get the sendq from the oper's class */
    send_umode_out(cptr, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
    send_reply(sptr, RPL_YOUREOPER);

    sendto_opmask_butone(0, SNO_OLDSNO, "%s (%s@%s) is now operator (%c)",
			 parv[0], cli_user(sptr)->username, cli_sockhost(sptr),
			 IsOper(sptr) ? 'O' : 'o');

    log_write(LS_OPER, L_INFO, 0, "OPER (%s) by (%#C)", name, sptr);
  }
  else {
    send_reply(sptr, ERR_PASSWDMISMATCH);
    sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s)",
			 parv[0], cli_user(sptr)->username, cli_sockhost(sptr));
  }
  return 0;
}

/*
 * ms_oper - server message handler
 */
int ms_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(IsServer(cptr));
  /*
   * if message arrived from server, trust it, and set to oper
   */
  if (!IsServer(sptr) && !IsOper(sptr)) {
    ++UserStats.opers;
    SetFlag(sptr, FLAG_OPER);
    sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s :+o", parv[0]);
  }
  return 0;
}

/*
 * mo_oper - oper message handler
 */
int mo_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  send_reply(sptr, RPL_YOUREOPER);
  return 0;
}
