/*
 * IRC - Internet Relay Chat, ircd/m_rehash.c
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
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "motd.h"
#include "numeric.h"
#include "s_conf.h"
#include "send.h"

#include <assert.h>

/*
 * mo_rehash - oper message handler
 * 
 * parv[1] = 'm' flushes the MOTD cache and returns
 * parv[1] = 'l' reopens the log files and returns
 * parv[1] = 'q' to not rehash the resolver (optional)
 */
int mo_rehash(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int flag = 0;

  if (!HasPriv(sptr, PRIV_REHASH))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc > 1) { /* special processing */
    if (*parv[1] == 'm') {
      send_reply(sptr, SND_EXPLICIT | RPL_REHASHING, ":Flushing MOTD cache");
      motd_recache(); /* flush MOTD cache */
      return 0;
    } else if (*parv[1] == 'l') {
      send_reply(sptr, SND_EXPLICIT | RPL_REHASHING, ":Reopening log files");
      log_reopen(); /* reopen log files */
      return 0;
    } else if (*parv[1] == 'q')
      flag = 2;
  }

  send_reply(sptr, RPL_REHASHING, configfile);
  sendto_opmask_butone(0, SNO_OLDSNO, "%C is rehashing Server config file",
		       sptr);

  log_write(LS_SYSTEM, L_INFO, 0, "REHASH From %#C", sptr);

  return rehash(cptr, flag);
}

