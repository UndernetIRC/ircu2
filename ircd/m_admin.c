/*
 * IRC - Internet Relay Chat, ircd/m_admin.c
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
#include "ircd_reply.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_user.h"

#include <assert.h>

static int send_admin_info(struct Client* sptr)
{
  const struct LocalConf* admin = conf_get_local();
  assert(0 != sptr);

  send_reply(sptr, RPL_ADMINME,    cli_name(&me));
  send_reply(sptr, RPL_ADMINLOC1,  admin->location1);
  send_reply(sptr, RPL_ADMINLOC2,  admin->location2);
  send_reply(sptr, RPL_ADMINEMAIL, admin->contact);
  return 0;
}


/*
 * m_admin - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = servername
 */
int m_admin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc > 1 && (!(acptr = find_match_server(parv[1])) || !IsMe(acptr)))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  return send_admin_info(sptr);
}

/*
 * mo_admin - oper message handler
 *
 * parv[0] = sender prefix
 * parv[1] = servername
 */
int mo_admin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (hunt_server_cmd(sptr, CMD_ADMIN, cptr, feature_int(FEAT_HIS_REMOTE), 
		      ":%C", 1,	parc, parv) != HUNTED_ISME)
    return 0;
  return send_admin_info(sptr);
}

/*
 * ms_admin - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = servername
 */
int ms_admin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(0 != sptr);

  if (parc < 2)
    return 0;

  if (hunt_server_cmd(sptr, CMD_ADMIN, cptr, 0, ":%C", 1, parc, parv) != HUNTED_ISME)
    return 0;

  return send_admin_info(sptr);
}

