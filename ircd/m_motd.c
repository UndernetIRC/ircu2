/*
 * IRC - Internet Relay Chat, ircd/m_motd.c
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
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "class.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>
#include <assert.h>

/*
 * m_motd - generic message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * Now using the motd_* family of functions defined in motd.c
 */
int m_motd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_MOTD, cptr, feature_int(FEAT_HIS_REMOTE),
		      "%C", 1, parc, parv) != HUNTED_ISME)
    return 0;

  return motd_send(sptr);
}

/*
 * ms_motd - server message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 * modified 30 mar 1995 by flux (cmlambertus@ucdavis.edu)
 * T line patch - display motd based on hostmask
 * modified again 7 sep 97 by Ghostwolf with code and ideas 
 * stolen from comstud & Xorath.  All motd files are read into
 * memory in read_motd() in s_conf.c
 *
 * Now using the motd_* family of functions defined in motd.c
 */
int ms_motd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_MOTD, cptr, 0, "%C", 1, parc, parv) !=
      HUNTED_ISME)
    return 0;

  return motd_send(sptr);
}
