/*
 * IRC - Internet Relay Chat, ircd/m_tmpl.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_conf.h"

#include <assert.h>

/*
 * ms_opmode - server message handler
 */
int ms_opmode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr = 0;
  struct ModeBuf mbuf;

  if (parc < 3)
    return need_more_params(sptr, "OPMODE");

  if (IsLocalChannel(parv[1]))
    return 0;

  if ('#' != *parv[1] || !(chptr = FindChannel(parv[1])))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  modebuf_init(&mbuf, sptr, cptr, chptr,
	       (MODEBUF_DEST_CHANNEL | /* Send MODE to channel */
		MODEBUF_DEST_SERVER  | /* And to server */
		MODEBUF_DEST_OPMODE  | /* Use OPMODE */
		MODEBUF_DEST_HACK4   | /* Generate a HACK(4) notice */
		MODEBUF_DEST_LOG));    /* Log the mode changes to OPATH */

  mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
	     (MODE_PARSE_SET    | /* Set the modes on the channel */
	      MODE_PARSE_STRICT | /* Be strict about it */
	      MODE_PARSE_FORCE)); /* And force them to be accepted */

  modebuf_flush(&mbuf); /* flush the modes */

  return 0;
}

/*
 * mo_opmode - oper message handler
 */
int mo_opmode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr = 0;
  struct ModeBuf mbuf;
  char *chname, *qreason;
  int force = 0;

  if (!feature_bool(FEAT_CONFIG_OPERCMDS))
    return send_reply(sptr, ERR_DISABLED, "OPMODE");

  if (parc < 3)
    return need_more_params(sptr, "OPMODE");

  chname = parv[1];
  if (*chname == '!') {
    chname++;
    if (!HasPriv(sptr, IsLocalChannel(chname) ? PRIV_FORCE_LOCAL_OPMODE : PRIV_FORCE_OPMODE))
      return send_reply(sptr, ERR_NOPRIVILEGES);
    force = 1;
  }
  clean_channelname(chname);

  if (!HasPriv(sptr,
	       IsLocalChannel(chname) ? PRIV_LOCAL_OPMODE : PRIV_OPMODE))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (('#' != *chname && '&' != *chname) || !(chptr = FindChannel(chname)))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, chname);

  if (!force && (qreason = find_quarantine(chptr->chname)))
    return send_reply(sptr, ERR_QUARANTINED, chptr->chname, qreason);

  modebuf_init(&mbuf, sptr, cptr, chptr,
	       (MODEBUF_DEST_CHANNEL | /* Send MODE to channel */
		MODEBUF_DEST_SERVER  | /* And to server */
		MODEBUF_DEST_OPMODE  | /* Use OPMODE */
		MODEBUF_DEST_HACK4   | /* Generate a HACK(4) notice */
		MODEBUF_DEST_LOG));    /* Log the mode changes to OPATH */

  mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
	     (MODE_PARSE_SET |    /* set the modes on the channel */
	      MODE_PARSE_FORCE)); /* And force them to be accepted */

  modebuf_flush(&mbuf); /* flush the modes */

  return 0;
}

