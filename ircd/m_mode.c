/*
 * IRC - Internet Relay Chat, ircd/m_mode.c
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

#include "handlers.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int
m_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr = 0;
  struct ModeBuf mbuf;
  struct Membership *member;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  clean_channelname(parv[1]);

  if (('#' != *parv[1] && '&' != *parv[1]) || !(chptr = FindChannel(parv[1])))
    return set_user_mode(cptr, sptr, parc, parv);

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 3) {
    char modebuf[MODEBUFLEN];
    char parabuf[MODEBUFLEN];

    *modebuf = *parabuf = '\0';
    modebuf[1] = '\0';
    channel_modes(sptr, modebuf, parabuf, sizeof(parabuf), chptr);
    send_reply(sptr, RPL_CHANNELMODEIS, chptr->chname, modebuf, parabuf);
    send_reply(sptr, RPL_CREATIONTIME, chptr->chname, chptr->creationtime);
    return 0;
  }

  if (!(member = find_member_link(chptr, sptr)) || !IsChanOp(member)) {
    if (IsLocalChannel(chptr->chname) && HasPriv(sptr, PRIV_MODE_LCHAN)) {
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to channel */
		    MODEBUF_DEST_HACK4));  /* Send HACK(4) notice */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
		 (MODE_PARSE_SET |    /* Set the mode */
		  MODE_PARSE_FORCE)); /* Force it to take */
      return modebuf_flush(&mbuf);
    } else
      mode_parse(0, cptr, sptr, chptr, parc - 2, parv + 2,
		 (member ? MODE_PARSE_NOTOPER : MODE_PARSE_NOTMEMBER));
    return 0;
  }

  modebuf_init(&mbuf, sptr, cptr, chptr,
	       (MODEBUF_DEST_CHANNEL | /* Send mode to channel */
		MODEBUF_DEST_SERVER)); /* Send mode to servers */
  mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2, MODE_PARSE_SET);
  return modebuf_flush(&mbuf);
}

int
ms_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr = 0;
  struct ModeBuf mbuf;
  struct Membership *member;

  if (parc < 3)
    return need_more_params(sptr, "MODE");

  if (IsLocalChannel(parv[1]))
    return 0;

  if ('#' != *parv[1] || !(chptr = FindChannel(parv[1])))
    return set_user_mode(cptr, sptr, parc, parv);

  ClrFlag(sptr, FLAG_TS8);

  if (IsServer(sptr)) {
    if (find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD))
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER  | /* Send mode to servers */
		    MODEBUF_DEST_HACK4));  /* Send a HACK(4) message */
    else
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER  | /* Send mode to servers */
		    MODEBUF_DEST_HACK3));  /* Send a HACK(3) message */

    mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
	       (MODE_PARSE_SET    | /* Set the mode */
		MODE_PARSE_STRICT | /* Interpret it strictly */
		MODE_PARSE_FORCE)); /* And force it to be accepted */
  } else {
    if (!(member = find_member_link(chptr, sptr)) || !IsChanOp(member)) {
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_SERVER |  /* Send mode to server */
		    MODEBUF_DEST_HACK2  |  /* Send a HACK(2) message */
		    MODEBUF_DEST_DEOP   |  /* Deop the source */
		    MODEBUF_DEST_BOUNCE)); /* And bounce the MODE */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
		 (MODE_PARSE_STRICT |  /* Interpret it strictly */
		  MODE_PARSE_BOUNCE)); /* And bounce the MODE */
    } else {
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER)); /* Send mode to servers */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
		 (MODE_PARSE_SET    | /* Set the mode */
		  MODE_PARSE_STRICT | /* Interpret it strictly */
		  MODE_PARSE_FORCE)); /* And force it to be accepted */
    }
  }

  return modebuf_flush(&mbuf);
}
