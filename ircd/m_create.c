/*
 * IRC - Internet Relay Chat, ircd/m_create.c
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

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * ms_create - server message handler
 */
int ms_create(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  time_t chanTS; /* channel creation time */
  char *p; /* strtok state */
  char *name; /* channel name */
  struct Channel *chptr; /* channel */
  struct JoinBuf join; /* join and create buffers */
  struct JoinBuf create;
  struct ModeBuf mbuf; /* a mode buffer */
  int badop; /* a flag */

  if (IsServer(sptr))
    return protocol_violation(sptr,"%s tried to CREATE a channel", cli_name(sptr));

  /* sanity checks: Only accept CREATE messages from servers */
  if (parc < 3 || *parv[2] == '\0')
    return need_more_params(sptr,"CREATE");

  chanTS = atoi(parv[2]);

  /* A create that didn't appear during a burst has that servers idea of
   * the current time.  Use it for lag calculations.
   */
  if (!IsBurstOrBurstAck(sptr) && 0 != chanTS &&
      MAGIC_REMOTE_JOIN_TS != chanTS)
    cli_serv(cli_user(sptr)->server)->lag = TStime() - chanTS;

  /* If this server is >1 minute fast, warn */
  if (TStime() - chanTS<-60) {
    static time_t rate;
    sendto_opmask_butone_ratelimited(0, SNO_NETWORK, &rate,
				     "Timestamp drift from %C (%is); issuing "
				     "SETTIME to correct this",
				     cli_user(sptr)->server,
				     chanTS - TStime());
    /* Now issue a SETTIME to resync.  If we're in the wrong, our
     * (RELIABLE_CLOCK) hub will bounce a SETTIME back to us.
     */
    sendcmdto_prio_one(&me, CMD_SETTIME, cli_user(sptr)->server,
		       "%Tu %C", TStime(), cli_user(sptr)->server);
  }

  joinbuf_init(&join, sptr, cptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, sptr, cptr, JOINBUF_TYPE_CREATE, 0, chanTS);

  /* For each channel in the comma seperated list: */
  for (name = ircd_strtok(&p, parv[1], ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    badop = 0;

    if (IsLocalChannel(name))
      continue;

    if ((chptr = FindChannel(name))) {
      name = chptr->chname;

      /* Check if we need to bounce a mode */
      if (TStime() - chanTS > TS_LAG_TIME ||
	  (chptr->creationtime && chanTS > chptr->creationtime &&
	   chptr->creationtime != MAGIC_REMOTE_JOIN_TS)) {
	modebuf_init(&mbuf, sptr, cptr, chptr,
		     (MODEBUF_DEST_SERVER |  /* Send mode to server */
		      MODEBUF_DEST_HACK2  |  /* Send a HACK(2) message */
		      MODEBUF_DEST_BOUNCE)); /* And bounce the mode */

	modebuf_mode_client(&mbuf, MODE_ADD | MODE_CHANOP, sptr);

	modebuf_flush(&mbuf);

	badop = 1;
      }
    } else                        /* Channel doesn't exist: create it */
      chptr = get_channel(sptr, name, CGT_CREATE);

    if (!badop) /* Set/correct TS */
      chptr->creationtime = chanTS;

    joinbuf_join(badop ? &join : &create, chptr,
		 (badop ? 0 : CHFL_CHANOP));
  }

  joinbuf_flush(&join); /* flush out the joins and creates */
  joinbuf_flush(&create);

  return 0;
}
