/*
 * IRC - Internet Relay Chat, ircd/m_sline.c
 * Copyright (C) 2025 MrIron <mriron@undernet.org>
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
#include "sline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/*
 * ms_sline - server message handler
 *
 * * parv[0] = Sender prefix
 * * parv[1] = (+ or -) (activate or deactivate)
 * * parv[2] = last modified timestamp
 * * parv[3] = expiration timestamp (0 = never)
 * * parv[4] = type (A/P/C/L/Q)
 * * parv[5] = pattern
 * 
 */
int
ms_sline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Sline *asline = 0;
  sl_msgtype_t msgtype = 0;
  time_t lastmod = 0, expire = 0;
  char *state = NULL, *pattern = NULL, *type = NULL;

  if (parc < 5)
    return need_more_params(sptr, "SLINE");

  state = parv[1];
  lastmod = atoi(parv[2]) == 0 ? TStime() : atoi(parv[2]);
  expire = atoi(parv[3]);
  type = parv[4];
  pattern = parv[5];

  if (*state != '+' && *state != '-')
    return protocol_violation(sptr, "Invalid SLINE action, expected '+' or '-'");

  /* Check if the pattern is valid */
  if (!pattern || strlen(pattern) == 0)
    return protocol_violation(sptr, "Invalid SLINE pattern");
    
  /* Parse type flags */
  for (int i = 0; type[i] != '\0'; i++) {
    if (type[i] == 'A') {
      msgtype |= SLINE_ALL;
      break; /* A overrides everything */
    } else if (type[i] == 'P') {
      msgtype |= SLINE_PRIVATE;
    } else if (type[i] == 'C') {
      msgtype |= SLINE_CHANNEL;
    } else if (type[i] == 'L') {
      msgtype |= SLINE_PART;
    } else if (type[i] == 'Q') {
      msgtype |= SLINE_QUIT;
    } else {
      // If we are adding other types later, we could perhaps propagate unknown types but avoid adding them ourself.
      return protocol_violation(sptr, "Invalid SLINE type '%c', expected 'A', 'P', 'C', 'L', or 'Q'", type[i]);
    }
  }

  /* Check if S-line already exists with the exact same pattern */
  asline = sline_find(pattern);
  if (asline) {
    unsigned int updates = 0;

    /* If we have a newer last modified timestamp, we ignore. */
    if (asline->sl_lastmod >= lastmod) {
      Debug((DEBUG_DEBUG, "S-line already exists with newer or equal timestamp, ignoring"));
      return 0;
    }

    /* Check whether there is a state update. */
    if ((*state == '+' && !(asline->sl_flags & SLINE_ACTIVE)) ||
        (*state == '-' && (asline->sl_flags & SLINE_ACTIVE))) {
      updates |= SLINE_STATE;
    }

    /* Check whether there is a message type update. */
    if (asline->sl_msgtype != msgtype) {
      updates |= SLINE_MSGTYPE;
    }

    /* Check whether the expire time has updated. */
    if (asline->sl_expire != expire) {
      updates |= SLINE_EXPIRE;
    }

    /* If there is no updates, we ignore. */
    if (updates == 0) {
      Debug((DEBUG_DEBUG, "S-line already exists with same state, msgtype and expire time, ignoring"));
      return 0;
    }

    /* Modify S:line record. */
    sline_modify(sptr, asline, lastmod, expire, msgtype, *state == '+' ? SLINE_ACTIVE : 0, updates);
  } else {
    sline_add(cptr, sptr, pattern, lastmod, expire, msgtype, *state == '+' ? SLINE_ACTIVE : 0);
  }

  /* Propagate. */  
  sendcmdto_serv_butone(sptr, CMD_SLINE, cptr, "%c %Tu %Tu %s :%s",
    *state, lastmod, expire, sline_flags_to_string(msgtype), pattern);

  return 1;
} 