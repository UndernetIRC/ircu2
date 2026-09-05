/*
 * IRC - Internet Relay Chat, ircd/m_ack.c
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
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
 */
/** @file
 * @brief Server-to-server relay for the IRCv3 labeled-response ACK.
 *
 * ACK is the labeled-response reply for a command that produced no
 * output at all: a bare ":<server> ACK" line carrying only the @label=
 * tag, so the client can still match its request. Like BATCH (see
 * m_batch.c, which documents the relay scheme), a server answering a
 * hunt_server_cmd()-routed request for a *remote* client emits it in an
 * S2S-addressed form -- ":<server> AK <target-numnick>" -- and this is
 * the relay that walks it back to the client's own server.
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"

/** Relay an S2S-addressed labeled-response ACK to its target.
 * @param[in] cptr Neighbor that sent us this line.
 * @param[in] sptr Server that generated it (the one actually answering
 *                 the labeled request, or a relay in between).
 * @param[in] parc Number of valid parameters.
 * @param[in] parv Parameters: parv[1] is the target numnick.
 */
int ms_ack(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;

  if (parc < 2)
    return protocol_violation(cptr, "ACK with no target");

  if (!(acptr = findNUser(parv[1])))
    return 0; /* target already gone: drop silently, like do_numeric() */

  if (MyConnect(acptr)) {
    /* Same gate as ms_batch() and parse.c's capture start: the target
     * must actually have batch and labeled-response active (m_cap.c NAKs
     * a REQ that would leave labeled-response without batch, so checking
     * both is the exact condition under which the capture that produced
     * this ACK could have been started). CapActive() reads con_active(),
     * which is only meaningful for a client actually connected here. */
    if (!CapActive(acptr, CAP_BATCH) || !CapActive(acptr, CAP_LABELED_RESPONSE))
      return 0;
    /* See m_batch.c: HIS rewrite is only meaningful at the delivering
     * hop, not baked in while relaying. */
    sendcmdto_one((feature_bool(FEAT_HIS_REWRITE) && !IsOper(acptr)) ? &me : sptr,
                  CMD_ACK, acptr, "");
  } else
    sendcmdto_one(sptr, CMD_ACK, acptr, "%C", acptr);

  return 0;
}
