/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
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
 * @brief Server-to-server relay for IRCv3 labeled-response BATCH.
 *
 * (ACK, the same relay for a response with no output, lives in m_ack.c.)
 *
 * BATCH and ACK are otherwise purely client-facing (see label.c): a server answering a hunt_server_cmd()-routed
 * request on behalf of a *remote* client (see parse_server()'s
 * labeled-response wrapper) emits its own BATCH/ACK addressed to that
 * client by numnick -- ":<server> BA <target-numnick> +ref type" /
 * "-ref", ":<server> AK <target-numnick>" -- rather than the plain,
 * unaddressed client-facing form (which relies on there being exactly
 * one recipient: the socket it's written to).
 *
 * This file is the relay for that addressed form as it crosses however
 * many further hops separate the answering server from the original
 * requester: same basic shape as do_numeric() in s_numeric.c (resolve the
 * target, then either deliver it locally in plain client-facing form, or
 * re-address it one more hop closer). @label=/@batch= tags on the
 * inbound line are preserved for free -- sendcmdto_one() picks up
 * whatever parse_server() already parsed into the current line's tags,
 * exactly like do_numeric()'s numeric relay already does.
 *
 * One deliberate difference from do_numeric(): the FEAT_HIS_REWRITE
 * decision (fold the true origin server into "&me") is made only at the
 * hop that actually MyConnect()s the target, not at every relaying hop.
 * do_numeric() rewrites at each hop it passes through, which is fine
 * when every server in the path agrees on FEAT_HIS_REWRITE, but on a
 * mixed-config network an earlier hop's rewrite permanently overwrites
 * sptr in the prefix before a later hop -- one that might have HIS
 * turned *off* -- ever gets a say, silently discarding the true origin.
 * Relaying hops here forward sptr untouched instead, so the one hop
 * that matters (the client's own server) is also the only one deciding.
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"

/** Relay an S2S-addressed BATCH open/close to its target.
 * @param[in] cptr Neighbor that sent us this line.
 * @param[in] sptr Server that generated it (the one actually answering
 *                 the labeled request, or a relay in between).
 * @param[in] parc Number of valid parameters.
 * @param[in] parv Parameters: parv[1] is the target numnick, the rest
 *                 (parv[2..]) is the BATCH ref/type payload verbatim.
 */
int ms_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  char rest[BUFSIZE];
  size_t len = 0;
  int i;

  if (parc < 3)
    return protocol_violation(cptr, "BATCH with too few parameters");

  if (!(acptr = findNUser(parv[1])))
    return 0; /* target already gone: drop silently, like do_numeric() */

  rest[0] = '\0';
  for (i = 2; i < parc && parv[i] && len < sizeof(rest) - 1; i++) {
    if (len)
      rest[len++] = ' ';
    len += ircd_snprintf(0, rest + len, sizeof(rest) - len, "%s", parv[i]);
  }

  if (MyConnect(acptr)) {
    /* CapActive() reads con_active(), which is only meaningful for a
     * client actually connected here -- a remote peer relaying this on
     * a stale/mistaken target, or one that never negotiated batch (or
     * dropped it after the request that caused this reply was sent),
     * must not have a raw BATCH line sprung on it. */
    if (!CapActive(acptr, CAP_BATCH) || !CapActive(acptr, CAP_LABELED_RESPONSE))
      return 0;
    /* HIS rewrite only makes sense at the hop actually delivering to
     * the client: it's a per-connection judgement (this server's own
     * FEAT_HIS_REWRITE setting, this server's own &me), not something
     * that survives being baked into the prefix mid-relay. Doing it at
     * every hop (as do_numeric() does) would let an earlier hop's own
     * HIS setting permanently overwrite sptr before a later hop -- one
     * that might have a *different* FEAT_HIS_REWRITE setting -- ever
     * gets a say, silently discarding the true origin along the way. */
    sendcmdto_one((feature_bool(FEAT_HIS_REWRITE) && !IsOper(acptr)) ? &me : sptr,
                  CMD_BATCH, acptr, "%s", rest);
  } else
    /* Not our target: just forward the line one hop closer, prefix
     * untouched. Whichever server ends up actually MyConnect()-ing
     * acptr makes the one HIS-rewrite decision that matters. */
    sendcmdto_one(sptr, CMD_BATCH, acptr, "%C %s", acptr, rest);

  return 0;
}
