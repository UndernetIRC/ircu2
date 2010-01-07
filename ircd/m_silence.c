/*
 * IRC - Internet Relay Chat, ircd/m_silence.c
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
 */
/** @file
 * @brief Handlers for SILENCE command.
 * @version $Id$
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Attempt to apply a SILENCE update to a user.
 *
 * Silences are propagated lazily between servers to save on bandwidth
 * and remote memory.  Any removal and any silence exception must be
 * propagated until a server has not seen the mask being removed or
 * has no positive silences for the user.
 *
 * @param[in] sptr Client to update.
 * @param[in] mask Single silence mask to apply, optionally preceded by '+' or '-' and maybe '~'.
 * @return The new ban entry on success, NULL on failure.
 */
static struct Ban *
apply_silence(struct Client *sptr, char *mask)
{
  struct Ban *sile;
  int flags;
  int res;
  char orig_mask[NICKLEN+USERLEN+HOSTLEN+3];

  assert(mask && mask[0]);

  /* Check for add or remove. */
  if (mask[0] == '-') {
    flags = BAN_DEL;
    mask++;
  } else if (mask[0] == '+') {
    flags = BAN_ADD;
    mask++;
  } else
    flags = BAN_ADD;

  /* Check for being an exception. */
  if (mask[0] == '~') {
    flags |= BAN_EXCEPTION;
    mask++;
  }

  /* Make the silence and set additional flags. */
  ircd_strncpy(orig_mask, mask, sizeof(orig_mask) - 1);
  sile = make_ban(pretty_mask(mask));
  sile->flags |= flags;

  /* If they're a local user trying to ban too broad a mask, forbid it. */
  if (MyUser(sptr)
      && (sile->flags & BAN_IPMASK)
      && sile->addrbits > 0
      && sile->addrbits < (irc_in_addr_is_ipv4(&sile->address) ? 112 : 32)) {
    send_reply(sptr, ERR_MASKTOOWIDE, orig_mask);
    free_ban(sile);
    return NULL;
  }

  /* Apply it to the silence list. */
  res = apply_ban(&cli_user(sptr)->silence, sile, 1);
  return res ? NULL : sile;
}

/** Apply and send silence updates for a user.
 * @param[in] sptr Client whose silence list has been updated.
 * @param[in] silences Comma-separated list of silence updates.
 * @param[in] dest Direction to send updates in (NULL for broadcast).
 */
static void
forward_silences(struct Client *sptr, char *silences, struct Client *dest)
{
  struct Ban *accepted[MAXPARA], *sile, **plast;
  char *cp, *p, buf[BUFSIZE];
  size_t ac_count, buf_used, slen, ii;

  /* Split the list of silences and try to apply each one in turn. */
  for (cp = ircd_strtok(&p, silences, ","), ac_count = 0;
       cp && (ac_count < MAXPARA);
       cp = ircd_strtok(&p, 0, ",")) {
    if ((sile = apply_silence(sptr, cp)))
      accepted[ac_count++] = sile;
  }

  if (MyUser(sptr)) {
    size_t siles, maxsiles, totlength, maxlength, jj;

    /* Check that silence count and total length are permitted. */
    maxsiles = feature_int(FEAT_MAXSILES);
    maxlength = maxsiles * feature_int(FEAT_AVBANLEN);
    siles = totlength = 0;
    /* Count number of current silences and their total length. */
    plast = &cli_user(sptr)->silence;
    for (sile = cli_user(sptr)->silence; sile; sile = sile->next) {
      if (sile->flags & (BAN_OVERLAPPED | BAN_ADD | BAN_DEL))
        continue;
      siles++;
      totlength += strlen(sile->banstr);
      plast = &sile->next;
    }
    for (ii = jj = 0; ii < ac_count; ++ii) {
      sile = accepted[ii];
      /* If the update is being added, and we would exceed the maximum
       * count or length, drop the update.
       */
      if (!(sile->flags & (BAN_OVERLAPPED | BAN_DEL))) {
        slen = strlen(sile->banstr);
        if ((siles >= maxsiles) || (totlength + slen >= maxlength)) {
          *plast = NULL;
          if (MyUser(sptr))
            send_reply(sptr, ERR_SILELISTFULL, accepted[ii]->banstr);
          free_ban(accepted[ii]);
          continue;
        }
        /* Update counts. */
        siles++;
        totlength += slen;
        plast = &sile->next;
      }
      /* Store the update. */
      accepted[jj++] = sile;
    }
    /* Write back the number of accepted updates. */
    ac_count = jj;

    /* Send the silence update list, including overlapped silences (to
     * make it easier on clients).
     */
    buf_used = 0;
    for (sile = cli_user(sptr)->silence; sile; sile = sile->next) {
      char ch;
      if (sile->flags & (BAN_OVERLAPPED | BAN_DEL))
        ch = '-';
      else if (sile->flags & BAN_ADD)
        ch = '+';
      else
        continue;
      slen = strlen(sile->banstr);
      if (buf_used + slen + 4 > 400) {
        buf[buf_used] = '\0';
        sendcmdto_one(sptr, CMD_SILENCE, sptr, "%s", buf);
        buf_used = 0;
      }
      if (buf_used)
        buf[buf_used++] = ',';
      buf[buf_used++] = ch;
      if (sile->flags & BAN_EXCEPTION)
        buf[buf_used++] = '~';
      memcpy(buf + buf_used, sile->banstr, slen);
      buf_used += slen;
    }
    if (buf_used > 0) {
        buf[buf_used] = '\0';
        sendcmdto_one(sptr, CMD_SILENCE, sptr, "%s", buf);
        buf_used = 0;
    }
  }

  /* Forward any silence removals or exceptions updates to other
   * servers if the user has positive silences.
   */
  if (!dest || !MyUser(dest)) {
    for (ii = buf_used = 0; ii < ac_count; ++ii) {
      char ch;
      sile = accepted[ii];
      if (sile->flags & BAN_OVERLAPPED)
        continue;
      else if (sile->flags & BAN_DEL)
        ch = '-';
      else if (sile->flags & BAN_ADD) {
        if (!(sile->flags & BAN_EXCEPTION))
          continue;
        ch = '+';
      } else
        continue;
      slen = strlen(sile->banstr);
      if (buf_used + slen + 4 > 400) {
        buf[buf_used] = '\0';
        if (dest)
          sendcmdto_one(sptr, CMD_SILENCE, dest, "%C %s", dest, buf);
        else
          sendcmdto_serv_butone(sptr, CMD_SILENCE, sptr, "* %s", buf);
        buf_used = 0;
      }
      if (buf_used)
        buf[buf_used++] = ',';
      buf[buf_used++] = ch;
      if (sile->flags & BAN_EXCEPTION)
        buf[buf_used++] = '~';
      memcpy(buf + buf_used, sile->banstr, slen);
      buf_used += slen;
    }
    if (buf_used > 0) {
        buf[buf_used] = '\0';
        if (dest)
          sendcmdto_one(sptr, CMD_SILENCE, dest, "%C %s", dest, buf);
        else
          sendcmdto_serv_butone(sptr, CMD_SILENCE, sptr, "* %s", buf);
        buf_used = 0;
    }
  }

  /* Remove overlapped and deleted silences from the user's silence
   * list.  Clear BAN_ADD since we're walking the list anyway.
   */
  for (plast = &cli_user(sptr)->silence; (sile = *plast) != NULL; ) {
    if (sile->flags & (BAN_OVERLAPPED | BAN_DEL)) {
      *plast = sile->next;
      free_ban(sile);
    } else {
      sile->flags &= ~BAN_ADD;
      *plast = sile;
      plast = &sile->next;
    }
  }

  /* Free any silence-deleting updates. */
  for (ii = 0; ii < ac_count; ++ii) {
    if ((accepted[ii]->flags & (BAN_ADD | BAN_DEL)) == BAN_DEL) {
      free_ban(accepted[ii]);
    }
  }
}

/** Handle a SILENCE command from a local user.
 * See @ref m_functions for general discussion of parameters.
 *
 * \a parv[1] may be any of the following:
 * \li Omitted or empty, to view your own silence list.
 * \li Nickname of a user, to view that user's silence list.
 * \li A comma-separated list of silence updates
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_silence(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Ban *sile;

  assert(0 != cptr);
  assert(cptr == sptr);

  /* See if the user is requesting a silence list. */
  acptr = sptr;
  if (parc < 2 || EmptyString(parv[1]) || (acptr = FindUser(parv[1]))) {
    if (cli_user(acptr) && ((acptr == sptr) || IsChannelService(acptr))) {
      for (sile = cli_user(acptr)->silence; sile; sile = sile->next) {
        send_reply(sptr, RPL_SILELIST, cli_name(acptr),
                   (sile->flags & BAN_EXCEPTION ? "~" : ""),  sile->banstr);
      }
    }
    send_reply(sptr, RPL_ENDOFSILELIST, cli_name(acptr));
    return 0;
  }

  /* The user must be attempting to update their list. */
  forward_silences(sptr, parv[1], NULL);
  return 0;
}

/** Handle a SILENCE command from a server.
 * See @ref m_functions for general discussion of parameters.
 *
 * \a parv[1] may be one of the following:
 * \li "*" to indicate a broadcast update (removing a SILENCE)
 * \li A client numnick that should be specifically SILENCEd.
 *
 * \a parv[2] is a comma-separated list of silence updates.
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_silence(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (IsServer(sptr))
    return protocol_violation(sptr, "Server trying to silence a user");
  if (parc < 3 || EmptyString(parv[2]))
    return need_more_params(sptr, "SILENCE");

  /* Figure out which silences can be forwarded. */
  forward_silences(sptr, parv[2], findNUser(parv[1]));
  return 0;
  (void)cptr;
}
