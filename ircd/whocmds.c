/*
 * IRC - Internet Relay Chat, ircd/s_user.c (formerly ircd/s_msg.c)
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
 * @brief Support functions for /WHO-like commands.
 * @version $Id$
 */
#include "config.h"

#include "whocmds.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "random.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"
#include "msg.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/** Send a WHO reply to a client who asked.
 * @param[in] sptr Client who is searching for other users.
 * @param[in] acptr Client who may be shown to \a sptr.
 * @param[in] repchan Shared channel that provides visibility.
 * @param[in] fields Bitmask of WHO_FIELD_* values, indicating what to show.
 * @param[in] qrt Query type string (ignored unless \a fields & WHO_FIELD_QTY).
 */
void do_who(struct Client* sptr, struct Client* acptr, struct Channel* repchan,
            int fields, char* qrt)
{
  char *p1;
  struct Membership *chan = 0;

  static char buf1[512];
  /* NOTE: with current fields list and sizes this _cannot_ overrun, 
     and also the message finally sent shouldn't ever be truncated */

  p1 = buf1;
  buf1[1] = '\0';

  /* If we don't have a channel and we need one... try to find it,
     unless the listing is for a channel service, we already know
     that there are no common channels, thus use PubChannel and not
     SeeChannel */
  if (repchan)
  {
    chan = find_channel_member(acptr, repchan);
  }
  else if ((!fields || (fields & (WHO_FIELD_CHA | WHO_FIELD_FLA)))
           && !IsChannelService(acptr))
  {
    for (chan = cli_user(acptr)->channel; chan; chan = chan->next_channel)
      if (PubChannel(chan->channel) &&
          (acptr == sptr || !IsZombie(chan)))
        break;
  }

  /* Place the fields one by one in the buffer and send it
     note that fields == NULL means "default query" */

  if (fields & WHO_FIELD_QTY)   /* Query type */
  {
    *(p1++) = ' ';
    if (BadPtr(qrt))
      *(p1++) = '0';
    else
      while ((*qrt) && (*(p1++) = *(qrt++)));
  }

  if (!fields || (fields & WHO_FIELD_CHA))
  {
    char *p2;
    *(p1++) = ' ';
    if ((p2 = (chan ? chan->channel->chname : NULL)))
      while ((*p2) && (*(p1++) = *(p2++)));
    else
      *(p1++) = '*';
  }

  if (!fields || (fields & WHO_FIELD_UID))
  {
    char *p2 = cli_user(acptr)->username;
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (fields & WHO_FIELD_NIP)
  {
    const char* p2 = HasHiddenHost(acptr) && !IsAnOper(sptr) ?
      feature_str(FEAT_HIDDEN_IP) :
      ircd_ntoa(&cli_ip(acptr));
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_HOS))
  {
    char *p2 = cli_user(acptr)->host;
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_SER))
  {
    const char *p2 = (feature_bool(FEAT_HIS_WHO_SERVERNAME) && !IsAnOper(sptr)) ?
                       feature_str(FEAT_HIS_SERVERNAME) :
                       cli_name(cli_user(acptr)->server);
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_NIC))
  {
    char *p2 = cli_name(acptr);
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_FLA))
  {
    *(p1++) = ' ';
    if (cli_user(acptr)->away)
      *(p1++) = 'G';
    else
      *(p1++) = 'H';
    if SeeOper(sptr,acptr)
      *(p1++) = '*';
    if (!chan) {
      /* No flags possible for the channel, so skip them all. */
    }
    else if (fields) {
      /* If you specified flags then we assume you know how to parse
       * multiple channel status flags, as this is currently the only
       * way to know if someone has @'s *and* is +'d.
       */
      if (IsChanOp(chan))
        *(p1++) = '@';
      if (HasVoice(chan))
        *(p1++) = '+';
      if (IsZombie(chan))
        *(p1++) = '!';
      if (IsDelayedJoin(chan))
        *(p1++) = '<';
    }
    else {
      if (IsChanOp(chan))
        *(p1++) = '@';
      else if (HasVoice(chan))
        *(p1++) = '+';
      else if (IsZombie(chan))
        *(p1++) = '!';
      else if (IsDelayedJoin(chan))
        *(p1++) = '<';
    }
    if (IsDeaf(acptr))
      *(p1++) = 'd';
    if (IsAnOper(sptr))
    {
      if (IsInvisible(acptr))
        *(p1++) = 'i';
      if (SendWallops(acptr))
        *(p1++) = 'w';
      if (SendDebug(acptr))
        *(p1++) = 'g';
    }
    if (HasHiddenHost(acptr))
      *(p1++) = 'x';
  }

  if (!fields || (fields & WHO_FIELD_DIS))
  {
    *p1++ = ' ';
    if (!fields)
      *p1++ = ':';              /* Place colon here for default reply */
    if (feature_bool(FEAT_HIS_WHO_HOPCOUNT) && !IsAnOper(sptr))
      *p1++ = (sptr == acptr) ? '0' : '3';
    else
      /* three digit hopcount maximum */
      p1 += ircd_snprintf(0, p1, 3, "%d", cli_hopcount(acptr));
  }

  if (fields & WHO_FIELD_IDL)
  {
    *p1++ = ' ';
    if (MyUser(acptr) &&
	(IsAnOper(sptr) || !feature_bool(FEAT_HIS_WHO_SERVERNAME) ||
	 acptr == sptr))
      p1 += ircd_snprintf(0, p1, 11, "%d",
                          CurrentTime - cli_user(acptr)->last);
    else
      *p1++ = '0';
  }

  if (fields & WHO_FIELD_ACC)
  {
    char *p2 = cli_user(acptr)->account;
    *(p1++) = ' ';
    if (*p2)
      while ((*p2) && (*(p1++) = *(p2++)));
    else
      *(p1++) = '0';
  }

  if (fields & WHO_FIELD_OPL)
  {
      if (!chan || !IsChanOp(chan))
      {
        strcpy(p1, " n/a");
        p1 += 4;
      }
      else
      {
        int vis_level = MAXOPLEVEL;
        if ((IsGlobalChannel(chan->channel->chname) ? IsOper(sptr) : IsAnOper(sptr))
            || is_chan_op(sptr, chan->channel))
          vis_level = OpLevel(chan);
        p1 += ircd_snprintf(0, p1, 5, " %d", vis_level);
      }
  }

  if (!fields || (fields & WHO_FIELD_REN))
  {
    char *p2 = cli_info(acptr);
    *p1++ = ' ';
    if (fields)
      *p1++ = ':';              /* Place colon here for special reply */
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  /* The first char will always be an useless blank and we 
     need to terminate buf1 */
  *p1 = '\0';
  p1 = buf1;
  send_reply(sptr, fields ? RPL_WHOSPCRPL : RPL_WHOREPLY, ++p1);
}
