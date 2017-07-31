/*
 * IRC - Internet Relay Chat, ircd/m_part.c
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

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Handle a PART message from a client connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is a comma-separated list of channel names
 * \li \a parv[\a parc - 1] is the parting comment
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_part(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  int colors = 0;
  char *p = 0;
  char *name;

  /* check number of arguments */
  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  /* init join/part buffer */
  joinbuf_init(&parts, sptr, cptr, JOINBUF_TYPE_PART,
	       (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0,
	       0);

  /* check for colors in message */
  if (parts.jb_comment) {
    for (p = parts.jb_comment; *p != '\0'; ++p) {
      if (*p == 3 || *p == 27) {
        colors = 1;
        break;
      }
    }
  }

  /* scan through channel list */
  for (name = ircd_strtok(&p, parv[1], ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    unsigned int flags = 0;

    chptr = get_channel(sptr, name, CGT_NO_CREATE); /* look up channel */

    if (!chptr) { /* complain if there isn't such a channel */
      send_reply(sptr, ERR_NOSUCHCHANNEL, name);
      continue;
    }

    if (!(member = find_member_link(chptr, sptr))) { /* complain if not on */
      send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
      continue;
    }

    assert(!IsZombie(member)); /* Local users should never zombie */

    if (!member_can_send_to_channel(member, 0))
    {
      flags |= CHFL_BANNED;
      /* Remote clients don't want to see a comment either. */
      parts.jb_comment = 0;
    }

    if ((member->channel->mode.mode & MODE_NOCOLOR) && colors)
      flags |= CHFL_BANNED;

    if (IsDelayedJoin(member))
      flags |= CHFL_DELAYED;

    joinbuf_join(&parts, chptr, flags); /* part client from channel */
    check_spambot_warning(sptr);
  }

  return joinbuf_flush(&parts); /* flush channel parts */
}

/** Handle a PART message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is a comma-separated list of channel names
 * \li \a parv[\a parc - 1] is the parting comment
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_part(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  unsigned int flags;
  char *p = 0;
  char *name;

  /* check number of arguments */
  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  /* init join/part buffer */
  joinbuf_init(&parts, sptr, cptr, JOINBUF_TYPE_PART,
	       (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0,
	       0);

  /* scan through channel list */
  for (name = ircd_strtok(&p, parv[1], ","); name;
       name = ircd_strtok(&p, 0, ",")) {

    flags = 0;

    chptr = get_channel(sptr, name, CGT_NO_CREATE); /* look up channel */

    if (!chptr || IsLocalChannel(name) ||
	!(member = find_member_link(chptr, sptr)))
      continue; /* ignore from remote clients */

    if (IsZombie(member)) /* figure out special flags... */
      flags |= CHFL_ZOMBIE;

    if (IsDelayedJoin(member))
      flags |= CHFL_DELAYED;

    /* part user from channel */
    joinbuf_join(&parts, chptr, flags);
  }

  return joinbuf_flush(&parts); /* flush channel parts */
}
