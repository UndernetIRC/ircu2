/*
 * IRC - Internet Relay Chat, ircd/m_burst.c
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
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * ms_burst - server message handler
 *
 * --  by Run carlo@runaway.xs4all.nl  december 1995 till march 1997
 *
 * parv[0] = sender prefix
 * parv[1] = channel name
 * parv[2] = channel timestamp
 * The meaning of the following parv[]'s depend on their first character:
 * If parv[n] starts with a '+':
 * Net burst, additive modes
 *   parv[n] = <mode>
 *   parv[n+1] = <param> (optional)
 *   parv[n+2] = <param> (optional)
 * If parv[n] starts with a '%', then n will be parc-1:
 *   parv[n] = %<ban> <ban> <ban> ...
 * If parv[n] starts with another character:
 *   parv[n] = <nick>[:<mode>],<nick>[:<mode>],...
 *   where <mode> is the channel mode (ov) of nick and all following nicks.
 *
 * Example:
 * "S BURST #channel 87654321 +ntkl key 123 AAA,AAB:o,BAA,BAB:ov :%ban1 ban2"
 *
 * Anti net.ride code.
 *
 * When the channel already exist, and its TS is larger then
 * the TS in the BURST message, then we cancel all existing modes.
 * If its is smaller then the received BURST message is ignored.
 * If it's equal, then the received modes are just added.
 */
int ms_burst(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct ModeBuf modebuf, *mbuf = 0;
  struct Channel *chptr;
  time_t timestamp;
  struct Membership *member, *nmember;
  struct SLink *lp, **lp_p;
  unsigned int parse_flags = (MODE_PARSE_FORCE | MODE_PARSE_BURST);
  int param, nickpos = 0, banpos = 0;
  char modestr[BUFSIZE], nickstr[BUFSIZE], banstr[BUFSIZE];

  if (parc < 3)
    return protocol_violation(sptr,"Too few parameters for BURST");

  if (!IsBurst(sptr)) /* don't allow BURST outside of burst */
    return exit_client_msg(cptr, cptr, &me, "HACK: BURST message outside "
			   "net.burst from %s", cli_name(sptr));

  if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
    return 0; /* can't create the channel? */

  timestamp = atoi(parv[2]);

  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    /*
     * Kick local members if channel is +i or +k and our TS was larger
     * than the burst TS (anti net.ride). The modes hack is here because
     * we have to do this before mode_parse, as chptr may go away.
     */
    for (param = 3; param < parc; param++) {
      if (parv[param][0] != '+')
        continue;
      if (strchr(parv[param], 'i') || strchr(parv[param], 'k')) {
        for (member = chptr->members; member; member = nmember) {
          nmember=member->next_member;
          if (!MyUser(member->user) || IsZombie(member))
            continue;
          sendcmdto_serv_butone(&me, CMD_KICK, NULL, "%H %C :Net Rider", chptr, member->user);
          sendcmdto_channel_butserv_butone(&me, CMD_KICK, chptr, NULL, "%H %C :Net Rider", chptr, member->user);
          make_zombie(member, member->user, &me, &me, chptr);
        }
        /* Clear any outstanding rogue invites */
        mode_invite_clear(chptr);
      }
      break;
    }

    /* If the channel had only locals, it went away by now. */
    if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
      return 0; /* can't create the channel? */
  }

  /* turn off burst joined flag */
  for (member = chptr->members; member; member = member->next_member)
    member->status &= ~CHFL_BURST_JOINED;

  if (!chptr->creationtime) /* mark channel as created during BURST */
    chptr->mode.mode |= MODE_BURSTADDED;

  /* new channel or an older one */
  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    chptr->creationtime = timestamp;

    modebuf_init(mbuf = &modebuf, &me, cptr, chptr,
		 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);
    modebuf_mode(mbuf, MODE_DEL | chptr->mode.mode); /* wipeout modes */
    chptr->mode.mode &= ~(MODE_ADD | MODE_DEL | MODE_PRIVATE | MODE_SECRET |
			  MODE_MODERATED | MODE_TOPICLIMIT | MODE_INVITEONLY |
			  MODE_NOPRIVMSGS);

    parse_flags |= (MODE_PARSE_SET | MODE_PARSE_WIPEOUT); /* wipeout keys */

    /* mark bans for wipeout */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= CHFL_BURST_BAN_WIPEOUT;
  } else if (chptr->creationtime == timestamp) {
    modebuf_init(mbuf = &modebuf, &me, cptr, chptr,
		 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);

    parse_flags |= MODE_PARSE_SET; /* set new modes */
  }

  param = 3; /* parse parameters */
  while (param < parc) {
    switch (*parv[param]) {
    case '+': /* parameter introduces a mode string */
      param += mode_parse(mbuf, cptr, sptr, chptr, parc - param,
			  parv + param, parse_flags);
      break;

    case '%': /* parameter contains bans */
      if (parse_flags & MODE_PARSE_SET) {
	char *banlist = parv[param] + 1, *p = 0, *ban, *ptr;
	struct SLink *newban;

	for (ban = ircd_strtok(&p, banlist, " "); ban;
	     ban = ircd_strtok(&p, 0, " ")) {
	  ban = collapse(pretty_mask(ban));

	    /*
	     * Yeah, we should probably do this elsewhere, and make it better
	     * and more general; this will hold until we get there, though.
	     * I dislike the current add_banid API... -Kev
	     *
	     * I wish there were a better algo. for this than the n^2 one
	     * shown below *sigh*
	     */
	  for (lp = chptr->banlist; lp; lp = lp->next) {
	    if (!ircd_strcmp(lp->value.ban.banstr, ban)) {
	      ban = 0; /* don't add ban */
	      lp->flags &= ~CHFL_BURST_BAN_WIPEOUT; /* not wiping out */
	      break; /* new ban already existed; don't even repropagate */
	    } else if (!(lp->flags & CHFL_BURST_BAN_WIPEOUT) &&
		       !mmatch(lp->value.ban.banstr, ban)) {
	      ban = 0; /* don't add ban unless wiping out bans */
	      break; /* new ban is encompassed by an existing one; drop */
	    } else if (!mmatch(ban, lp->value.ban.banstr))
	      lp->flags |= CHFL_BAN_OVERLAPPED; /* remove overlapping ban */

	    if (!lp->next)
	      break;
	  }

	  if (ban) { /* add the new ban to the end of the list */
	    /* Build ban buffer */
	    if (!banpos) {
	      banstr[banpos++] = ' ';
	      banstr[banpos++] = ':';
	      banstr[banpos++] = '%';
	    } else
	      banstr[banpos++] = ' ';
	    for (ptr = ban; *ptr; ptr++) /* add ban to buffer */
	      banstr[banpos++] = *ptr;

	    newban = make_link(); /* create new ban */

	    DupString(newban->value.ban.banstr, ban);

	    DupString(newban->value.ban.who, 
		      cli_name(feature_bool(FEAT_HIS_BANWHO) ? &me : sptr));

	    newban->value.ban.when = TStime();

	    newban->flags = CHFL_BAN | CHFL_BURST_BAN; /* set flags */
	    if ((ptr = strrchr(ban, '@')) && check_if_ipmask(ptr + 1))
	      newban->flags |= CHFL_BAN_IPMASK;

	    newban->next = 0;
	    if (lp)
	      lp->next = newban; /* link it in */
	    else
	      chptr->banlist = newban;
	  }
	}
      } 
      param++; /* look at next param */
      break;

    default: /* parameter contains clients */
      {
	struct Client *acptr;
	char *nicklist = parv[param], *p = 0, *nick, *ptr;
	int default_mode = CHFL_DEOPPED | CHFL_BURST_JOINED;
	int last_mode = CHFL_DEOPPED | CHFL_BURST_JOINED;

	for (nick = ircd_strtok(&p, nicklist, ","); nick;
	     nick = ircd_strtok(&p, 0, ",")) {

	  if ((ptr = strchr(nick, ':'))) { /* new flags; deal */
	    *ptr++ = '\0';

	    if (parse_flags & MODE_PARSE_SET) {
	      for (default_mode = CHFL_DEOPPED | CHFL_BURST_JOINED; *ptr;
		   ptr++) {
		if (*ptr == 'o') /* has oper status */
		  default_mode = (default_mode & ~CHFL_DEOPPED) | CHFL_CHANOP;
		else if (*ptr == 'v') /* has voice status */
		  default_mode |= CHFL_VOICE;
		else /* I don't recognize that flag */
		  break; /* so stop processing */
	      }
	    }
	  }

	  if (!(acptr = findNUser(nick)) || cli_from(acptr) != cptr)
	    continue; /* ignore this client */

	  /* Build nick buffer */
	  nickstr[nickpos] = nickpos ? ',' : ' '; /* first char */
	  nickpos++;

	  for (ptr = nick; *ptr; ptr++) /* store nick */
	    nickstr[nickpos++] = *ptr;

	  if (default_mode != last_mode) { /* if mode changed... */
	    last_mode = default_mode;

	    nickstr[nickpos++] = ':'; /* add a specifier */
	    if (default_mode & CHFL_CHANOP)
	      nickstr[nickpos++] = 'o';
	    if (default_mode & CHFL_VOICE)
	      nickstr[nickpos++] = 'v';
	  }

	  add_user_to_channel(chptr, acptr, default_mode);
	  sendcmdto_channel_butserv_butone(acptr, CMD_JOIN, chptr, NULL, "%H", chptr);
	}
      }
      param++;
      break;
    } /* switch (*parv[param]) { */
  } /* while (param < parc) { */

  nickstr[nickpos] = '\0';
  banstr[banpos] = '\0';

  if (parse_flags & MODE_PARSE_SET) {
    modebuf_extract(mbuf, modestr + 1); /* for sending BURST onward */
    modestr[0] = modestr[1] ? ' ' : '\0';
  } else
    modestr[0] = '\0';

  sendcmdto_serv_butone(sptr, CMD_BURST, cptr, "%H %Tu%s%s%s", chptr,
			chptr->creationtime, modestr, nickstr, banstr);

  if (parse_flags & MODE_PARSE_WIPEOUT || banpos)
    mode_ban_invalidate(chptr);

  if (parse_flags & MODE_PARSE_SET) { /* any modes changed? */
    /* first deal with channel members */
    for (member = chptr->members; member; member = member->next_member) {
      if (member->status & CHFL_BURST_JOINED) { /* joined during burst */
	if (member->status & CHFL_CHANOP)
	  modebuf_mode_client(mbuf, MODE_ADD | CHFL_CHANOP, member->user);
	if (member->status & CHFL_VOICE)
	  modebuf_mode_client(mbuf, MODE_ADD | CHFL_VOICE, member->user);
      } else if (parse_flags & MODE_PARSE_WIPEOUT) { /* wipeout old ops */
	if (member->status & CHFL_CHANOP)
	  modebuf_mode_client(mbuf, MODE_DEL | CHFL_CHANOP, member->user);
	if (member->status & CHFL_VOICE)
	  modebuf_mode_client(mbuf, MODE_DEL | CHFL_VOICE, member->user);
	member->status = ((member->status & ~(CHFL_CHANOP | CHFL_VOICE)) |
			  CHFL_DEOPPED);
      }
    }

    /* Now deal with channel bans */
    lp_p = &chptr->banlist;
    while (*lp_p) {
      lp = *lp_p;

      /* remove ban from channel */
      if (lp->flags & (CHFL_BAN_OVERLAPPED | CHFL_BURST_BAN_WIPEOUT)) {
	modebuf_mode_string(mbuf, MODE_DEL | MODE_BAN,
			    lp->value.ban.banstr, 1); /* let it free banstr */

	*lp_p = lp->next; /* clip out of list */
	MyFree(lp->value.ban.who); /* free who */
	free_link(lp); /* free ban */
	continue;
      } else if (lp->flags & CHFL_BURST_BAN) /* add ban to channel */
	modebuf_mode_string(mbuf, MODE_ADD | MODE_BAN,
			    lp->value.ban.banstr, 0); /* don't free banstr */

      lp->flags &= (CHFL_BAN | CHFL_BAN_IPMASK); /* reset the flag */
      lp_p = &(*lp_p)->next;
    }
  }

  return mbuf ? modebuf_flush(mbuf) : 0;
}
