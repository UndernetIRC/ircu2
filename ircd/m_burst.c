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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
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
  struct Membership *member;
  struct SLink *lp, **lp_p;
  unsigned int parse_flags = (MODE_PARSE_FORCE | MODE_PARSE_BURST);
  int param, nickpos = 0, banpos = 0;
  char modestr[IRC_BUFSIZE], nickstr[IRC_BUFSIZE], banstr[IRC_BUFSIZE];

  if (parc < 4)
    return 0;

  if (!IsBurst(sptr)) /* don't allow BURST outside of burst */
    return exit_client_msg(cptr, cptr, &me, "HACK: BURST message outside "
			   "net.burst from %s", sptr->name);

  if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
    return 0; /* can't create the channel? */

  timestamp = atoi(parv[2]);

  /* turn off burst joined flag */
  for (member = chptr->members; member; member = member->next_member)
    member->status &= ~CHFL_BURST_JOINED;

  if (!chptr->creationtime) /* mark channel as created during BURST */
    chptr->mode.mode |= MODE_BURSTADDED;

  /* new channel or an older one */
  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    chptr->creationtime = timestamp;

    modebuf_init(mbuf = &modebuf, sptr, cptr, chptr, MODEBUF_DEST_CHANNEL);
    modebuf_mode(mbuf, MODE_DEL | chptr->mode.mode); /* wipeout modes */
    chptr->mode.mode &= ~(MODE_ADD | MODE_DEL | MODE_PRIVATE | MODE_SECRET |
			  MODE_MODERATED | MODE_TOPICLIMIT | MODE_INVITEONLY |
			  MODE_NOPRIVMSGS);

    parse_flags |= (MODE_PARSE_SET | MODE_PARSE_WIPEOUT); /* wipeout keys */

    /* mark bans for wipeout */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= CHFL_BURST_BAN_WIPEOUT;
  } else if (chptr->creationtime == timestamp) {
    modebuf_init(mbuf = &modebuf, sptr, cptr, chptr, MODEBUF_DEST_CHANNEL);

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
	    DupString(newban->value.ban.who, sptr->name);
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

	  if (!(acptr = findNUser(nick)) || acptr->from != cptr)
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
	  sendcmdto_channel_butserv(acptr, CMD_JOIN, chptr, "%H", chptr);
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
#if 0
int ms_burst(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  time_t          timestamp;
  int             netride = 0;
  int             wipeout = 0;
  int             n;
  int             send_it = 0;
  int             add_banid_not_called = 1;
  struct Mode*    current_mode;
  size_t          sblen;
  size_t          mblen = 0;
  int             mblen2;
  int             pblen2;
  int             cnt;
  int             prev_mode;
  char            prev_key[KEYLEN + 1];
  struct Membership* member;
  struct SLink*   lp;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  char bmodebuf[MODEBUFLEN];
  char bparambuf[MODEBUFLEN];

  /* BURST is only for servers and has at least 4 parameters */
  if (!IsServer(cptr) || parc < 4)
    return 0;

  if (!IsBurst(sptr))
  {
    int i;
    char *p;
    if (find_conf_byhost(cptr->confs, sptr->name, CONF_UWORLD))
    {
      p =
          sprintf_irc(sendbuf, /* XXX DYING */
          ":%s NOTICE * :*** Notice -- HACK(4): %s BURST %s %s", me.name,
          sptr->name, parv[1], parv[2]);
      for (i = 3; i < parc - 1; ++i)
        p = sprintf_irc(p, " %s", parv[i]);
      sprintf_irc(p, " :%s", parv[parc - 1]);
      sendbufto_op_mask(SNO_HACK4); /* XXX DYING */
    }
    else
    {
#if 1            /* FIXME: This should be removed after all HUBs upgraded to ircu2.10.05 */
      SetBurst(sptr);
      if (MyConnect(sptr))
#endif
        return exit_client_msg(cptr, cptr, &me,
            "HACK: BURST message outside net.burst from %s", sptr->name);
    }
  }

  /* Find the channel, or create it - note that the creation time
   * will be 0 if it has to be created */
  chptr = get_channel(sptr, parv[1], CGT_CREATE);
  current_mode = &chptr->mode;
  prev_mode = chptr->mode.mode;
  if (*chptr->mode.key)
  {
    prev_mode |= MODE_KEY;
    strcpy(prev_key, chptr->mode.key);
  }
  if (chptr->mode.limit)
    prev_mode |= MODE_LIMIT;

  timestamp = atoi(parv[2]);

  /* Copy the new TS when the received creationtime appears to be older */
  if (!chptr->creationtime || chptr->creationtime > timestamp)
  {
    /* Set the new timestamp */
    chptr->creationtime = timestamp;
    send_it = 1;                /* Make sure we pass on the different timestamp ! */
    /* Mark all bans as needed to be wiped out */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= CHFL_BURST_BAN_WIPEOUT;
    /*
     * Only the first BURST for this channel can have creationtime > timestamp,
     * so at this moment ALL members are on OUR side, and thus all net.riders:
     */
    wipeout = 1;
  }
  for (member = chptr->members; member; member = member->next_member)
    member->status &= ~CHFL_BURST_JOINED;    /* Set later for nicks in the BURST msg */
  /* If `wipeout' is set then these will be deopped later. */

  /* If the entering creationtime is younger, ignore the modes */
  if (chptr->creationtime < timestamp)
    netride = 1;                /* Only pass on the nicks (so they JOIN) */

  /* Prepare buffers to pass the message */
  *bparambuf = *bmodebuf = *parabuf = '\0';
  pblen2 = 0;
  *modebuf = '+';
  mblen2 = 1;
  cnt = 0;
  sblen = sprintf_irc(sendbuf, "%s B %s " TIME_T_FMT, /* XXX DYING */
      NumServ(sptr), chptr->chname, chptr->creationtime) - sendbuf; /* XXX DYING */

  /* Run over all remaining parameters */
  for (n = 3; n < parc; n++)
    switch (*parv[n])           /* What type is it ? mode, nicks or bans ? */
    {
      case '+':         /* modes */
      {
        char *p = parv[n];
        while (*(++p))          /* Run over all mode characters */
        {
          switch (*p)           /* which mode ? */
          {
              /*
               * The following cases all do the following:
               * - In case wipeout needed, reset 'prev_mode' to indicate this
               *   mode should not be cancelled.
               * - If wipeout or (not netride and the new mode is a change),
               *   add it to bmodebuf and bparabuf for propagation.
               * - Else ignore it.
               * - Add it to modebuf and parabuf for propagation to the
               *   clients when not netride and the new mode is a change.
               * Special cases:
               * - If a +s is received, cancel a +p and sent a -p to the
               *   clients too (if +p was set).
               * - If a +p is received and +s is set, ignore the +p.
               */
            case 'i':
            {
              int tmp;
              prev_mode &= ~MODE_INVITEONLY;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_INVITEONLY)) || wipeout)
              {
                bmodebuf[mblen++] = 'i';
                current_mode->mode |= MODE_INVITEONLY;
              }
              if (!tmp)
                modebuf[mblen2++] = 'i';
              break;
            }
            case 'k':
            {
              int tmp;
              char *param = parv[++n];
              prev_mode &= ~MODE_KEY;
              if (!(tmp = netride || (*current_mode->key &&
                  (!strcmp(current_mode->key, param) ||
                  (!wipeout && strcmp(current_mode->key, param) < 0)))) ||
                  wipeout)
              {
                bmodebuf[mblen++] = 'k';
                strcat(bparambuf, " ");
                strcat(bparambuf, param);
                ircd_strncpy(current_mode->key, param, KEYLEN);
              }
              if (!tmp && !wipeout)
              {
                modebuf[mblen2++] = 'k';
                parabuf[pblen2++] = ' ';
                strcpy(parabuf + pblen2, param);
                pblen2 += strlen(param);
                cnt++;
              }
              break;
            }
            case 'l':
            {
              int tmp;
              unsigned int param = atoi(parv[++n]);
              prev_mode &= ~MODE_LIMIT;
              if (!(tmp = netride || (current_mode->limit &&
                  (current_mode->limit == param ||
                  (!wipeout && current_mode->limit < param)))) || wipeout)
              {
                bmodebuf[mblen++] = 'l';
                sprintf_irc(bparambuf + strlen(bparambuf), " %d", param);
                current_mode->limit = param;
              }
              if (!tmp)
              {
                modebuf[mblen2++] = 'l';
                pblen2 = sprintf_irc(parabuf + pblen2, " %d", param) - parabuf;
                cnt++;
              }
              break;
            }
            case 'm':
            {
              int tmp;
              prev_mode &= ~MODE_MODERATED;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_MODERATED)) || wipeout)
              {
                bmodebuf[mblen++] = 'm';
                current_mode->mode |= MODE_MODERATED;
              }
              if (!tmp)
                modebuf[mblen2++] = 'm';
              break;
            }
            case 'n':
            {
              int tmp;
              prev_mode &= ~MODE_NOPRIVMSGS;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_NOPRIVMSGS)) || wipeout)
              {
                bmodebuf[mblen++] = 'n';
                current_mode->mode |= MODE_NOPRIVMSGS;
              }
              if (!tmp)
                modebuf[mblen2++] = 'n';
              break;
            }
            case 'p':
            {
              int tmp;

              /* Special case: */
              if (!netride && !wipeout && (current_mode->mode & MODE_SECRET))
                break;

              prev_mode &= ~MODE_PRIVATE;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_PRIVATE)) || wipeout)
              {
                bmodebuf[mblen++] = 'p';
                current_mode->mode |= MODE_PRIVATE;
              }
              if (!tmp)
                modebuf[mblen2++] = 'p';
              break;
            }
            case 's':
            {
              int tmp;
              prev_mode &= ~MODE_SECRET;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_SECRET)) || wipeout)
              {
                bmodebuf[mblen++] = 's';
                current_mode->mode |= MODE_SECRET;
              }
              if (!tmp)
                modebuf[mblen2++] = 's';

              /* Special case: */
              if (!netride && !wipeout && (current_mode->mode & MODE_PRIVATE))
              {
                int i;
                for (i = mblen2 - 1; i >= 0; --i)
                  modebuf[i + 2] = modebuf[i];
                modebuf[0] = '-';
                modebuf[1] = 'p';
                mblen2 += 2;
                current_mode->mode &= ~MODE_PRIVATE;
              }

              break;
            }
            case 't':
            {
              int tmp;
              prev_mode &= ~MODE_TOPICLIMIT;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_TOPICLIMIT)) || wipeout)
              {
                bmodebuf[mblen++] = 't';
                current_mode->mode |= MODE_TOPICLIMIT;
              }
              if (!tmp)
                modebuf[mblen2++] = 't';
              break;
            }
          }
        }                       /* <-- while over all modes */

        bmodebuf[mblen] = '\0';
        sendbuf[sblen] = '\0'; /* XXX DYING */
        if (mblen)              /* Anything to send at all ? */
        {
          send_it = 1;
          strcpy(sendbuf + sblen, " +"); /* XXX DYING */
          sblen += 2;
          strcpy(sendbuf + sblen, bmodebuf); /* XXX DYING */
          sblen += mblen;
          strcpy(sendbuf + sblen, bparambuf); /* XXX DYING */
          sblen += strlen(bparambuf);
        }
        break;                  /* Done mode part */
      }
      case '%':         /* bans */
      {
        char *pv, *p = 0, *ban;
        int first = 1;
        if (netride)
          break;                /* Ignore bans */
        /* Run over all bans */
        for (pv = parv[n] + 1; (ban = ircd_strtok(&p, pv, " ")); pv = 0)
        {
          int ret;
          /*
           * The following part should do the following:
           * - If the new (un)ban is not a _change_ it is ignored.
           * - Else, add it to sendbuf for later use.
           * - If sendbuf is full, send it, and prepare a new
           *   message in sendbuf.
           */
          ret = add_banid(sptr, chptr, ban, 1, add_banid_not_called);
          if (ret == 0)
          {
            add_banid_not_called = 0;
            /* Mark this new ban so we can send it to the clients later */
            chptr->banlist->flags |= CHFL_BURST_BAN;
          }
          if (ret != -1)
            /* A new ban was added or an existing one needs to be passed on.
             * Also add it to sendbuf: */
            add_token_to_sendbuf(ban, &sblen, &first, &send_it, '%', 0); /* XXX DYING */
        }
        break;                  /* Done bans part */
      }
      default:                  /* nicks */
      {
        char *pv, *p = 0, *nick, *ptr;
        int first = 1;
        /* Default mode: */
        int default_mode = CHFL_DEOPPED;
        /* Run over all nicks */
        for (pv = parv[n]; (nick = ircd_strtok(&p, pv, ",")); pv = 0)
        {
          struct Client *acptr;
          if ((ptr = strchr(nick, ':')))        /* New default mode ? */
          {
            *ptr = '\0';        /* Fix 'nick' */
            acptr = findNUser(nick);
            if (!netride)
            {
              /* Calculate new mode change: */
              default_mode = CHFL_DEOPPED;
              while (*(++ptr))
                if (*ptr == 'o')
                {
                  default_mode |= CHFL_CHANOP;
                  default_mode &= ~CHFL_DEOPPED;
                }
                else if (*ptr == 'v')
                  default_mode |= CHFL_VOICE;
                else
                  break;
            }
          }
          else
            acptr = findNUser(nick);
          /*
           * Note that at this point we already received a 'NICK' for any
           * <nick> numeric that is joining (and possibly opped) here.
           * Therefore we consider the following situations:
           * - The <nick> numeric exists and is from the direction of cptr: ok
           * - The <nick> numeric does not exist:
           *   Apparently this previous <nick> numeric was killed (upstream)
           *   or it collided with an existing <nick> name.
           * - The <nick> numeric exists but is from another direction:
           *   Apparently this previous <nick> numeric was killed,
           *   and due to a reroute it signed on via another link (probably
           *   a nick [numeric] collision).
           * Note that it can't be a QUIT or SQUIT, because a QUIT would
           * come from the same direction as the BURST (cptr) while an
           * upstream SQUIT removes the source (server) and we would thus
           * have this BURST ignored already.
           * This means that if we find the nick and it is from the correct
           * direction, it joins. If it doesn't exist or is from another
           * direction, we have to ignore it. If all nicks are ignored, we
           * remove the channel again when it is empty and don't propagate
           * the BURST message.
           */
          if (acptr && acptr->from == cptr)
          {
            /*
             * The following should do the following:
             * - Add it to sendbuf for later use.
             * - If sendbuf is full, send it, and prepare a new
             *   message in sendbuf.
             */
            add_token_to_sendbuf(nick, &sblen, &first, &send_it, 0, /* XXX DYING */
                default_mode);
            /* Let is take effect: (Note that in the case of a netride
             * 'default_mode' is always CHFL_DEOPPED here). */
            add_user_to_channel(chptr, acptr, default_mode | CHFL_BURST_JOINED);
          }
        }                       /* <-- Next nick */
        if (!chptr->members)    /* All nicks collided and channel is empty ? */
        {
          sub1_from_channel(chptr);
          return 0;             /* Forget about the (rest of the) message... */
        }
        break;                  /* Done nicks part */
      }
    }                           /* <-- Next parameter if any */
  if (!chptr->members)          /* This message only contained bans (then the previous
                                   message only contained collided nicks, see above) */
  {
    sub1_from_channel(chptr);
    if (!add_banid_not_called)
      while (next_removed_overlapped_ban());
    return 0;                   /* Forget about the (rest of the) message... */
  }

  /* The last (possibly only) message is always send here */
  if (send_it)                  /* Anything (left) to send ? */
  {
    struct DLink *lp;
    struct Membership* member;

    /* send 'sendbuf' to all downlinks */
    for (lp = me.serv->down; lp; lp = lp->next)
    {
      if (lp->value.cptr == cptr)
        continue;
      if (Protocol(lp->value.cptr) > 9)
        sendbufto_one(lp->value.cptr); /* XXX DYING */
    }

    /*
     * Now we finally can screw sendbuf again...
     * Send all changes to the local clients:
     *
     * First send all joins and op them, because 2.9 servers
     * would protest with a HACK if we first de-opped people.
     * However, we don't send the +b bans yes, because we
     * DO first want to -b the old bans (otherwise it's confusing).
     */

    /* Send all joins: */
    for (member = chptr->members; member; member = member->next_member)
      if (IsBurstJoined(member))
      {
        sendto_channel_butserv(chptr, member->user, ":%s JOIN :%s", /* XXX DYING */
                               member->user->name, chptr->chname);
      }

    if (!netride)
    {
      /* Send all +o and +v modes: */
      for (member = chptr->members; member; member = member->next_member)
      {
        if (IsBurstJoined(member))
        {
          int mode = CHFL_CHANOP;
          for (;;)
          {
            if ((member->status & mode))
            {
              modebuf[mblen2++] = (mode == CHFL_CHANOP) ? 'o' : 'v';
              parabuf[pblen2++] = ' ';
              strcpy(parabuf + pblen2, member->user->name);
              pblen2 += strlen(member->user->name);
              if (6 == ++cnt)
              {
                modebuf[mblen2] = 0;
                sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DYING */
                    parv[0], chptr->chname, modebuf, parabuf);
                *parabuf = 0;
                pblen2 = 0;
                mblen2 = 1;
                cnt = 0;
              }
            }
            if (mode == CHFL_CHANOP)
              mode = CHFL_VOICE;
            else
              break;
          }
        }
      }
      /* Flush MODEs: */
      if (cnt > 0 || mblen2 > 1)
      {
        modebuf[mblen2] = 0;
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DYING */
            parv[0], chptr->chname, modebuf, parabuf);
      }
    }
  }

  if (wipeout)
  {
    struct Membership* member;
    struct SLink**     ban;
    int                mode;
    char               m;
    int                count = -1;

    /* Now cancel all previous simple modes */
    if ((prev_mode & MODE_SECRET))
      cancel_mode(sptr, chptr, 's', 0, &count); /* XXX DYING */
    if ((prev_mode & MODE_PRIVATE))
      cancel_mode(sptr, chptr, 'p', 0, &count); /* XXX DYING */
    if ((prev_mode & MODE_MODERATED))
      cancel_mode(sptr, chptr, 'm', 0, &count); /* XXX DYING */
    if ((prev_mode & MODE_TOPICLIMIT))
      cancel_mode(sptr, chptr, 't', 0, &count); /* XXX DYING */
    if ((prev_mode & MODE_INVITEONLY))
      cancel_mode(sptr, chptr, 'i', 0, &count); /* XXX DYING */
    if ((prev_mode & MODE_NOPRIVMSGS))
      cancel_mode(sptr, chptr, 'n', 0, &count); /* XXX DYING */
    if ((prev_mode & MODE_LIMIT))
    {
      current_mode->limit = 0;
      cancel_mode(sptr, chptr, 'l', 0, &count); /* XXX DYING */
    }
    if ((prev_mode & MODE_KEY))
    {
      *current_mode->key = 0;
      cancel_mode(sptr, chptr, 'k', prev_key, &count); /* XXX DYING */
    }
    current_mode->mode &= ~prev_mode;

    /* And deop and devoice all net.riders on my side */
    mode = CHFL_CHANOP;
    m = 'o';
    for (;;)
    {
      struct Membership* member_next = 0;

      for (member = chptr->members; member; member = member_next)
      {
        member_next = member->next_member;
        if (IsBurstJoined(member))
          continue;             /* This is not a net.rider from
                                   this side of the net.junction */
#if defined(NO_INVITE_NETRIDE)
        /*
         * Kick net riding users from invite only channels.
         *  - Isomer 25-11-1999
         */
        if (chptr->mode.mode & MODE_INVITEONLY) {
          /* kick is magical - lotsa zombies and other undead.
           * I'm hoping this is the right idea, comments anyone?
           * Set everyone to a zombie, remove ops, and then send kicks
           * everywhere...
           */
           if (IsZombie(member)) { /* don't kick ppl twice */
                member->status = member->status & ~mode;
                continue;
           }

           sendto_highprot_butone(0, 10, "%s " TOK_KICK " %s %s%s :Net Rider", /* XXX DYING */
            NumServ(&me), chptr->chname, NumNick(member->user));
           sendto_channel_butserv(chptr, sptr, /* XXX DYING */
            ":%s KICK %s %s :Net Rider", me.name, chptr->chname,
            member->user->name);

           if (MyUser(member->user)) {
             sendto_lowprot_butone(0, 9, ":%s PART %s", /* XXX DYING */
               member->user->name, chptr->chname, member->user->name);
             sendto_highprot_butone(0, 10, "%s%s PART %s", /* XXX DYING */
               NumNick(member->user), chptr->chname);
             remove_user_from_channel(member->user, chptr);
           }
           else {
             member->status = (member->status & ~mode) | CHFL_ZOMBIE;
           }
           continue;
        }
#endif /* defined(NO_INVITE_NETRIDE) */
        if ((member->status & mode))
        {
          member->status &= ~mode;
          if (mode == CHFL_CHANOP)
            SetDeopped(member);
          cancel_mode(sptr, chptr, m, member->user->name, &count); /* XXX DYING */
        }
      }
      if (mode == CHFL_VOICE)
        break;
      mode = CHFL_VOICE;
      m = 'v';
    }

    /* And finally wipeout all bans that are left */
    for (ban = &chptr->banlist; *ban; ) {
      struct SLink* tmp = *ban;
      if ((tmp->flags & CHFL_BURST_BAN_WIPEOUT)) {
        struct Membership* member_z;

        *ban = tmp->next;
        cancel_mode(sptr, chptr, 'b', tmp->value.ban.banstr, &count); /* XXX DYING */

        /* Copied from del_banid(): */
        MyFree(tmp->value.ban.banstr);
        MyFree(tmp->value.ban.who);
        free_link(tmp);

        /* Erase ban-valid-bit, for channel members that are banned */
        for (member_z = chptr->members; member_z; member_z = member_z->next_member)
          if ((member_z->status & CHFL_BANVALIDMASK) == CHFL_BANVALIDMASK)
            ClearBanValid(member_z);
      }
      else
        ban = &tmp->next;
    }
    /* Also wipeout overlapped bans */
    if (!add_banid_not_called)
    {
      struct SLink *ban;
      while ((ban = next_removed_overlapped_ban()))
        cancel_mode(sptr, chptr, 'b', ban->value.ban.banstr, &count); /* XXX DYING */
    }
    cancel_mode(sptr, chptr, 0, 0, &count);  /* flush */ /* XXX DYING */
  }

  if (send_it && !netride)
  {
    struct SLink *bl;
    int deban;

    if (add_banid_not_called || !(bl = next_removed_overlapped_ban()))
    {
      deban = 0;
      bl = chptr->banlist;
      *modebuf = '+';
    }
    else
    {
      deban = 1;
      *modebuf = '-';
    }

    mblen2 = 1;
    pblen2 = 0;
    cnt = 0;
    for (;;)
    {
      size_t nblen = 0;
      if (bl)
        nblen = strlen(bl->value.ban.banstr);
      if (cnt == 6 || (!bl && cnt) || pblen2 + nblen + 12 > MODEBUFLEN) /* The last check is to make sure
                                                                           that the receiving 2.9 will
                                                                           still process this */
      {
        /* Time to send buffer */
        modebuf[mblen2] = 0;
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DYING */
            parv[0], chptr->chname, modebuf, parabuf);
        *modebuf = deban ? '-' : '+';
        mblen2 = 1;
        pblen2 = 0;
        cnt = 0;
      }
      if (!bl)                  /* Done ? */
        break;
      if (deban || (bl->flags & CHFL_BURST_BAN))
      {
        /* Add ban to buffers and remove it */
        modebuf[mblen2++] = 'b';
        parabuf[pblen2++] = ' ';
        strcpy(parabuf + pblen2, bl->value.ban.banstr);
        pblen2 += nblen;
        cnt++;
        bl->flags &= ~CHFL_BURST_BAN;
      }
      if (deban)
      {
        if (!(bl = next_removed_overlapped_ban()))
        {
          deban = 0;
          modebuf[mblen2++] = '+';
          bl = chptr->banlist;
        }
      }
      else
        bl = bl->next;
    }
    /* Flush MODE [-b]+b ...: */
    if (cnt > 0 || mblen2 > 1)
    {
      modebuf[mblen2] = 0;
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DYING */
          parv[0], chptr->chname, modebuf, parabuf);
    }
  }
  return 0;
}
#endif

#if 0
/*
 * m_burst  --  by Run carlo@runaway.xs4all.nl  december 1995 till march 1997
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
int m_burst(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel* chptr;
  time_t          timestamp;
  int             netride = 0;
  int             wipeout = 0;
  int             n;
  int             send_it = 0;
  int             add_banid_not_called = 1;
  struct Mode*    current_mode;
  size_t          sblen;
  size_t          mblen = 0;
  int             mblen2;
  int             pblen2;
  int             cnt;
  int             prev_mode;
  char            prev_key[KEYLEN + 1];
  struct Membership* member;
  struct SLink*   lp;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  char bmodebuf[MODEBUFLEN];
  char bparambuf[MODEBUFLEN];

  /* BURST is only for servers and has at least 4 parameters */
  if (!IsServer(cptr) || parc < 4)
    return 0;

  if (!IsBurst(sptr))
  {
    int i;
    char *p;
    if (find_conf_byhost(cptr->confs, sptr->name, CONF_UWORLD))
    {
      p =
          sprintf_irc(sendbuf, /* XXX DEAD */
          ":%s NOTICE * :*** Notice -- HACK(4): %s BURST %s %s", me.name,
          sptr->name, parv[1], parv[2]);
      for (i = 3; i < parc - 1; ++i)
        p = sprintf_irc(p, " %s", parv[i]);
      sprintf_irc(p, " :%s", parv[parc - 1]);
      sendbufto_op_mask(SNO_HACK4); /* XXX DEAD */
    }
    else
    {
#if 1                           /* FIXME: This should be removed after all HUBs upgraded to ircu2.10.05 */
      SetBurst(sptr);
      if (MyConnect(sptr))
#endif
        return exit_client_msg(cptr, cptr, &me,
            "HACK: BURST message outside net.burst from %s", sptr->name);
    }
  }

  /* Find the channel, or create it - note that the creation time
   * will be 0 if it has to be created */
  chptr = get_channel(sptr, parv[1], CGT_CREATE);
  current_mode = &chptr->mode;
  prev_mode = chptr->mode.mode;
  if (*chptr->mode.key)
  {
    prev_mode |= MODE_KEY;
    strcpy(prev_key, chptr->mode.key);
  }
  if (chptr->mode.limit)
    prev_mode |= MODE_LIMIT;

  timestamp = atoi(parv[2]);

  /* Copy the new TS when the received creationtime appears to be older */
  if (!chptr->creationtime || chptr->creationtime > timestamp)
  {
    /* Set the new timestamp */
    chptr->creationtime = timestamp;
    send_it = 1;                /* Make sure we pass on the different timestamp ! */
    /* Mark all bans as needed to be wiped out */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= CHFL_BURST_BAN_WIPEOUT;
    /*
     * Only the first BURST for this channel can have creationtime > timestamp,
     * so at this moment ALL members are on OUR side, and thus all net.riders:
     */
    wipeout = 1;
  }
  for (member = chptr->members; member; member = member->next_member)
    member->status &= ~CHFL_BURST_JOINED;    /* Set later for nicks in the BURST msg */
  /* If `wipeout' is set then these will be deopped later. */

  /* If the entering creationtime is younger, ignore the modes */
  if (chptr->creationtime < timestamp)
    netride = 1;                /* Only pass on the nicks (so they JOIN) */

  /* Prepare buffers to pass the message */
  *bparambuf = *bmodebuf = *parabuf = '\0';
  pblen2 = 0;
  *modebuf = '+';
  mblen2 = 1;
  cnt = 0;
  sblen = sprintf_irc(sendbuf, "%s B %s " TIME_T_FMT, /* XXX DEAD */
      NumServ(sptr), chptr->chname, chptr->creationtime) - sendbuf; /* XXX DEAD */

  /* Run over all remaining parameters */
  for (n = 3; n < parc; n++)
    switch (*parv[n])           /* What type is it ? mode, nicks or bans ? */
    {
      case '+':         /* modes */
      {
        char *p = parv[n];
        while (*(++p))          /* Run over all mode characters */
        {
          switch (*p)           /* which mode ? */
          {
              /*
               * The following cases all do the following:
               * - In case wipeout needed, reset 'prev_mode' to indicate this
               *   mode should not be cancelled.
               * - If wipeout or (not netride and the new mode is a change),
               *   add it to bmodebuf and bparabuf for propagation.
               * - Else ignore it.
               * - Add it to modebuf and parabuf for propagation to the
               *   clients when not netride and the new mode is a change.
               * Special cases:
               * - If a +s is received, cancel a +p and sent a -p to the
               *   clients too (if +p was set).
               * - If a +p is received and +s is set, ignore the +p.
               */
            case 'i':
            {
              int tmp;
              prev_mode &= ~MODE_INVITEONLY;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_INVITEONLY)) || wipeout)
              {
                bmodebuf[mblen++] = 'i';
                current_mode->mode |= MODE_INVITEONLY;
              }
              if (!tmp)
                modebuf[mblen2++] = 'i';
              break;
            }
            case 'k':
            {
              int tmp;
              char *param = parv[++n];
              prev_mode &= ~MODE_KEY;
              if (!(tmp = netride || (*current_mode->key &&
                  (!strcmp(current_mode->key, param) ||
                  (!wipeout && strcmp(current_mode->key, param) < 0)))) ||
                  wipeout)
              {
                bmodebuf[mblen++] = 'k';
                strcat(bparambuf, " ");
                strcat(bparambuf, param);
                ircd_strncpy(current_mode->key, param, KEYLEN);
              }
              if (!tmp && !wipeout)
              {
                modebuf[mblen2++] = 'k';
                parabuf[pblen2++] = ' ';
                strcpy(parabuf + pblen2, param);
                pblen2 += strlen(param);
                cnt++;
              }
              break;
            }
            case 'l':
            {
              int tmp;
              unsigned int param = atoi(parv[++n]);
              prev_mode &= ~MODE_LIMIT;
              if (!(tmp = netride || (current_mode->limit &&
                  (current_mode->limit == param ||
                  (!wipeout && current_mode->limit < param)))) || wipeout)
              {
                bmodebuf[mblen++] = 'l';
                sprintf_irc(bparambuf + strlen(bparambuf), " %d", param);
                current_mode->limit = param;
              }
              if (!tmp)
              {
                modebuf[mblen2++] = 'l';
                pblen2 = sprintf_irc(parabuf + pblen2, " %d", param) - parabuf;
                cnt++;
              }
              break;
            }
            case 'm':
            {
              int tmp;
              prev_mode &= ~MODE_MODERATED;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_MODERATED)) || wipeout)
              {
                bmodebuf[mblen++] = 'm';
                current_mode->mode |= MODE_MODERATED;
              }
              if (!tmp)
                modebuf[mblen2++] = 'm';
              break;
            }
            case 'n':
            {
              int tmp;
              prev_mode &= ~MODE_NOPRIVMSGS;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_NOPRIVMSGS)) || wipeout)
              {
                bmodebuf[mblen++] = 'n';
                current_mode->mode |= MODE_NOPRIVMSGS;
              }
              if (!tmp)
                modebuf[mblen2++] = 'n';
              break;
            }
            case 'p':
            {
              int tmp;

              /* Special case: */
              if (!netride && !wipeout && (current_mode->mode & MODE_SECRET))
                break;

              prev_mode &= ~MODE_PRIVATE;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_PRIVATE)) || wipeout)
              {
                bmodebuf[mblen++] = 'p';
                current_mode->mode |= MODE_PRIVATE;
              }
              if (!tmp)
                modebuf[mblen2++] = 'p';
              break;
            }
            case 's':
            {
              int tmp;
              prev_mode &= ~MODE_SECRET;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_SECRET)) || wipeout)
              {
                bmodebuf[mblen++] = 's';
                current_mode->mode |= MODE_SECRET;
              }
              if (!tmp)
                modebuf[mblen2++] = 's';

              /* Special case: */
              if (!netride && !wipeout && (current_mode->mode & MODE_PRIVATE))
              {
                int i;
                for (i = mblen2 - 1; i >= 0; --i)
                  modebuf[i + 2] = modebuf[i];
                modebuf[0] = '-';
                modebuf[1] = 'p';
                mblen2 += 2;
                current_mode->mode &= ~MODE_PRIVATE;
              }

              break;
            }
            case 't':
            {
              int tmp;
              prev_mode &= ~MODE_TOPICLIMIT;
              if (!(tmp = netride ||
                  (current_mode->mode & MODE_TOPICLIMIT)) || wipeout)
              {
                bmodebuf[mblen++] = 't';
                current_mode->mode |= MODE_TOPICLIMIT;
              }
              if (!tmp)
                modebuf[mblen2++] = 't';
              break;
            }
          }
        }                       /* <-- while over all modes */

        bmodebuf[mblen] = '\0';
        sendbuf[sblen] = '\0'; /* XXX DEAD */
        if (mblen)              /* Anything to send at all ? */
        {
          send_it = 1;
          strcpy(sendbuf + sblen, " +"); /* XXX DEAD */
          sblen += 2;
          strcpy(sendbuf + sblen, bmodebuf); /* XXX DEAD */
          sblen += mblen;
          strcpy(sendbuf + sblen, bparambuf); /* XXX DEAD */
          sblen += strlen(bparambuf);
        }
        break;                  /* Done mode part */
      }
      case '%':         /* bans */
      {
        char *pv, *p = 0, *ban;
        int first = 1;
        if (netride)
          break;                /* Ignore bans */
        /* Run over all bans */
        for (pv = parv[n] + 1; (ban = ircd_strtok(&p, pv, " ")); pv = 0)
        {
          int ret;
          /*
           * The following part should do the following:
           * - If the new (un)ban is not a _change_ it is ignored.
           * - Else, add it to sendbuf for later use.
           * - If sendbuf is full, send it, and prepare a new
           *   message in sendbuf.
           */
          ret = add_banid(sptr, chptr, ban, 1, add_banid_not_called);
          if (ret == 0)
          {
            add_banid_not_called = 0;
            /* Mark this new ban so we can send it to the clients later */
            chptr->banlist->flags |= CHFL_BURST_BAN;
          }
          if (ret != -1)
            /* A new ban was added or an existing one needs to be passed on.
             * Also add it to sendbuf: */
            add_token_to_sendbuf(ban, &sblen, &first, &send_it, '%', 0); /* XXX DEAD */
        }
        break;                  /* Done bans part */
      }
      default:                  /* nicks */
      {
        char *pv, *p = 0, *nick, *ptr;
        int first = 1;
        /* Default mode: */
        int default_mode = CHFL_DEOPPED;
        /* Run over all nicks */
        for (pv = parv[n]; (nick = ircd_strtok(&p, pv, ",")); pv = 0)
        {
          struct Client *acptr;
          if ((ptr = strchr(nick, ':')))        /* New default mode ? */
          {
            *ptr = '\0';        /* Fix 'nick' */
            acptr = findNUser(nick);
            if (!netride)
            {
              /* Calculate new mode change: */
              default_mode = CHFL_DEOPPED;
              while (*(++ptr))
                if (*ptr == 'o')
                {
                  default_mode |= CHFL_CHANOP;
                  default_mode &= ~CHFL_DEOPPED;
                }
                else if (*ptr == 'v')
                  default_mode |= CHFL_VOICE;
                else
                  break;
            }
          }
          else
            acptr = findNUser(nick);
          /*
           * Note that at this point we already received a 'NICK' for any
           * <nick> numeric that is joining (and possibly opped) here.
           * Therefore we consider the following situations:
           * - The <nick> numeric exists and is from the direction of cptr: ok
           * - The <nick> numeric does not exist:
           *   Apparently this previous <nick> numeric was killed (upstream)
           *   or it collided with an existing <nick> name.
           * - The <nick> numeric exists but is from another direction:
           *   Apparently this previous <nick> numeric was killed,
           *   and due to a reroute it signed on via another link (probably
           *   a nick [numeric] collision).
           * Note that it can't be a QUIT or SQUIT, because a QUIT would
           * come from the same direction as the BURST (cptr) while an
           * upstream SQUIT removes the source (server) and we would thus
           * have this BURST ignored already.
           * This means that if we find the nick and it is from the correct
           * direction, it joins. If it doesn't exist or is from another
           * direction, we have to ignore it. If all nicks are ignored, we
           * remove the channel again when it is empty and don't propagate
           * the BURST message.
           */
          if (acptr && acptr->from == cptr)
          {
            /*
             * The following should do the following:
             * - Add it to sendbuf for later use.
             * - If sendbuf is full, send it, and prepare a new
             *   message in sendbuf.
             */
            add_token_to_sendbuf(nick, &sblen, &first, &send_it, 0, /* XXX DEAD */
                default_mode);
            /* Let is take effect: (Note that in the case of a netride
             * 'default_mode' is always CHFL_DEOPPED here). */
            add_user_to_channel(chptr, acptr, default_mode | CHFL_BURST_JOINED);
          }
        }                       /* <-- Next nick */
        if (!chptr->members)    /* All nicks collided and channel is empty ? */
        {
          sub1_from_channel(chptr);
          return 0;             /* Forget about the (rest of the) message... */
        }
        break;                  /* Done nicks part */
      }
    }                           /* <-- Next parameter if any */
  if (!chptr->members)          /* This message only contained bans (then the previous
                                   message only contained collided nicks, see above) */
  {
    sub1_from_channel(chptr);
    if (!add_banid_not_called)
      while (next_removed_overlapped_ban());
    return 0;                   /* Forget about the (rest of the) message... */
  }

  /* The last (possibly only) message is always send here */
  if (send_it)                  /* Anything (left) to send ? */
  {
    struct DLink *lp;
    struct Membership* member;

    /* send 'sendbuf' to all downlinks */
    for (lp = me.serv->down; lp; lp = lp->next)
    {
      if (lp->value.cptr == cptr)
        continue;
      if (Protocol(lp->value.cptr) > 9)
        sendbufto_one(lp->value.cptr); /* XXX DEAD */
    }

    /*
     * Now we finally can screw sendbuf again...
     * Send all changes to the local clients:
     *
     * First send all joins and op them, because 2.9 servers
     * would protest with a HACK if we first de-opped people.
     * However, we don't send the +b bans yes, because we
     * DO first want to -b the old bans (otherwise it's confusing).
     */

    /* Send all joins: */
    for (member = chptr->members; member; member = member->next_member)
      if (IsBurstJoined(member))
      {
        sendto_channel_butserv(chptr, member->user, ":%s JOIN :%s", /* XXX DEAD */
                               member->user->name, chptr->chname);
      }

    if (!netride)
    {
      /* Send all +o and +v modes: */
      for (member = chptr->members; member; member = member->next_member)
      {
        if (IsBurstJoined(member))
        {
          int mode = CHFL_CHANOP;
          for (;;)
          {
            if ((member->status & mode))
            {
              modebuf[mblen2++] = (mode == CHFL_CHANOP) ? 'o' : 'v';
              parabuf[pblen2++] = ' ';
              strcpy(parabuf + pblen2, member->user->name);
              pblen2 += strlen(member->user->name);
              if (6 == ++cnt)
              {
                modebuf[mblen2] = 0;
                sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DEAD */
                    parv[0], chptr->chname, modebuf, parabuf);
                *parabuf = 0;
                pblen2 = 0;
                mblen2 = 1;
                cnt = 0;
              }
            }
            if (mode == CHFL_CHANOP)
              mode = CHFL_VOICE;
            else
              break;
          }
        }
      }
      /* Flush MODEs: */
      if (cnt > 0 || mblen2 > 1)
      {
        modebuf[mblen2] = 0;
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DEAD */
            parv[0], chptr->chname, modebuf, parabuf);
      }
    }
  }

  if (wipeout)
  {
    struct Membership* member;
    struct SLink**     ban;
    int                mode;
    char               m;
    int                count = -1;

    /* Now cancel all previous simple modes */
    if ((prev_mode & MODE_SECRET))
      cancel_mode(sptr, chptr, 's', 0, &count); /* XXX DEAD */
    if ((prev_mode & MODE_PRIVATE))
      cancel_mode(sptr, chptr, 'p', 0, &count); /* XXX DEAD */
    if ((prev_mode & MODE_MODERATED))
      cancel_mode(sptr, chptr, 'm', 0, &count); /* XXX DEAD */
    if ((prev_mode & MODE_TOPICLIMIT))
      cancel_mode(sptr, chptr, 't', 0, &count); /* XXX DEAD */
    if ((prev_mode & MODE_INVITEONLY))
      cancel_mode(sptr, chptr, 'i', 0, &count); /* XXX DEAD */
    if ((prev_mode & MODE_NOPRIVMSGS))
      cancel_mode(sptr, chptr, 'n', 0, &count); /* XXX DEAD */
    if ((prev_mode & MODE_LIMIT))
    {
      current_mode->limit = 0;
      cancel_mode(sptr, chptr, 'l', 0, &count); /* XXX DEAD */
    }
    if ((prev_mode & MODE_KEY))
    {
      *current_mode->key = 0;
      cancel_mode(sptr, chptr, 'k', prev_key, &count); /* XXX DEAD */
    }
    current_mode->mode &= ~prev_mode;

    /* And deop and devoice all net.riders on my side */
    mode = CHFL_CHANOP;
    m = 'o';
    for (;;)
    {
      struct Membership* member_next = 0;

      for (member = chptr->members; member; member = member_next)
      {
        member_next = member->next_member;
        if (IsBurstJoined(member))
          continue;             /* This is not a net.rider from
                                   this side of the net.junction */
#if defined(NO_INVITE_NETRIDE)
        /*
         * Kick net riding users from invite only channels.
         *  - Isomer 25-11-1999
         */
        if (chptr->mode.mode & MODE_INVITEONLY) {
          /* kick is magical - lotsa zombies and other undead.
           * I'm hoping this is the right idea, comments anyone?
           * Set everyone to a zombie, remove ops, and then send kicks
           * everywhere...
           */
           if (IsZombie(member)) { /* don't kick ppl twice */
                member->status = member->status & ~mode;
                continue;
           }
           member->status = (member->status & ~mode) | CHFL_ZOMBIE;

           sendto_highprot_butone(0, 10, "%s " TOK_KICK "%s %s%s :Net Rider", /* XXX DEAD */
            NumServ(&me), chptr->chname, NumNick(member->user));
           sendto_channel_butserv(chptr, sptr, /* XXX DEAD */
            ":%s KICK %s %s :Net Rider", me.name, chptr->chname,
            member->user->name);

           if (MyUser(member->user)) {
             sendto_lowprot_butone(0, 9, ":%s PART %s", /* XXX DEAD */
               member->user->name, chptr->chname, member->user->name);
             sendto_highprot_butone(0, 10, "%s%s PART %s", /* XXX DEAD */
               NumNick(member->user), chptr->chname);
             remove_user_from_channel(member->user, chptr);
           }
           else {
             member->status = (member->status & ~mode) | CHFL_ZOMBIE;
           }
           continue;
        }
#endif /* defined(NO_INVITE_NETRIDE) */
        if ((member->status & mode))
        {
          member->status &= ~mode;
          if (mode == CHFL_CHANOP)
            SetDeopped(member);
          cancel_mode(sptr, chptr, m, member->user->name, &count); /* XXX DEAD */
        }
      }
      if (mode == CHFL_VOICE)
        break;
      mode = CHFL_VOICE;
      m = 'v';
    }

    /* And finally wipeout all bans that are left */
    for (ban = &chptr->banlist; *ban; ) {
      struct SLink* tmp = *ban;
      if ((tmp->flags & CHFL_BURST_BAN_WIPEOUT)) {
        struct Membership* member_z;

        *ban = tmp->next;
        cancel_mode(sptr, chptr, 'b', tmp->value.ban.banstr, &count); /* XXX DEAD */

        /* Copied from del_banid(): */
        MyFree(tmp->value.ban.banstr);
        MyFree(tmp->value.ban.who);
        free_link(tmp);

        /* Erase ban-valid-bit, for channel members that are banned */
        for (member_z = chptr->members; member_z; member_z = member_z->next_member)
          if ((member_z->status & CHFL_BANVALIDMASK) == CHFL_BANVALIDMASK)
            ClearBanValid(member_z);
      }
      else
        ban = &tmp->next;
    }
    /* Also wipeout overlapped bans */
    if (!add_banid_not_called)
    {
      struct SLink *ban;
      while ((ban = next_removed_overlapped_ban()))
        cancel_mode(sptr, chptr, 'b', ban->value.ban.banstr, &count); /* XXX DEAD */
    }
    cancel_mode(sptr, chptr, 0, 0, &count);  /* flush */ /* XXX DEAD */
  }

  if (send_it && !netride)
  {
    struct SLink *bl;
    int deban;

    if (add_banid_not_called || !(bl = next_removed_overlapped_ban()))
    {
      deban = 0;
      bl = chptr->banlist;
      *modebuf = '+';
    }
    else
    {
      deban = 1;
      *modebuf = '-';
    }

    mblen2 = 1;
    pblen2 = 0;
    cnt = 0;
    for (;;)
    {
      size_t nblen = 0;
      if (bl)
        nblen = strlen(bl->value.ban.banstr);
      if (cnt == 6 || (!bl && cnt) || pblen2 + nblen + 12 > MODEBUFLEN) /* The last check is to make sure
                                                                           that the receiving 2.9 will
                                                                           still process this */
      {
        /* Time to send buffer */
        modebuf[mblen2] = 0;
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DEAD */
            parv[0], chptr->chname, modebuf, parabuf);
        *modebuf = deban ? '-' : '+';
        mblen2 = 1;
        pblen2 = 0;
        cnt = 0;
      }
      if (!bl)                  /* Done ? */
        break;
      if (deban || (bl->flags & CHFL_BURST_BAN))
      {
        /* Add ban to buffers and remove it */
        modebuf[mblen2++] = 'b';
        parabuf[pblen2++] = ' ';
        strcpy(parabuf + pblen2, bl->value.ban.banstr);
        pblen2 += nblen;
        cnt++;
        bl->flags &= ~CHFL_BURST_BAN;
      }
      if (deban)
      {
        if (!(bl = next_removed_overlapped_ban()))
        {
          deban = 0;
          modebuf[mblen2++] = '+';
          bl = chptr->banlist;
        }
      }
      else
        bl = bl->next;
    }
    /* Flush MODE [-b]+b ...: */
    if (cnt > 0 || mblen2 > 1)
    {
      modebuf[mblen2] = 0;
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s", /* XXX DEAD */
          parv[0], chptr->chname, modebuf, parabuf);
    }
  }

  return 0;
}
#endif /* 0 */

