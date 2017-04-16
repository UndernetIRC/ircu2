/*
 * IRC - Internet Relay Chat, ircd/gline.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Implementation of Gline manipulation functions.
 * @version $Id$
 */
#include "config.h"

#include "gline.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK_APPROVED	   0	/**< Mask is acceptable */
#define CHECK_OVERRIDABLE  1	/**< Mask is acceptable, but not by default */
#define CHECK_REJECTED	   2	/**< Mask is totally unacceptable */

#define MASK_WILD_0	0x01	/**< Wildcards in the last position */
#define MASK_WILD_1	0x02	/**< Wildcards in the next-to-last position */

#define MASK_WILD_MASK	0x03	/**< Mask out the positional wildcards */

#define MASK_WILDS	0x10	/**< Mask contains wildcards */
#define MASK_IP		0x20	/**< Mask is an IP address */
#define MASK_HALT	0x40	/**< Finished processing mask */
#define ONE_MONTH	(30 * 24 * 3600) /**< Number of seconds in 30 days */

/** List of user G-lines. */
struct Gline* GlobalGlineList  = 0;
/** List of BadChan G-lines. */
struct Gline* BadChanGlineList = 0;

/** Iterate through \a list of G-lines.  Use this like a for loop,
 * i.e., follow it with braces and use whatever you passed as \a gl
 * as a single G-line to be acted upon.
 *
 * @param[in] list List of G-lines to iterate over.
 * @param[in] gl Name of a struct Gline pointer variable that will be made to point to the G-lines in sequence.
 * @param[in] next Name of a scratch struct Gline pointer variable.
 */
/* There is some subtlety here with the boolean operators:
 * (x || 1) is used to continue in a logical-and series even when !x.
 * (x && 0) is used to continue in a logical-or series even when x.
 */
#define gliter(list, gl, next)				\
  /* Iterate through the G-lines in the list */		\
  for ((gl) = (list); (gl); (gl) = (next))		\
    /* Figure out the next pointer in list... */	\
    if ((((next) = (gl)->gl_next) || 1) &&		\
	/* Then see if it's expired */			\
	(((gl)->gl_lifetime <= TStime()) ||             \
	 (((gl)->gl_expire < TStime() - ONE_MONTH) &&   \
	  ((gl)->gl_lastmod < TStime() - ONE_MONTH))))  \
      /* Record has expired, so free the G-line */	\
      gline_free((gl));					\
    /* See if we need to expire the G-line */		\
    else if ((((gl)->gl_expire > TStime()) ||		\
	      (((gl)->gl_flags &= ~GLINE_ACTIVE) && 0) ||	\
	      ((gl)->gl_state = GLOCAL_GLOBAL)) && 0)	\
      ; /* empty statement */				\
    else

/** Find canonical user and host for a string.
 * If \a userhost starts with '$', assign \a userhost to *user_p and NULL to *host_p.
 * Otherwise, if \a userhost contains '@', assign the earlier part of it to *user_p and the rest to *host_p.
 * Otherwise, assign \a def_user to *user_p and \a userhost to *host_p.
 *
 * @param[in] userhost Input string from user.
 * @param[out] user_p Gets pointer to user (or channel/realname) part of hostmask.
 * @param[out] host_p Gets point to host part of hostmask (may be assigned NULL).
 * @param[in] def_user Default value for user part.
 */
static void
canon_userhost(char *userhost, char **user_p, char **host_p, char *def_user)
{
  char *tmp;

  if (*userhost == '$') {
    *user_p = userhost;
    *host_p = NULL;
    return;
  }

  if (!(tmp = strchr(userhost, '@'))) {
    *user_p = def_user;
    *host_p = userhost;
  } else {
    *user_p = userhost;
    *(tmp++) = '\0';
    *host_p = tmp;
  }
}

/** Create a Gline structure.
 * @param[in] user User part of mask.
 * @param[in] host Host part of mask (NULL if not applicable).
 * @param[in] reason Reason for G-line.
 * @param[in] expire Expiration timestamp.
 * @param[in] lastmod Last modification timestamp.
 * @param[in] flags Bitwise combination of GLINE_* bits.
 * @return Newly allocated G-line.
 */
static struct Gline *
make_gline(char *user, char *host, char *reason, time_t expire, time_t lastmod,
	   time_t lifetime, unsigned int flags)
{
  struct Gline *gline;

  assert(0 != expire);

  gline = (struct Gline *)MyMalloc(sizeof(struct Gline)); /* alloc memory */
  assert(0 != gline);

  DupString(gline->gl_reason, reason); /* initialize gline... */
  gline->gl_expire = expire;
  gline->gl_lifetime = lifetime;
  gline->gl_lastmod = lastmod;
  gline->gl_flags = flags & GLINE_MASK;
  gline->gl_state = GLOCAL_GLOBAL; /* not locally modified */

  if (flags & GLINE_BADCHAN) { /* set a BADCHAN gline */
    DupString(gline->gl_user, user); /* first, remember channel */
    gline->gl_host = NULL;

    gline->gl_next = BadChanGlineList; /* then link it into list */
    gline->gl_prev_p = &BadChanGlineList;
    if (BadChanGlineList)
      BadChanGlineList->gl_prev_p = &gline->gl_next;
    BadChanGlineList = gline;
  } else {
    DupString(gline->gl_user, user); /* remember them... */
    if (*user != '$')
      DupString(gline->gl_host, host);
    else
      gline->gl_host = NULL;

    if (*user != '$' && ipmask_parse(host, &gline->gl_addr, &gline->gl_bits))
      gline->gl_flags |= GLINE_IPMASK;

    gline->gl_next = GlobalGlineList; /* then link it into list */
    gline->gl_prev_p = &GlobalGlineList;
    if (GlobalGlineList)
      GlobalGlineList->gl_prev_p = &gline->gl_next;
    GlobalGlineList = gline;
  }

  return gline;
}

/** Check local clients against a new G-line.
 * If the G-line is inactive or a badchan, return immediately.
 * Otherwise, if any users match it, disconnect them.
 * @param[in] cptr Peer connect that sent the G-line.
 * @param[in] sptr Client that originated the G-line.
 * @param[in] gline New G-line to check.
 * @return Zero, unless \a sptr G-lined himself, in which case CPTR_KILLED.
 */
static int
do_gline(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  struct Client *acptr;
  int fd, retval = 0, tval;

  if (feature_bool(FEAT_DISABLE_GLINES))
    return 0; /* G-lines are disabled */

  if (GlineIsBadChan(gline)) /* no action taken on badchan glines */
    return 0;
  if (!GlineIsActive(gline)) /* no action taken on inactive glines */
    return 0;

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!cli_user(acptr))
	continue;

      if (GlineIsRealName(gline)) { /* Realname Gline */
	Debug((DEBUG_DEBUG,"Realname Gline: %s %s",(cli_info(acptr)),
					gline->gl_user+2));
        if (match(gline->gl_user+2, cli_info(acptr)) != 0)
            continue;
        Debug((DEBUG_DEBUG,"Matched!"));
      } else { /* Host/IP gline */
        if (match(gline->gl_user, (cli_user(acptr))->username) != 0)
          continue;

        if (GlineIsIpMask(gline)) {
          if (!ipmask_check(&cli_ip(acptr), &gline->gl_addr, gline->gl_bits))
            continue;
        }
        else {
          if (match(gline->gl_host, cli_sockhost(acptr)) != 0)
            continue;
        }
      }

      /* ok, here's one that got G-lined */
      send_reply(acptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s",
      	   gline->gl_reason);

      /* let the ops know about it */
      sendto_opmask_butone(0, SNO_GLINE, "G-line active for %s",
                           get_client_name(acptr, SHOW_IP));

      /* and get rid of him */
      if ((tval = exit_client_msg(cptr, acptr, &me, "G-lined (%s)",
          gline->gl_reason)))
        retval = tval; /* retain killed status */
    }
  }
  return retval;
}

/**
 * Implements the mask checking applied to local G-lines.
 * Basically, host masks must have a minimum of two non-wild domain
 * fields, and IP masks must have a minimum of 16 bits.  If the mask
 * has even one wild-card, OVERRIDABLE is returned, assuming the other
 * check doesn't fail.
 * @param[in] mask G-line mask to check.
 * @return One of CHECK_REJECTED, CHECK_OVERRIDABLE, or CHECK_APPROVED.
 */
static int
gline_checkmask(char *mask)
{
  unsigned int flags = MASK_IP;
  unsigned int dots = 0;
  unsigned int ipmask = 0;

  for (; *mask; mask++) { /* go through given mask */
    if (*mask == '.') { /* it's a separator; advance positional wilds */
      flags = (flags & ~MASK_WILD_MASK) | ((flags << 1) & MASK_WILD_MASK);
      dots++;

      if ((flags & (MASK_IP | MASK_WILDS)) == MASK_IP)
	ipmask += 8; /* It's an IP with no wilds, count bits */
    } else if (*mask == '*' || *mask == '?')
      flags |= MASK_WILD_0 | MASK_WILDS; /* found a wildcard */
    else if (*mask == '/') { /* n.n.n.n/n notation; parse bit specifier */
      ++mask;
      ipmask = strtoul(mask, &mask, 10);

      /* sanity-check to date */
      if (*mask || (flags & (MASK_WILDS | MASK_IP)) != MASK_IP)
	return CHECK_REJECTED;
      if (!dots) {
        if (ipmask > 128)
          return CHECK_REJECTED;
        if (ipmask < 128)
          flags |= MASK_WILDS;
      } else {
        if (dots != 3 || ipmask > 32)
          return CHECK_REJECTED;
        if (ipmask < 32)
	  flags |= MASK_WILDS;
      }

      flags |= MASK_HALT; /* Halt the ipmask calculation */
      break; /* get out of the loop */
    } else if (!IsIP6Char(*mask)) {
      flags &= ~MASK_IP; /* not an IP anymore! */
      ipmask = 0;
    }
  }

  /* Sanity-check quads */
  if (dots > 3 || (!(flags & MASK_WILDS) && dots < 3)) {
    flags &= ~MASK_IP;
    ipmask = 0;
  }

  /* update bit count if necessary */
  if ((flags & (MASK_IP | MASK_WILDS | MASK_HALT)) == MASK_IP)
    ipmask += 8;

  /* Check to see that it's not too wide of a mask */
  if (flags & MASK_WILDS &&
      ((!(flags & MASK_IP) && (dots < 2 || flags & MASK_WILD_MASK)) ||
       (flags & MASK_IP && ipmask < 16)))
    return CHECK_REJECTED; /* to wide, reject */

  /* Ok, it's approved; require override if it has wildcards, though */
  return flags & MASK_WILDS ? CHECK_OVERRIDABLE : CHECK_APPROVED;
}

/** Forward a G-line to other servers.
 * @param[in] cptr Client that sent us the G-line.
 * @param[in] sptr Client that originated the G-line.
 * @param[in] gline G-line to forward.
 * @return Zero.
 */
static int
gline_propagate(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  if (GlineIsLocal(gline))
    return 0;

  assert(gline->gl_lastmod);

  sendcmdto_serv_butone(sptr, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
			GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
			gline->gl_host ? "@" : "",
			gline->gl_host ? gline->gl_host : "",
			gline->gl_expire - TStime(), gline->gl_lastmod,
			gline->gl_lifetime, gline->gl_reason);

  return 0;
}

/** Count number of users who match \a mask.
 * @param[in] mask user\@host or user\@ip mask to check.
 * @param[in] flags Bitmask possibly containing the value GLINE_LOCAL, to limit searches to this server.
 * @return Count of matching users.
 */
static int
count_users(char *mask, int flags)
{
  struct irc_in_addr ipmask;
  struct Client *acptr;
  int count = 0;
  int ipmask_valid;
  char namebuf[USERLEN + HOSTLEN + 2];
  char ipbuf[USERLEN + SOCKIPLEN + 2];
  unsigned char ipmask_len;

  ipmask_valid = ipmask_parse(mask, &ipmask, &ipmask_len);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if ((flags & GLINE_LOCAL) && !MyConnect(acptr))
      continue;

    ircd_snprintf(0, namebuf, sizeof(namebuf), "%s@%s",
		  cli_user(acptr)->username, cli_user(acptr)->realhost);
    ircd_snprintf(0, ipbuf, sizeof(ipbuf), "%s@%s", cli_user(acptr)->username,
		  ircd_ntoa(&cli_ip(acptr)));

    if (!match(mask, namebuf)
        || !match(mask, ipbuf)
        || (ipmask_valid && ipmask_check(&cli_ip(acptr), &ipmask, ipmask_len)))
      count++;
  }

  return count;
}

/** Count number of users with a realname matching \a mask.
 * @param[in] mask Wildcard mask to match against realnames.
 * @return Count of matching users.
 */
static int
count_realnames(const char *mask)
{
  struct Client *acptr;
  int minlen;
  int count;
  char cmask[BUFSIZE];

  count = 0;
  matchcomp(cmask, &minlen, NULL, mask);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if (strlen(cli_info(acptr)) < minlen)
      continue;
    if (!matchexec(cli_info(acptr), cmask, minlen))
      count++;
  }
  return count;
}

/** Create a new G-line and add it to global lists.
 * \a userhost may be in one of four forms:
 * \li A channel name, to add a BadChan.
 * \li A string starting with $R and followed by a mask to match against their realname.
 * \li A user\@IP mask (user\@ part optional) to create an IP-based ban.
 * \li A user\@host mask (user\@ part optional) to create a hostname ban.
 *
 * @param[in] cptr Client that sent us the G-line.
 * @param[in] sptr Client that originated the G-line.
 * @param[in] userhost Text mask for the G-line.
 * @param[in] reason Reason for G-line.
 * @param[in] expire Expiration time of G-line.
 * @param[in] lastmod Last modification time of G-line.
 * @param[in] lifetime Lifetime of G-line.
 * @param[in] flags Bitwise combination of GLINE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, time_t lifetime,
	  unsigned int flags)
{
  struct Gline *agline;
  char uhmask[USERLEN + HOSTLEN + 2];
  char *user, *host;
  int tmp;

  assert(0 != userhost);
  assert(0 != reason);
  assert(((flags & (GLINE_GLOBAL | GLINE_LOCAL)) == GLINE_GLOBAL) ||
         ((flags & (GLINE_GLOBAL | GLINE_LOCAL)) == GLINE_LOCAL));

  Debug((DEBUG_DEBUG, "gline_add(\"%s\", \"%s\", \"%s\", \"%s\", %Tu, %Tu "
	 "%Tu, 0x%04x)", cli_name(cptr), cli_name(sptr), userhost, reason,
	 expire, lastmod, lifetime, flags));

  if (*userhost == '#' || *userhost == '&') {
    if ((flags & GLINE_LOCAL) && !HasPriv(sptr, PRIV_LOCAL_BADCHAN))
      return send_reply(sptr, ERR_NOPRIVILEGES);
    /* Allow maximum channel name length, plus margin for wildcards. */
    if (strlen(userhost+1) >= CHANNELLEN + 6)
      return send_reply(sptr, ERR_LONGMASK);

    flags |= GLINE_BADCHAN;
    user = userhost;
    host = NULL;
  } else if (*userhost == '$') {
    switch (userhost[1]) {
      case 'R':
        /* Allow REALLEN for the real name, plus margin for wildcards. */
        if (strlen(userhost+2) >= REALLEN + 6)
          return send_reply(sptr, ERR_LONGMASK);
        flags |= GLINE_REALNAME;
        break;
      default:
        /* uh, what to do here? */
        /* The answer, my dear Watson, is we throw a protocol_violation()
           -- hikari */
        if (IsServer(cptr))
          return protocol_violation(sptr,"%s has been smoking the sweet leaf and sent me a whacky gline",cli_name(sptr));
        sendto_opmask_butone(NULL, SNO_GLINE, "%s has been smoking the sweet leaf and sent me a whacky gline", cli_name(sptr));
        return 0;
    }
    user = userhost;
    host = NULL;
    if (MyUser(sptr) || (IsUser(sptr) && flags & GLINE_LOCAL)) {
      tmp = count_realnames(userhost + 2);
      if ((tmp >= feature_int(FEAT_GLINEMAXUSERCOUNT))
	  && !(flags & GLINE_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  } else {
    canon_userhost(userhost, &user, &host, "*");
    if (sizeof(uhmask) <
	ircd_snprintf(0, uhmask, sizeof(uhmask), "%s@%s", user, host))
      return send_reply(sptr, ERR_LONGMASK);
    else if (MyUser(sptr) || (IsUser(sptr) && flags & GLINE_LOCAL)) {
      switch (gline_checkmask(host)) {
      case CHECK_OVERRIDABLE: /* oper overrided restriction */
	if (flags & GLINE_OPERFORCE)
	  break;
	/*FALLTHROUGH*/
      case CHECK_REJECTED:
	return send_reply(sptr, ERR_MASKTOOWIDE, uhmask);
	break;
      }

      if ((tmp = count_users(uhmask, flags)) >=
	  feature_int(FEAT_GLINEMAXUSERCOUNT) && !(flags & GLINE_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  }

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than GLINE_MAX_EXPIRE.
   */
  if (!(flags & GLINE_FORCE) &&
      (expire <= TStime() || expire > TStime() + GLINE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  } else if (expire <= TStime()) {
    /* This expired G-line was forced to be added, so mark it inactive. */
    flags &= ~GLINE_ACTIVE;
  }

  if (!lifetime) /* no lifetime set, use expiration time */
    lifetime = expire;

  /* lifetime is already an absolute timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
                       SNO_AUTO, "%s adding %s%s %s for %s%s%s, expiring at "
                       "%Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       (flags & GLINE_ACTIVE) ? "" : "deactivated ",
		       (flags & GLINE_LOCAL) ? "local" : "global",
		       (flags & GLINE_BADCHAN) ? "BADCHAN" : "GLINE", user,
		       (flags & (GLINE_BADCHAN|GLINE_REALNAME)) ? "" : "@",
		       (flags & (GLINE_BADCHAN|GLINE_REALNAME)) ? "" : host,
		       expire, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s %s for %s%s%s, expiring at %Tu: %s", sptr,
	    flags & GLINE_LOCAL ? "local" : "global",
	    flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", user,
	    flags & (GLINE_BADCHAN|GLINE_REALNAME) ? "" : "@",
	    flags & (GLINE_BADCHAN|GLINE_REALNAME) ? "" : host,
	    expire, reason);

  /* make the gline */
  agline = make_gline(user, host, reason, expire, lastmod, lifetime, flags);

  /* since we've disabled overlapped G-line checking, agline should
   * never be NULL...
   */
  assert(agline);

  gline_propagate(cptr, sptr, agline);

  return do_gline(cptr, sptr, agline); /* knock off users if necessary */
}

/** Activate a currently inactive G-line.
 * @param[in] cptr Peer that told us to activate the G-line.
 * @param[in] sptr Client that originally thought it was a good idea.
 * @param[in] gline G-line to activate.
 * @param[in] lastmod New value for last modification timestamp.
 * @param[in] flags 0 if the activation should be propagated, GLINE_LOCAL if not.
 * @return Zero, unless \a sptr had a death wish (in which case CPTR_KILLED).
 */
int
gline_activate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
	       time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != gline);

  saveflags = gline->gl_flags;

  if (flags & GLINE_LOCAL)
    gline->gl_flags &= ~GLINE_LDEACT;
  else {
    gline->gl_flags |= GLINE_ACTIVE;

    if (gline->gl_lastmod) {
      if (gline->gl_lastmod >= lastmod) /* force lastmod to increase */
	gline->gl_lastmod++;
      else
	gline->gl_lastmod = lastmod;
    }
  }

  if ((saveflags & GLINE_ACTMASK) == GLINE_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global %s for %s%s%s, "
                       "expiring at %Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
                       gline->gl_user, gline->gl_host ? "@" : "",
                       gline->gl_host ? gline->gl_host : "",
                       gline->gl_expire, gline->gl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global %s for %s%s%s, expiring at %Tu: %s", sptr,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    gline->gl_host ? "@" : "",
	    gline->gl_host ? gline->gl_host : "",
	    gline->gl_expire, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  return do_gline(cptr, sptr, gline);
}

/** Deactivate a G-line.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the deactivation.
 * @param[in] gline G-line to deactivate.
 * @param[in] lastmod New value for G-line last modification timestamp.
 * @param[in] flags GLINE_LOCAL to only deactivate locally, 0 to propagate.
 * @return Zero.
 */
int
gline_deactivate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
		 time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;
  char *msg;

  assert(0 != gline);

  saveflags = gline->gl_flags;

  if (GlineIsLocal(gline))
    msg = "removing local";
  else if (!gline->gl_lastmod && !(flags & GLINE_LOCAL)) {
    msg = "removing global";
    gline->gl_flags &= ~GLINE_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";

    if (flags & GLINE_LOCAL)
      gline->gl_flags |= GLINE_LDEACT;
    else {
      gline->gl_flags &= ~GLINE_ACTIVE;

      if (gline->gl_lastmod) {
	if (gline->gl_lastmod >= lastmod)
	  gline->gl_lastmod++;
	else
	  gline->gl_lastmod = lastmod;
      }
    }

    if ((saveflags & GLINE_ACTMASK) != GLINE_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s %s %s for %s%s%s, expiring at %Tu: "
		       "%s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
		       msg, GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       gline->gl_user, gline->gl_host ? "@" : "",
                       gline->gl_host ? gline->gl_host : "",
		       gline->gl_expire, gline->gl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s %s for %s%s%s, expiring at %Tu: %s", sptr, msg,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    gline->gl_host ? "@" : "",
	    gline->gl_host ? gline->gl_host : "",
	    gline->gl_expire, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  /* if it's a local gline or a Uworld gline (and not locally deactivated).. */
  if (GlineIsLocal(gline) || (!gline->gl_lastmod && !(flags & GLINE_LOCAL)))
    gline_free(gline); /* get rid of it */

  return 0;
}

/** Modify a global G-line.
 * @param[in] cptr Client that sent us the G-line modification.
 * @param[in] sptr Client that originated the G-line modification.
 * @param[in] gline G-line being modified.
 * @param[in] action Resultant status of the G-line.
 * @param[in] reason Reason for G-line.
 * @param[in] expire Expiration time of G-line.
 * @param[in] lastmod Last modification time of G-line.
 * @param[in] lifetime Lifetime of G-line.
 * @param[in] flags Bitwise combination of GLINE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
gline_modify(struct Client *cptr, struct Client *sptr, struct Gline *gline,
	     enum GlineAction action, char *reason, time_t expire,
	     time_t lastmod, time_t lifetime, unsigned int flags)
{
  char buf[BUFSIZE], *op = "";
  int pos = 0, non_auto = 0;

  assert(gline);
  assert(!GlineIsLocal(gline));

  Debug((DEBUG_DEBUG,  "gline_modify(\"%s\", \"%s\", \"%s%s%s\", %s, \"%s\", "
	 "%Tu, %Tu, %Tu, 0x%04x)", cli_name(cptr), cli_name(sptr),
	 gline->gl_user, gline->gl_host ? "@" : "",
	 gline->gl_host ? gline->gl_host : "",
	 action == GLINE_ACTIVATE ? "GLINE_ACTIVATE" :
	 (action == GLINE_DEACTIVATE ? "GLINE_DEACTIVATE" :
	  (action == GLINE_LOCAL_ACTIVATE ? "GLINE_LOCAL_ACTIVATE" :
	   (action == GLINE_LOCAL_DEACTIVATE ? "GLINE_LOCAL_DEACTIVATE" :
	    (action == GLINE_MODIFY ? "GLINE_MODIFY" : "<UNKNOWN>")))),
	 reason, expire, lastmod, lifetime, flags));

  /* First, let's check lastmod... */
  if (action != GLINE_LOCAL_ACTIVATE && action != GLINE_LOCAL_DEACTIVATE) {
    if (GlineLastMod(gline) > lastmod) { /* we have a more recent version */
      if (IsBurstOrBurstAck(cptr))
	return 0; /* middle of a burst, it'll resync on its own */
      return gline_resend(cptr, gline); /* resync the server */
    } else if (GlineLastMod(gline) == lastmod)
      return 0; /* we have that version of the G-line... */
  }

  /* All right, we know that there's a change of some sort.  What is it? */
  /* first, check out the expiration time... */
  if ((flags & GLINE_EXPIRE) && expire) {
    if (!(flags & GLINE_FORCE) &&
	(expire <= TStime() || expire > TStime() + GLINE_MAX_EXPIRE)) {
      if (!IsServer(sptr) && MyConnect(sptr)) /* bad expiration time */
	send_reply(sptr, ERR_BADEXPIRE, expire);
      return 0;
    }
  } else
    flags &= ~GLINE_EXPIRE;

  /* Now check to see if there's any change... */
  if ((flags & GLINE_EXPIRE) && expire == gline->gl_expire) {
    flags &= ~GLINE_EXPIRE; /* no change to expiration time... */
    expire = 0;
  }

  /* Next, check out lifetime--this one's a bit trickier... */
  if (!(flags & GLINE_LIFETIME) || !lifetime)
    lifetime = gline->gl_lifetime; /* use G-line lifetime */

  lifetime = IRCD_MAX(lifetime, expire); /* set lifetime to the max */

  /* OK, let's see which is greater... */
  if (lifetime > gline->gl_lifetime)
    flags |= GLINE_LIFETIME; /* have to update lifetime */
  else {
    flags &= ~GLINE_LIFETIME; /* no change to lifetime */
    lifetime = 0;
  }

  /* Finally, let's see if the reason needs to be updated */
  if ((flags & GLINE_REASON) && reason &&
      !ircd_strcmp(gline->gl_reason, reason))
    flags &= ~GLINE_REASON; /* no changes to the reason */

  /* OK, now let's take a look at the action... */
  if ((action == GLINE_ACTIVATE && (gline->gl_flags & GLINE_ACTIVE)) ||
      (action == GLINE_DEACTIVATE && !(gline->gl_flags & GLINE_ACTIVE)) ||
      (action == GLINE_LOCAL_ACTIVATE &&
       (gline->gl_state == GLOCAL_ACTIVATED)) ||
      (action == GLINE_LOCAL_DEACTIVATE &&
       (gline->gl_state == GLOCAL_DEACTIVATED)) ||
      /* can't activate an expired G-line */
      IRCD_MAX(gline->gl_expire, expire) <= TStime())
    action = GLINE_MODIFY; /* no activity state modifications */

  Debug((DEBUG_DEBUG,  "About to perform changes; flags 0x%04x, action %s",
	 flags, action == GLINE_ACTIVATE ? "GLINE_ACTIVATE" :
	 (action == GLINE_DEACTIVATE ? "GLINE_DEACTIVATE" :
	  (action == GLINE_LOCAL_ACTIVATE ? "GLINE_LOCAL_ACTIVATE" :
	   (action == GLINE_LOCAL_DEACTIVATE ? "GLINE_LOCAL_DEACTIVATE" :
	    (action == GLINE_MODIFY ? "GLINE_MODIFY" : "<UNKNOWN>"))))));

  /* If there are no changes to perform, do no changes */
  if (!(flags & GLINE_UPDATE) && action == GLINE_MODIFY)
    return 0;

  /* Now we know what needs to be changed, so let's process the changes... */

  /* Start by updating lastmod, if indicated... */
  if (action != GLINE_LOCAL_ACTIVATE && action != GLINE_LOCAL_DEACTIVATE)
    gline->gl_lastmod = lastmod;

  /* Then move on to activity status changes... */
  switch (action) {
  case GLINE_ACTIVATE: /* Globally activating G-line */
    gline->gl_flags |= GLINE_ACTIVE; /* make it active... */
    gline->gl_state = GLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally activating G-line");
    op = "+"; /* operation for G-line propagation */
    break;

  case GLINE_DEACTIVATE: /* Globally deactivating G-line */
    gline->gl_flags &= ~GLINE_ACTIVE; /* make it inactive... */
    gline->gl_state = GLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally deactivating G-line");
    op = "-"; /* operation for G-line propagation */
    break;

  case GLINE_LOCAL_ACTIVATE: /* Locally activating G-line */
    gline->gl_state = GLOCAL_ACTIVATED; /* make it locally active */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally activating G-line");
    break;

  case GLINE_LOCAL_DEACTIVATE: /* Locally deactivating G-line */
    gline->gl_state = GLOCAL_DEACTIVATED; /* make it locally inactive */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally deactivating G-line");
    break;

  case GLINE_MODIFY: /* no change to activity status */
    break;
  }

  /* Handle expiration changes... */
  if (flags & GLINE_EXPIRE) {
    gline->gl_expire = expire; /* save new expiration time */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing expiration time to %Tu",
			   pos ? ";" : "",
			   pos && !(flags & (GLINE_LIFETIME | GLINE_REASON)) ?
			   " and" : "", expire);
  }

  /* Next, handle lifetime changes... */
  if (flags & GLINE_LIFETIME) {
    gline->gl_lifetime = lifetime; /* save new lifetime */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s extending record lifetime to %Tu",
			   pos ? ";" : "", pos && !(flags & GLINE_REASON) ?
			   " and" : "", lifetime);
  }

  /* Now, handle reason changes... */
  if (flags & GLINE_REASON) {
    non_auto = non_auto || ircd_strncmp(gline->gl_reason, "AUTO", 4);
    MyFree(gline->gl_reason); /* release old reason */
    DupString(gline->gl_reason, reason); /* store new reason */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing reason to \"%s\"",
			   pos ? ";" : "", pos ? " and" : "", reason);
  }

  /* All right, inform ops... */
  non_auto = non_auto || ircd_strncmp(gline->gl_reason, "AUTO", 4);
  sendto_opmask_butone(0, non_auto ? SNO_GLINE : SNO_AUTO,
		       "%s modifying global %s for %s%s%s:%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       gline->gl_user, gline->gl_host ? "@" : "",
		       gline->gl_host ? gline->gl_host : "", buf);

  /* and log the change */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C modifying global %s for %s%s%s:%s", sptr,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    gline->gl_host ? "@" : "", gline->gl_host ? gline->gl_host : "",
	    buf);

  /* We'll be simple for this release, but we can update this to change
   * the propagation syntax on future updates
   */
  if (action != GLINE_LOCAL_ACTIVATE && action != GLINE_LOCAL_DEACTIVATE)
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr,
			  "* %s%s%s%s%s %Tu %Tu %Tu :%s",
			  flags & GLINE_OPERFORCE ? "!" : "", op,
			  gline->gl_user, gline->gl_host ? "@" : "",
			  gline->gl_host ? gline->gl_host : "",
			  gline->gl_expire - TStime(), gline->gl_lastmod,
			  gline->gl_lifetime, gline->gl_reason);

  /* OK, let's do the G-line... */
  return do_gline(cptr, sptr, gline);
}

/** Destroy a local G-line.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the destruction.
 * @param[in] gline G-line to destroy.
 * @return Zero.
 */
int
gline_destroy(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  assert(gline);
  assert(GlineIsLocal(gline));

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s removing local %s for %s%s%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       gline->gl_user, gline->gl_host ? "@" : "",
		       gline->gl_host ? gline->gl_host : "");
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C removing local %s for %s%s%s", sptr,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    gline->gl_host ? "@" : "", gline->gl_host ? gline->gl_host : "");

  gline_free(gline); /* get rid of the G-line */

  return 0; /* convenience return */
}

/** Find a G-line for a particular mask, guided by certain flags.
 * Certain bits in \a flags are interpreted specially:
 * <dl>
 * <dt>GLINE_ANY</dt><dd>Search both BadChans and user G-lines.</dd>
 * <dt>GLINE_BADCHAN</dt><dd>Search BadChans.</dd>
 * <dt>GLINE_GLOBAL</dt><dd>Only match global G-lines.</dd>
 * <dt>GLINE_LOCAL</dt><dd>Only match local G-lines.</dd>
 * <dt>GLINE_LASTMOD</dt><dd>Only match G-lines with a last modification time.</dd>
 * <dt>GLINE_EXACT</dt><dd>Require an exact match of G-line mask.</dd>
 * <dt>anything else</dt><dd>Search user G-lines.</dd>
 * </dl>
 * @param[in] userhost Mask to search for.
 * @param[in] flags Bitwise combination of GLINE_* flags.
 * @return First matching G-line, or NULL if none are found.
 */
struct Gline *
gline_find(char *userhost, unsigned int flags)
{
  struct Gline *gline = 0;
  struct Gline *sgline;
  char *user, *host, *t_uh;

  if (flags & (GLINE_BADCHAN | GLINE_ANY)) {
    gliter(BadChanGlineList, gline, sgline) {
        if ((flags & (GlineIsLocal(gline) ? GLINE_GLOBAL : GLINE_LOCAL)) ||
	  (flags & GLINE_LASTMOD && !gline->gl_lastmod))
	continue;
      else if ((flags & GLINE_EXACT ? ircd_strcmp(gline->gl_user, userhost) :
		match(gline->gl_user, userhost)) == 0)
	return gline;
    }
  }

  if ((flags & (GLINE_BADCHAN | GLINE_ANY)) == GLINE_BADCHAN ||
      *userhost == '#' || *userhost == '&')
    return 0;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &user, &host, "*");

  gliter(GlobalGlineList, gline, sgline) {
    if ((flags & (GlineIsLocal(gline) ? GLINE_GLOBAL : GLINE_LOCAL)) ||
	(flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;
    else if (flags & GLINE_EXACT) {
      if (((gline->gl_host && host && ircd_strcmp(gline->gl_host, host) == 0)
           || (!gline->gl_host && !host)) &&
          (ircd_strcmp(gline->gl_user, user) == 0))
	break;
    } else {
      if (((gline->gl_host && host && match(gline->gl_host, host) == 0)
           || (!gline->gl_host && !host)) &&
	  (match(gline->gl_user, user) == 0))
	break;
    }
  }

  MyFree(t_uh);

  return gline;
}

/** Find a matching G-line for a user.
 * @param[in] cptr Client to compare against.
 * @param[in] flags Bitwise combination of GLINE_GLOBAL and/or
 * GLINE_LASTMOD to limit matches.
 * @return Matching G-line, or NULL if none are found.
 */
struct Gline *
gline_lookup(struct Client *cptr, unsigned int flags)
{
  struct Gline *gline;
  struct Gline *sgline;

  gliter(GlobalGlineList, gline, sgline) {
    if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
        (flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;

    if (GlineIsRealName(gline)) {
      Debug((DEBUG_DEBUG,"realname gline: '%s' '%s'",gline->gl_user,cli_info(cptr)));
      if (match(gline->gl_user+2, cli_info(cptr)) != 0)
        continue;
    }
    else {
      if (match(gline->gl_user, (cli_user(cptr))->username) != 0)
        continue;

      if (GlineIsIpMask(gline)) {
        if (!ipmask_check(&cli_ip(cptr), &gline->gl_addr, gline->gl_bits))
          continue;
      }
      else {
        if (match(gline->gl_host, (cli_user(cptr))->realhost) != 0)
          continue;
      }
    }
    if (GlineIsActive(gline))
      return gline;
  }
  /*
   * No Glines matched
   */
  return 0;
}

/** Delink and free a G-line.
 * @param[in] gline G-line to free.
 */
void
gline_free(struct Gline *gline)
{
  assert(0 != gline);

  *gline->gl_prev_p = gline->gl_next; /* squeeze this gline out */
  if (gline->gl_next)
    gline->gl_next->gl_prev_p = gline->gl_prev_p;

  MyFree(gline->gl_user); /* free up the memory */
  if (gline->gl_host)
    MyFree(gline->gl_host);
  MyFree(gline->gl_reason);
  MyFree(gline);
}

/** Burst all known global G-lines to another server.
 * @param[in] cptr Destination of burst.
 */
void
gline_burst(struct Client *cptr)
{
  struct Gline *gline;
  struct Gline *sgline;

  gliter(GlobalGlineList, gline, sgline) {
    if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
                    gline->gl_host ? "@" : "",
                    gline->gl_host ? gline->gl_host : "",
		    gline->gl_expire - TStime(), gline->gl_lastmod,
                    gline->gl_lifetime, gline->gl_reason);
  }

  gliter(BadChanGlineList, gline, sgline) {
    if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s %Tu %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
		    gline->gl_expire - TStime(), gline->gl_lastmod,
		    gline->gl_lifetime, gline->gl_reason);
  }
}

/** Send a G-line to another server.
 * @param[in] cptr Who to inform of the G-line.
 * @param[in] gline G-line to send.
 * @return Zero.
 */
int
gline_resend(struct Client *cptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || !gline->gl_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
		GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
		gline->gl_host ? "@" : "",
                gline->gl_host ? gline->gl_host : "",
		gline->gl_expire - TStime(), gline->gl_lastmod,
		gline->gl_lifetime, gline->gl_reason);

  return 0;
}

/** Display one or all G-lines to a user.
 * If \a userhost is not NULL, only send the first matching G-line.
 * Otherwise send the whole list.
 * @param[in] sptr User asking for G-line list.
 * @param[in] userhost G-line mask to search for (or NULL).
 * @return Zero.
 */
int
gline_list(struct Client *sptr, char *userhost)
{
  struct Gline *gline;
  struct Gline *sgline;

  if (userhost) {
    if (!(gline = gline_find(userhost, GLINE_ANY))) /* no such gline */
      return send_reply(sptr, ERR_NOSUCHGLINE, userhost);

    /* send gline information along */
    send_reply(sptr, RPL_GLIST, gline->gl_user,
               gline->gl_host ? "@" : "",
               gline->gl_host ? gline->gl_host : "",
	       gline->gl_expire, gline->gl_lastmod,
	       gline->gl_lifetime,
	       GlineIsLocal(gline) ? cli_name(&me) : "*",
	       gline->gl_state == GLOCAL_ACTIVATED ? ">" :
	       (gline->gl_state == GLOCAL_DEACTIVATED ? "<" : ""),
	       GlineIsRemActive(gline) ? '+' : '-', gline->gl_reason);
  } else {
    gliter(GlobalGlineList, gline, sgline) {
      send_reply(sptr, RPL_GLIST, gline->gl_user,
		 gline->gl_host ? "@" : "",
		 gline->gl_host ? gline->gl_host : "",
		 gline->gl_expire, gline->gl_lastmod,
		 gline->gl_lifetime,
		 GlineIsLocal(gline) ? cli_name(&me) : "*",
		 gline->gl_state == GLOCAL_ACTIVATED ? ">" :
		 (gline->gl_state == GLOCAL_DEACTIVATED ? "<" : ""),
		 GlineIsRemActive(gline) ? '+' : '-', gline->gl_reason);
    }

    gliter(BadChanGlineList, gline, sgline) {
      send_reply(sptr, RPL_GLIST, gline->gl_user, "", "",
		 gline->gl_expire, gline->gl_lastmod,
		 gline->gl_lifetime,
		 GlineIsLocal(gline) ? cli_name(&me) : "*",
		 gline->gl_state == GLOCAL_ACTIVATED ? ">" :
		 (gline->gl_state == GLOCAL_DEACTIVATED ? "<" : ""),
		 GlineIsRemActive(gline) ? '+' : '-', gline->gl_reason);
    }
  }

  /* end of gline information */
  return send_reply(sptr, RPL_ENDOFGLIST);
}

/** Statistics callback to list G-lines.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Mask to filter reported G-lines.
 */
void
gline_stats(struct Client *sptr, const struct StatDesc *sd,
            char *param)
{
  struct Gline *gline;
  struct Gline *sgline;

  gliter(GlobalGlineList, gline, sgline) {
    if (param) {
      char gl_mask[USERLEN+HOSTLEN+2];
      strcpy(gl_mask, gline->gl_user);
      if (gline->gl_host) {
	size_t len = strlen(gl_mask);
	gl_mask[len++] = '@';
	strcpy(gl_mask + len, gline->gl_host);
      }
      if (mmatch(param, gl_mask))
	continue;
    }

    send_reply(sptr, RPL_STATSGLINE, 'G', gline->gl_user,
	       gline->gl_host ? "@" : "",
	       gline->gl_host ? gline->gl_host : "",
	       gline->gl_expire, gline->gl_lastmod,
	       gline->gl_lifetime,
	       gline->gl_state == GLOCAL_ACTIVATED ? ">" :
	       (gline->gl_state == GLOCAL_DEACTIVATED ? "<" : ""),
	       GlineIsRemActive(gline) ? '+' : '-',
	       gline->gl_reason);
  }
}

/** Calculate memory used by G-lines.
 * @param[out] gl_size Number of bytes used by G-lines.
 * @return Number of G-lines in use.
 */
int
gline_memory_count(size_t *gl_size)
{
  struct Gline *gline;
  unsigned int gl = 0;

  for (gline = GlobalGlineList; gline; gline = gline->gl_next) {
    gl++;
    *gl_size += sizeof(struct Gline);
    *gl_size += gline->gl_user ? (strlen(gline->gl_user) + 1) : 0;
    *gl_size += gline->gl_host ? (strlen(gline->gl_host) + 1) : 0;
    *gl_size += gline->gl_reason ? (strlen(gline->gl_reason) + 1) : 0;
  }

  for (gline = BadChanGlineList; gline; gline = gline->gl_next) {
    gl++;
    *gl_size += sizeof(struct Gline);
    *gl_size += gline->gl_user ? (strlen(gline->gl_user) + 1) : 0;
    *gl_size += gline->gl_host ? (strlen(gline->gl_host) + 1) : 0;
    *gl_size += gline->gl_reason ? (strlen(gline->gl_reason) + 1) : 0;
  }

  return gl;
}
