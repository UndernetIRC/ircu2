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
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"
#include "whocmds.h"

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

/** List of user G-lines. */
struct Gline* GlobalGlineList  = 0;
/** List of BadChan G-lines. */
struct Gline* BadChanGlineList = 0;

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
	   unsigned int flags)
{
  struct Gline *gline, *sgline, *after = 0;

  if (!(flags & GLINE_BADCHAN)) { /* search for overlapping glines first */

    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else if (((gline->gl_flags & GLINE_LOCAL) != (flags & GLINE_LOCAL)) ||
               (gline->gl_host && !host) || (!gline->gl_host && host))
	continue;
      else if (!mmatch(gline->gl_user, user) /* gline contains new mask */
	       && (gline->gl_host == NULL || !mmatch(gline->gl_host, host))) {
	if (expire <= gline->gl_expire) /* will expire before wider gline */
	  return 0;
	else
	  after = gline; /* stick new gline after this one */
      } else if (!mmatch(user, gline->gl_user) /* new mask contains gline */
		 && (gline->gl_host==NULL || !mmatch(host, gline->gl_host)) 
		 && gline->gl_expire <= expire) /* old expires before new */
	gline_free(gline); /* save some memory */
    }
  }

  gline = (struct Gline *)MyMalloc(sizeof(struct Gline)); /* alloc memory */
  assert(0 != gline);

  DupString(gline->gl_reason, reason); /* initialize gline... */
  gline->gl_expire = expire;
  gline->gl_lastmod = lastmod;
  gline->gl_flags = flags & GLINE_MASK;

  if (flags & GLINE_BADCHAN) { /* set a BADCHAN gline */
    DupString(gline->gl_user, user); /* first, remember channel */
    gline->gl_host = 0;

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

    if (*user != '$' && ipmask_parse(host, &gline->gl_addr, &gline->gl_bits)) {
      Debug((DEBUG_DEBUG,"IP gline: %s/%u", ircd_ntoa(&gline->gl_addr), gline->gl_bits));
      gline->gl_flags |= GLINE_IPMASK;
    }

    if (after) {
      gline->gl_next = after->gl_next;
      gline->gl_prev_p = &after->gl_next;
      if (after->gl_next)
	after->gl_next->gl_prev_p = &gline->gl_next;
      after->gl_next = gline;
    } else {
      gline->gl_next = GlobalGlineList; /* then link it into list */
      gline->gl_prev_p = &GlobalGlineList;
      if (GlobalGlineList)
	GlobalGlineList->gl_prev_p = &gline->gl_next;
      GlobalGlineList = gline;
    }
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
        if (cli_user(acptr)->username &&
            match(gline->gl_user, (cli_user(acptr))->username) != 0)
          continue;

        if (GlineIsIpMask(gline)) {
#ifdef DEBUGMODE
          char tbuf1[SOCKIPLEN], tbuf2[SOCKIPLEN];
          Debug((DEBUG_DEBUG,"IP gline: %s %s/%u", ircd_ntoa_r(tbuf1, &cli_ip(cptr)), ircd_ntoa_r(tbuf2, &gline->gl_addr), gline->gl_bits));
#endif
          if (!ipmask_check(&cli_ip(cptr), &gline->gl_addr, gline->gl_bits))
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
        if (dots != 3 || ipmask > 3)
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
int
gline_propagate(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || (IsUser(sptr) && !gline->gl_lastmod))
    return 0;

  if (gline->gl_lastmod)
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu :%s",
			  GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
			  gline->gl_host ? "@" : "",
			  gline->gl_host ? gline->gl_host : "",
			  gline->gl_expire - CurrentTime, gline->gl_lastmod,
			  gline->gl_reason);
  else
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr,
			  (GlineIsRemActive(gline) ?
			   "* +%s%s%s %Tu :%s" : "* -%s%s%s"),
			  gline->gl_user, 
			  gline->gl_host ? "@" : "",
			  gline->gl_host ? gline->gl_host : "",
			  gline->gl_expire - CurrentTime, gline->gl_reason);

  return 0;
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
 * @param[in] expire Duration of G-line in seconds.
 * @param[in] lastmod Last modification time of G-line.
 * @param[in] flags Bitwise combination of GLINE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, unsigned int flags)
{
  struct Gline *agline;
  char uhmask[USERLEN + HOSTLEN + 2];
  char *user, *host;
  int tmp;

  assert(0 != userhost);
  assert(0 != reason);

  if (*userhost == '#' || *userhost == '&') {
    if ((flags & GLINE_LOCAL) && !HasPriv(sptr, PRIV_LOCAL_BADCHAN))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    flags |= GLINE_BADCHAN;
    user = userhost;
    host = 0;
  } else if (*userhost == '$') {
    switch (*userhost == '$' ? userhost[1] : userhost[3]) {
      case 'R': flags |= GLINE_REALNAME; break;
      default:
        /* uh, what to do here? */
        /* The answer, my dear Watson, is we throw a protocol_violation()
           -- hikari */
        return protocol_violation(sptr,"%s has been smoking the sweet leaf and sent me a whacky gline",cli_name(sptr));
        break;
    }
     user = (*userhost =='$' ? userhost : userhost+2);
     host = 0;
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

      if ((tmp = count_users(uhmask)) >=
	  feature_int(FEAT_GLINEMAXUSERCOUNT) && !(flags & GLINE_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  }

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than GLINE_MAX_EXPIRE.
   */
  if (!(flags & GLINE_FORCE) && (expire <= 0 || expire > GLINE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
                       SNO_AUTO, "%s adding %s %s for %s%s%s, expiring at "
                       "%Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
		       (flags & GLINE_LOCAL) ? "local" : "global",
		       (flags & GLINE_BADCHAN) ? "BADCHAN" : "GLINE", user,
		       (flags & (GLINE_BADCHAN|GLINE_REALNAME)) ? "" : "@",
		       (flags & (GLINE_BADCHAN|GLINE_REALNAME)) ? "" : host,
		       expire + TSoffset, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s %s for %s%s%s, expiring at %Tu: %s", sptr,
	    flags & GLINE_LOCAL ? "local" : "global",
	    flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", user,
	    flags & (GLINE_BADCHAN|GLINE_REALNAME) ? "" : "@",
	    flags & (GLINE_BADCHAN|GLINE_REALNAME) ? "" : host,
	    expire + TSoffset, reason);

  /* make the gline */
  agline = make_gline(user, host, reason, expire, lastmod, flags);

  if (!agline) /* if it overlapped, silently return */
    return 0;

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
                       gline->gl_expire + TSoffset, gline->gl_reason);
  
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global %s for %s%s%s, expiring at %Tu: %s", sptr,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    gline->gl_host ? "@" : "",
	    gline->gl_host ? gline->gl_host : "",
	    gline->gl_expire + TSoffset, gline->gl_reason);

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
		       gline->gl_expire + TSoffset, gline->gl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s %s for %s%s%s, expiring at %Tu: %s", sptr, msg,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    gline->gl_host ? "@" : "",
	    gline->gl_host ? gline->gl_host : "",
	    gline->gl_expire + TSoffset, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  /* if it's a local gline or a Uworld gline (and not locally deactivated).. */
  if (GlineIsLocal(gline) || (!gline->gl_lastmod && !(flags & GLINE_LOCAL)))
    gline_free(gline); /* get rid of it */

  return 0;
}

/** Find a G-line for a particular mask, guided by certain flags.
 * Certain bits in \a flags are interpreted specially:
 * <dl>
 * <dt>GLINE_ANY</dt><dd>Search both BadChans and user G-lines.</dd>
 * <dt>GLINE_BADCHAN</dt><dd>Search BadChans.</dd>
 * <dt>GLINE_GLOBAL</dt><dd>Only match global G-lines.</dd>
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
  struct Gline *gline;
  struct Gline *sgline;
  char *user, *host, *t_uh;

  if (flags & (GLINE_BADCHAN | GLINE_ANY)) {
    for (gline = BadChanGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
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
  canon_userhost(t_uh, &user, &host, 0);

  if (BadPtr(user))
    return 0;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
	     (flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;
    else if (flags & GLINE_EXACT) {
      if (((gline->gl_host && host && ircd_strcmp(gline->gl_host, host) == 0)
           || (!gline->gl_host && !host)) &&
          ((!user && ircd_strcmp(gline->gl_user, "*") == 0) ||
	   ircd_strcmp(gline->gl_user, user) == 0))
	break;
    } else {
      if (((gline->gl_host && host && match(gline->gl_host, host) == 0)
           || (!gline->gl_host && !host)) &&
	  ((!user && ircd_strcmp(gline->gl_user, "*") == 0) ||
	   match(gline->gl_user, user) == 0))
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

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) {
      gline_free(gline);
      continue;
    }
    
    if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
        (flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;

    if (GlineIsRealName(gline)) {
      Debug((DEBUG_DEBUG,"realname gline: '%s' '%s'",gline->gl_user,cli_info(cptr)));
      if (match(gline->gl_user+2, cli_info(cptr)) != 0)
        continue;
      if (!GlineIsActive(gline))
        continue;
      return gline;
    }
    else {
      if (match(gline->gl_user, (cli_user(cptr))->username) != 0)
        continue;

      if (GlineIsIpMask(gline)) {
#ifdef DEBUGMODE
        char tbuf1[SOCKIPLEN], tbuf2[SOCKIPLEN];
        Debug((DEBUG_DEBUG,"IP gline: %s %s/%u", ircd_ntoa_r(tbuf1, &cli_ip(cptr)), ircd_ntoa_r(tbuf2, &gline->gl_addr), gline->gl_bits));
#endif
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

  for (gline = GlobalGlineList; gline; gline = sgline) { /* all glines */
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
                    gline->gl_host ? "@" : "",
                    gline->gl_host ? gline->gl_host : "",
		    gline->gl_expire - CurrentTime, gline->gl_lastmod,
                    gline->gl_reason);
  }

  for (gline = BadChanGlineList; gline; gline = sgline) { /* all glines */
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
		    gline->gl_expire - CurrentTime, gline->gl_lastmod,
		    gline->gl_reason);
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

  sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu :%s",
		GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
		gline->gl_host ? "@" : "",
                gline->gl_host ? gline->gl_host : "",
		gline->gl_expire - CurrentTime, gline->gl_lastmod,
		gline->gl_reason);

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
	       gline->gl_expire + TSoffset,
	       GlineIsLocal(gline) ? cli_name(&me) : "*",
	       GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
  } else {
    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	send_reply(sptr, RPL_GLIST, gline->gl_user,
                   gline->gl_host ? "@" : "",
                   gline->gl_host ? gline->gl_host : "",
		   gline->gl_expire + TSoffset,
		   GlineIsLocal(gline) ? cli_name(&me) : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }

    for (gline = BadChanGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	send_reply(sptr, RPL_GLIST, gline->gl_user, "", "",
		   gline->gl_expire + TSoffset,
		   GlineIsLocal(gline) ? cli_name(&me) : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }
  }

  /* end of gline information */
  return send_reply(sptr, RPL_ENDOFGLIST);
}

/** Statistics callback to list G-lines.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
gline_stats(struct Client *sptr, const struct StatDesc *sd,
            char *param)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else
      send_reply(sptr, RPL_STATSGLINE, 'G', gline->gl_user,
                 gline->gl_host ? "@" : "",
                 gline->gl_host ? gline->gl_host : "",
		 gline->gl_expire + TSoffset, gline->gl_reason);
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

  for (gline = GlobalGlineList; gline; gline = gline->gl_next)
  {
    gl++;
    *gl_size += sizeof(struct Gline);
    *gl_size += gline->gl_user ? (strlen(gline->gl_user) + 1) : 0;
    *gl_size += gline->gl_host ? (strlen(gline->gl_host) + 1) : 0;
    *gl_size += gline->gl_reason ? (strlen(gline->gl_reason) + 1) : 0;
  }
  return gl;
}
