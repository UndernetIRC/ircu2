/*
 * IRC - Internet Relay Chat, ircd/gline.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
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
#include "gline.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"
#include "sys.h"    /* FALSE bleah */

#include <assert.h>
#include <string.h>

struct Gline* GlobalGlineList  = 0;
struct Gline* BadChanGlineList = 0;

static void
canon_userhost(char *userhost, char **user_p, char **host_p, char *def_user)
{
  char *tmp;

  if (!(tmp = strchr(userhost, '@'))) {
    *user_p = def_user;
    *host_p = userhost;
  } else {
    *user_p = userhost;
    *(tmp++) = '\0';
    *host_p = tmp;
  }
}

static struct Gline *
make_gline(char *userhost, char *reason, time_t expire, time_t lastmod,
	   unsigned int flags)
{
  struct Gline *gline;
  char *user, *host;

  gline = (struct Gline *)MyMalloc(sizeof(struct Gline)); /* alloc memory */
  assert(0 != gline);

  DupString(gline->gl_reason, reason); /* initialize gline... */
  gline->gl_expire = expire;
  gline->gl_lastmod = lastmod;
  gline->gl_flags = flags & GLINE_MASK;

  if (flags & GLINE_BADCHAN) { /* set a BADCHAN gline */
    DupString(gline->gl_user, userhost); /* first, remember channel */
    gline->gl_host = 0;

    gline->gl_next = BadChanGlineList; /* then link it into list */
    gline->gl_prev_p = &BadChanGlineList;
    if (BadChanGlineList)
      BadChanGlineList->gl_prev_p = &gline->gl_next;
    BadChanGlineList = gline;
  } else {
    canon_userhost(userhost, &user, &host, "*"); /* find user and host */

    DupString(gline->gl_user, user); /* remember them... */
    DupString(gline->gl_host, host);

    if (check_if_ipmask(host)) /* mark if it's an IP mask */
      gline->gl_flags |= GLINE_IPMASK;

    gline->gl_next = GlobalGlineList; /* then link it into list */
    gline->gl_prev_p = &GlobalGlineList;
    if (GlobalGlineList)
      GlobalGlineList->gl_prev_p = &gline->gl_next;
    GlobalGlineList = gline;
  }

  return gline;
}

static int
do_gline(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  struct Client *acptr;
  int fd, retval = 0, tval;

  if (!GlineIsActive(gline)) /* no action taken on inactive glines */
    return 0;

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!acptr->user)
	continue;

      if ((GlineIsIpMask(gline) ? match(gline->gl_host, acptr->sock_ip) :
	   match(gline->gl_host, acptr->sockhost)) == 0 &&
	  (!acptr->user->username ||
	   match(gline->gl_user, acptr->user->username) == 0)) {
	/* ok, here's one that got G-lined */
	sendto_one(acptr, ":%s %d %s :*** %s.", me.name, ERR_YOUREBANNEDCREEP,
		   acptr->name, gline->gl_reason);

	/* let the ops know about it */
	sendto_op_mask(SNO_GLINE, "G-line active for %s",
		       get_client_name(acptr, FALSE));

	/* and get rid of him */
	if ((tval = exit_client_msg(cptr, acptr, &me, "G-lined (%s)",
				    gline->gl_reason)))
	  retval = tval; /* retain killed status */
      }
    }
  }

  return retval;
}

static void
propagate_gline(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || (IsUser(sptr) && !gline->gl_lastmod))
    return;

  if (gline->gl_lastmod)
    sendcmdto_serv_butone(cptr, CMD_GLINE, sptr, "* %c%s%s%s %Tu %Tu :%s",
			  GlineIsActive(gline) ? '+' : '-', gline->gl_user,
			  GlineIsBadChan(gline) ? "" : "@",
			  GlineIsBadChan(gline) ? "" : gline->gl_host,
			  gline->gl_expire - CurrentTime, gline->gl_lastmod,
			  gline->gl_reason);
  else
    sendcmdto_serv_butone(cptr, CMD_GLINE, sptr, "* %c%s%s%s %Tu :%s",
			  GlineIsActive(gline) ? '+' : '-', gline->gl_user,
			  GlineIsBadChan(gline) ? "" : "@",
			  GlineIsBadChan(gline) ? "" : gline->gl_host,
			  gline->gl_expire - CurrentTime, gline->gl_reason);
}

int 
gline_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, unsigned int flags)
{
  struct Gline *agline;

  assert(0 != userhost);
  assert(0 != reason);

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than GLINE_MAX_EXPIRE.
   */
  if (!(flags & GLINE_FORCE) && (expire <= 0 || expire > GLINE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_error_to_client(sptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* NO_OLD_GLINE allows *@#channel to work correctly */
#ifdef BADCHAN
  if (*userhost == '#' || *userhost == '&' || *userhost == '+'
# ifndef NO_OLD_GLINE
      || userhost[2] == '#' || userhost[2] == '&' || userhost[2] == '+'
# endif /* OLD_GLINE */
      ) {
# ifndef LOCAL_BADCHAN
    if (flags & GLINE_LOCAL)
      return 0;
# endif
    flags |= GLINE_BADCHAN;
  }
#endif /* BADCHAN */

  /* Inform ops... */
  sendto_op_mask(SNO_GLINE, "%s adding %s %s for %s, expiring at "
		 TIME_T_FMT ": %s",
		 IsServer(sptr) ? sptr->name : sptr->user->server->name,
		 flags & GLINE_LOCAL ? "local" : "global",
		 flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost,
		 expire + TSoffset, reason);

#ifdef GPATH
  /* and log it */
  if (IsServer(sptr))
    write_log(GPATH, "# " TIME_T_FMT " %s adding %s %s for %s, expiring at "
	      TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      flags & GLINE_LOCAL ? "local" : "global",
	      flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost,
	      expire + TSoffset, reason);
  else
    write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s adding %s %s for %s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host,
	      flags & GLINE_LOCAL ? "local" : "global",
	      flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost,
	      expire + TSoffset, reason);
#endif /* GPATH */

  /* make the gline */
  agline = make_gline(userhost, reason, expire, lastmod, flags);

  propagate_gline(cptr, sptr, agline);

  if (GlineIsBadChan(agline))
    return 0;

#ifdef GPATH
  /* this can be inserted into the conf */
  write_log(GPATH, "%c:%s:%s:%s\n", GlineIsIpMask(agline) ? 'k' : 'K',
	    GlineHost(agline), GlineReason(agline), GlineUser(agline));
#endif /* GPATH */

  return do_gline(cptr, sptr, agline); /* knock off users if necessary */
}

int
gline_activate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
	       time_t lastmod)
{
  assert(0 != gline);
  assert(!GlineIsLocal(gline));

  gline->gl_flags |= GLINE_ACTIVE;

  if (gline->gl_lastmod >= lastmod) /* force lastmod to increase */
    gline->gl_lastmod++;
  else
    gline->gl_lastmod = lastmod;

  /* Inform ops and log it */
  sendto_op_mask(SNO_GLINE, "%s activating global %s for %s%s%s, expiring at "
		 TIME_T_FMT ": %s",
		 IsServer(sptr) ? sptr->name : sptr->user->server->name,
		 GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		 gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		 GlineIsBadChan(gline) ? "" : gline->gl_host,
		 gline->gl_expire + TSoffset, gline->gl_reason);

#ifdef GPATH
  if (IsServer(sptr))
    write_log(GPATH, "# " TIME_T_FMT " %s activating global %s for %s%s%s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host,
	      gline->gl_expire + TSoffset, gline->gl_reason);
  else
    write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s activating %s for "
	      "%s%s%s, expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host,
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host,
	      gline->gl_expire + TSoffset, gline->gl_reason);
#endif /* GPATH */

  propagate_gline(cptr, sptr, gline);

  return GlineIsBadChan(gline) ? 0 : do_gline(cptr, sptr, gline);
}

int
gline_deactivate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
		 time_t lastmod)
{
  assert(0 != gline);

  if (!GlineIsLocal(gline)) {
    gline->gl_flags &= ~GLINE_ACTIVE;

    if (gline->gl_lastmod >= lastmod)
      gline->gl_lastmod++;
    else
      gline->gl_lastmod = lastmod;
  }

  /* Inform ops and log it */
  sendto_op_mask(SNO_GLINE, "%s %s %s for %s%s%s, expiring at "
		 TIME_T_FMT ": %s",
		 IsServer(sptr) ? sptr->name : sptr->user->server->name,
		 GlineIsLocal(gline) ? "removing local" :
		 "deactivating global",
		 GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		 gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		 GlineIsBadChan(gline) ? "" : gline->gl_host,
		 gline->gl_expire + TSoffset, gline->gl_reason);

#ifdef GPATH
  if (IsServer(sptr))
    write_log(GPATH, "# " TIME_T_FMT " %s %s %s for %s%s%s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      GlineIsLocal(gline) ? "removing local" : "deactivating global",
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host,
	      gline->gl_expire + TSoffset, gline->gl_reason);
  else
    write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s %s %s for "
	      "%s%s%s, expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host,
	      GlineIsLocal(gline) ? "removing local" : "deactivating global",
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host,
	      gline->gl_expire + TSoffset, gline->gl_reason);
#endif /* GPATH */

  if (GlineIsLocal(gline))
    gline_free(gline);
  else
    propagate_gline(cptr, sptr, gline);

  return 0;
}

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
      else if ((flags & GLINE_EXACT ? ircd_strcmp(gline->gl_user, userhost) :
		match(gline->gl_user, userhost)) == 0)
	return gline;
    }
  }

  if ((flags & (GLINE_BADCHAN | GLINE_ANY)) == GLINE_BADCHAN ||
      *userhost == '#' || *userhost == '&' || *userhost == '+'
#ifndef NO_OLD_GLINE
      || userhost[2] == '#' || userhost[2] == '&' || userhost[2] == '+'
#endif /* NO_OLD_GLINE */
      )
    return 0;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &user, &host, 0);

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else if (flags & GLINE_EXACT) {
      if (ircd_strcmp(gline->gl_host, host) == 0 &&
	  ((!user && ircd_strcmp(gline->gl_user, "*") == 0) ||
	   ircd_strcmp(gline->gl_user, user) == 0))
	break;
    } else {
      if (match(gline->gl_host, host) == 0 &&
	  ((!user && ircd_strcmp(gline->gl_user, "*") == 0) ||
	   match(gline->gl_user, user) == 0))
      break;
    }
  }

  MyFree(t_uh);

  return gline;
}

struct Gline *
gline_lookup(struct Client *cptr)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else if ((GlineIsIpMask(gline) ?
	      match(gline->gl_host, ircd_ntoa((const char *)&cptr->ip)) :
	      match(gline->gl_host, cptr->user->host)) == 0 &&
	     match(gline->gl_user, cptr->user->username) == 0)
      return gline;
  }

  return 0;
}

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
      sendcmdto_one(cptr, CMD_GLINE, &me, "* %c%s@%s %Tu %Tu :%s",
		    GlineIsActive(gline) ? '+' : '-', gline->gl_user,
		    gline->gl_host, gline->gl_expire - CurrentTime,
		    gline->gl_lastmod, gline->gl_reason);
  }

  for (gline = BadChanGlineList; gline; gline = sgline) { /* all glines */
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendcmdto_one(cptr, CMD_GLINE, &me, "* %c%s %Tu %Tu :%s",
		    GlineIsActive(gline) ? '+' : '-', gline->gl_user,
		    gline->gl_expire - CurrentTime, gline->gl_lastmod,
		    gline->gl_reason);
  }
}

int
gline_resend(struct Client *cptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || !gline->gl_lastmod)
    return 0;

  sendcmdto_one(cptr, CMD_GLINE, &me, "* %c%s%s%s %Tu %Tu :%s",
		GlineIsActive(gline) ? '+' : '-', gline->gl_user,
		GlineIsBadChan(gline) ? "" : "@",
		GlineIsBadChan(gline) ? "" : gline->gl_host,
		gline->gl_expire - CurrentTime, gline->gl_lastmod,
		gline->gl_reason);

  return 0;
}

int
gline_list(struct Client *sptr, char *userhost)
{
  struct Gline *gline;
  struct Gline *sgline;

  if (userhost) {
    if (!(gline = gline_find(userhost, GLINE_ANY))) /* no such gline */
      return send_error_to_client(sptr, ERR_NOSUCHGLINE, userhost);

    /* send gline information along */
    sendto_one(sptr, rpl_str(RPL_GLIST), me.name, sptr->name, gline->gl_user,
	       GlineIsBadChan(gline) ? "" : "@",
	       GlineIsBadChan(gline) ? "" : gline->gl_host,
	       gline->gl_expire + TSoffset,
	       GlineIsLocal(gline) ? me.name : "*",
	       GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
  } else {
    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	sendto_one(sptr, rpl_str(RPL_GLIST), me.name, sptr->name,
		   gline->gl_user, "@", gline->gl_host,
		   gline->gl_expire + TSoffset,
		   GlineIsLocal(gline) ? me.name : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }

    for (gline = BadChanGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	sendto_one(sptr, rpl_str(RPL_GLIST), me.name, sptr->name,
		   gline->gl_user, "", "", gline->gl_expire + TSoffset,
		   GlineIsLocal(gline) ? me.name : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }
  }

  /* end of gline information */
  sendto_one(sptr, rpl_str(RPL_ENDOFGLIST), me.name, sptr->name);
  return 0;
}

void
gline_stats(struct Client *sptr)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= CurrentTime)
      gline_free(gline);
    else
      sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name, sptr->name, 'G',
		 gline->gl_user, gline->gl_host, gline->gl_expire + TSoffset,
		 gline->gl_reason);
  }
}
