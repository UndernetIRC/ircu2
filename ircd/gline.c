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
#include "config.h"

#include "gline.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_debug.h"
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
#include <stdio.h>
#include <arpa/inet.h> /* for inet_ntoa */

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
  struct Gline *gline, *sgline, *after = 0;
  char *user, *host;

  if (!(flags & GLINE_BADCHAN)) { /* search for overlapping glines first */
    canon_userhost(userhost, &user, &host, "*"); /* find user and host */

    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else if ((gline->gl_flags & GLINE_LOCAL) != (flags & GLINE_LOCAL))
	continue;
      else if (!mmatch(gline->gl_user, user) && /* gline contains new mask */
	       !mmatch(gline->gl_host, host)) {
	if (expire <= gline->gl_expire) /* will expire before wider gline */
	  return 0;
	else
	  after = gline; /* stick new gline after this one */
      } else if (!mmatch(user, gline->gl_user) && /* new mask contains gline */
		 !mmatch(host, gline->gl_host) &&
		 gline->gl_expire <= expire) /* gline expires before new one */
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
    DupString(gline->gl_user, userhost); /* first, remember channel */
    gline->gl_host = 0;

    gline->gl_next = BadChanGlineList; /* then link it into list */
    gline->gl_prev_p = &BadChanGlineList;
    if (BadChanGlineList)
      BadChanGlineList->gl_prev_p = &gline->gl_next;
    BadChanGlineList = gline;
  } else {
    DupString(gline->gl_user, user); /* remember them... */
    DupString(gline->gl_host, host);

    if (check_if_ipmask(host)) { /* mark if it's an IP mask */
      int class;
      char ipname[16];
      int ad[4] = { 0 };
      int bits2 = 0;
       
      class = sscanf(host,"%d.%d.%d.%d/%d",
                     &ad[0],&ad[1],&ad[2],&ad[3], &bits2);
      if (class!=5) {
        gline->bits=class*8;
      }
      else {
        gline->bits=bits2;
      }
      sprintf_irc(ipname,"%d.%d.%d.%d",ad[0],ad[1],ad[2],ad[3]);
      gline->ipnum.s_addr = inet_addr(ipname);
      Debug((DEBUG_DEBUG,"IP gline: %08x/%i",gline->ipnum.s_addr,gline->bits));
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
      if (!cli_user(acptr))
	continue;
	
      if (cli_user(acptr)->username && 
          match (gline->gl_user, (cli_user(acptr))->username) != 0)
               continue;
          
      if (GlineIsIpMask(gline)) {
        Debug((DEBUG_DEBUG,"IP gline: %08x %08x/%i",(cli_ip(cptr)).s_addr,gline->ipnum.s_addr,gline->bits));
        if (((cli_ip(acptr)).s_addr & NETMASK(gline->bits)) != gline->ipnum.s_addr)
          continue;
      }
      else {
        if (match(gline->gl_host, cli_sockhost(acptr)) != 0)
          continue;
      }

      /* ok, here's one that got G-lined */
      send_reply(acptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s",
      	   gline->gl_reason);

      /* let the ops know about it */
      sendto_opmask_butone(0, SNO_GLINE, "G-line active for %s",
      		     get_client_name(acptr, TRUE));

      /* and get rid of him */
      if ((tval = exit_client_msg(cptr, acptr, &me, "G-lined (%s)",
          gline->gl_reason)))
        retval = tval; /* retain killed status */
    }
  }
  return retval;
}

int
gline_propagate(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || (IsUser(sptr) && !gline->gl_lastmod))
    return 0;

  if (gline->gl_lastmod)
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu :%s",
			  GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
			  GlineIsBadChan(gline) ? "" : "@",
			  GlineIsBadChan(gline) ? "" : gline->gl_host,
			  gline->gl_expire - CurrentTime, gline->gl_lastmod,
			  gline->gl_reason);
  else
    sendcmdto_serv_butone(sptr, CMD_GLINE, cptr,
			  (GlineIsRemActive(gline) ?
			   "* +%s%s%s %Tu :%s" : "* -%s%s%s"),
			  gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
			  GlineIsBadChan(gline) ? "" : gline->gl_host,
			  gline->gl_expire - CurrentTime, gline->gl_reason);

  return 0;
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
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* NO_OLD_GLINE allows *@#channel to work correctly */
  if (*userhost == '#' || *userhost == '&' || *userhost == '+'
# ifndef NO_OLD_GLINE
      || userhost[2] == '#' || userhost[2] == '&' || userhost[2] == '+'
# endif /* OLD_GLINE */
      ) {
    if ((flags & GLINE_LOCAL) && !HasPriv(sptr, PRIV_LOCAL_BADCHAN))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    flags |= GLINE_BADCHAN;
  }

  /* Inform ops... */
  sendto_opmask_butone(0, SNO_GLINE, "%s adding %s %s for %s, expiring at "
		       "%Tu: %s", IsServer(sptr) ? cli_name(sptr) :
		       cli_name((cli_user(sptr))->server),
		       flags & GLINE_LOCAL ? "local" : "global",
		       flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost,
		       expire + TSoffset, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s %s for %s, expiring at %Tu: %s", sptr,
	    flags & GLINE_LOCAL ? "local" : "global",
	    flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost,
	    expire + TSoffset, reason);

  /* make the gline */
  agline = make_gline(userhost, reason, expire, lastmod, flags);

  if (!agline) /* if it overlapped, silently return */
    return 0;

  gline_propagate(cptr, sptr, agline);

  if (GlineIsBadChan(agline))
    return 0;

  return do_gline(cptr, sptr, agline); /* knock off users if necessary */
}

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
		       "expiring at %Tu: %s", IsServer(sptr) ? cli_name(sptr) :
		       cli_name((cli_user(sptr))->server),
		       GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		       GlineIsBadChan(gline) ? "" : gline->gl_host,
		       gline->gl_expire + TSoffset, gline->gl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global %s for %s%s%s, expiring at %Tu: %s", sptr,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    GlineIsBadChan(gline) ? "" : "@",
	    GlineIsBadChan(gline) ? "" : gline->gl_host,
	    gline->gl_expire + TSoffset, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  return GlineIsBadChan(gline) ? 0 : do_gline(cptr, sptr, gline);
}

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
		       "%s", IsServer(sptr) ? cli_name(sptr) :
		       cli_name((cli_user(sptr))->server),
		       msg, GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		       gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		       GlineIsBadChan(gline) ? "" : gline->gl_host,
		       gline->gl_expire + TSoffset, gline->gl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s %s for %s%s%s, expiring at %Tu: %s", sptr, msg,
	    GlineIsBadChan(gline) ? "BADCHAN" : "GLINE", gline->gl_user,
	    GlineIsBadChan(gline) ? "" : "@",
	    GlineIsBadChan(gline) ? "" : gline->gl_host,
	    gline->gl_expire + TSoffset, gline->gl_reason);

  if (!(flags & GLINE_LOCAL)) /* don't propagate local changes */
    gline_propagate(cptr, sptr, gline);

  /* if it's a local gline or a Uworld gline (and not locally deactivated).. */
  if (GlineIsLocal(gline) || (!gline->gl_lastmod && !(flags & GLINE_LOCAL)))
    gline_free(gline); /* get rid of it */

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
      else if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
	       (flags & GLINE_LASTMOD && !gline->gl_lastmod))
	continue;
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
    else if ((flags & GLINE_GLOBAL && gline->gl_flags & GLINE_LOCAL) ||
	     (flags & GLINE_LASTMOD && !gline->gl_lastmod))
      continue;
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
     
    if (match(gline->gl_user, (cli_user(cptr))->username) != 0)
      continue;
    	 
    if (GlineIsIpMask(gline)) {
      Debug((DEBUG_DEBUG,"IP gline: %08x %08x/%i",(cli_ip(cptr)).s_addr,gline->ipnum.s_addr,gline->bits));
      if (((cli_ip(cptr)).s_addr & NETMASK(gline->bits)) != gline->ipnum.s_addr)
        continue;
    }
    else {
      if (match(gline->gl_host, (cli_user(cptr))->host) != 0) 
        continue;
    }
    return gline;
  }
  /*
   * No Glines matched
   */
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
      sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s@%s %Tu %Tu :%s",
		    GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
		    gline->gl_host, gline->gl_expire - CurrentTime,
		    gline->gl_lastmod, gline->gl_reason);
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

int
gline_resend(struct Client *cptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || !gline->gl_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_GLINE, cptr, "* %c%s%s%s %Tu %Tu :%s",
		GlineIsRemActive(gline) ? '+' : '-', gline->gl_user,
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
      return send_reply(sptr, ERR_NOSUCHGLINE, userhost);

    /* send gline information along */
    send_reply(sptr, RPL_GLIST, gline->gl_user,
	       GlineIsBadChan(gline) ? "" : "@",
	       GlineIsBadChan(gline) ? "" : gline->gl_host,
	       gline->gl_expire + TSoffset,
	       GlineIsLocal(gline) ? cli_name(&me) : "*",
	       GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
  } else {
    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= CurrentTime)
	gline_free(gline);
      else
	send_reply(sptr, RPL_GLIST, gline->gl_user, "@", gline->gl_host,
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
      send_reply(sptr, RPL_STATSGLINE, 'G', gline->gl_user, gline->gl_host,
		 gline->gl_expire + TSoffset, gline->gl_reason);
  }
}
