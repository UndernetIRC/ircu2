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
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"    /* FALSE bleah */

#include <assert.h>

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
  struct Gline *agline;
  char *user, *host;

  agline = (struct Gline *)MyMalloc(sizeof(struct Gline)); /* alloc memory */
  assert(0 != agline);

  gline->gl_expire = expire; /* initialize gline... */
  gline->gl_lastmod = lastmod;
  gline->gl_flags = flags & GLINE_MASK;

  if (flags & GLINE_BADCHAN) { /* set a BADCHAN gline */
    DupString(gline->gl_user, userhost); /* first, remember channel */
    gline->gl_host = 0;

    gline->gl_next = BadChanGlineList; /* then link it into list */
    gline->gl_prev_p = &BadChanGlineList;
    if (BadChanGlineList)
      BadChanGlineList->gl_prev_p = &agline->gl_next;
    BadChanGlineList = agline;
  } else {
    canon_userhost(userhost, &user, &host, "*"); /* find user and host */

    DupString(gline->gl_user, user); /* remember them... */
    DupString(gline->gl_host, host);

    if (check_if_ipmask(host)) /* mark if it's an IP mask */
      gline->gl_flags |= GLINE_IPMASK;

    gline->gl_next = GlobalGlineList; /* then link it into list */
    gline->gl_prev_p = &GlobalGlineList;
    if (GlobalGlineList)
      GlobalGlineList->gl_prev_p = &agline->gl_next;
    GlobalGlineList = agline;
  }

  return agline;
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

      if ((GlineIsIpMask(gline) ? match(gline->host, acptr->sock_ip) :
	   match(gline->host, acptr->sockhost)) == 0 &&
	  (!acptr->user->username ||
	   match(gline->name, acptr->user->username) == 0)) {
	/* ok, here's one that got G-lined */
	sendto_one(acptr, ":%s %d %s :*** %s.", me.name, ERR_YOUREBANNEDCREEP,
		   acptr->name, gline->reason);

	/* let the ops know about it */
	sendto_op_mask(SNO_GLINE, "G-line active for %s",
		       get_client_name(acptr, FALSE));

	/* and get rid of him */
	if ((tval = exit_client_msg(cptr, acptr, &me, "G-lined (%s)",
				    gline->reason)))
	  retval = tval; /* retain killed status */
      }
    }
  }

  return retval;
}

static void
propagate_gline(struct Client *cptr, struct Client *sptr, struct Gline *gline)
{
  if (GlineIsLocal(gline)) /* don't propagate local glines */
    return;

  if (IsUser(sptr)) { /* select appropriate source */
    assert(0 != gline->gl_lastmod);
    sendto_serv_butone(cptr, "%s%s " TOK_GLINE " * %c%s%s%s " TIME_T_FMT " "
		       TIME_T_FMT " :%s", NumNick(sptr),
		       GlineIsActive(gline) ? '+' : '-', gline->gl_user,
		       GlineIsBadChan(gline) ? "" : "@",
		       GlineIsBadChan(gline) ? "" : gline->gl_host,
		       gline->gl_expire - TStime(), gline->gl_lastmod,
		       gline->gl_reason);
  } else {
    if (gline->gl_lastmod)
      sendto_serv_butone(cptr, "%s " TOK_GLINE " * %c%s%s%s " TIME_T_FMT " "
			 TIME_T_FMT " :%s", NumServ(sptr),
			 GlineIsActive(gline) ? '+' : '-', gline->gl_user,
			 GlineIsBadChan(gline) ? "" : "@",
			 GlineIsBadChan(gline) ? "" : gline->gl_host,
			 gline->gl_expire - TStime(), gline->gl_lastmod,
			 gline->gl_reason);
    else
      sendto_serv_butone(cptr, "%s " TOK_GLINE " * %c%s%s%s " TIME_T_FMT
			 " :%s", NumServ(sptr),
			 GlineIsActive(gline) ? '+' : '-', gline->gl_user,
			 GlineIsBadChan(gline) ? "" : "@",
			 GlineIsBadChan(gline) ? "" : gline->gl_host,
			 gline->gl_expire - TStime(), gline->gl_reason);
  }
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

  expire += TStime(); /* convert from lifetime to timestamp */

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
		 expire, reason);

#ifdef GPATH
  /* and log it */
  if (IsServer(sptr))
    write_log(GPATH, "# " TIME_T_FMT " %s adding %s %s for %s, expiring at "
	      TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      flags & GLINE_LOCAL ? "local" : "global",
	      flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost, expire,
	      reason);
  else
    write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s adding %s %s for %s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host,
	      flags & GLINE_LOCAL ? "local" : "global",
	      flags & GLINE_BADCHAN ? "BADCHAN" : "GLINE", userhost, expire,
	      reason);
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

  gline->gl_flags |= GLINE_ACTIVE;
  gline->gl_lastmod = lastmod;

  /* Inform ops and log it */
  sendto_op_mask(SNO_GLINE, "%s activating %s %s for %s%s%s, expiring at "
		 TIME_T_FMT ": %s",
		 IsServer(sptr) ? sptr->name : sptr->user->server->name,
		 GlineIsLocal(gline) ? "local" : "global",
		 GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		 gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		 GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
		 gline->gl_reason);

#ifdef GPATH
  if (IsServer(sptr))
    write_log(GPATH, "# " TIME_T_FMT " %s activating %s %s for %s%s%s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      GlineIsLocal(gline) ? "local" : "global",
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
	      gline->gl_reason);
  else
    write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s activating %s %s for "
	      "%s%s%s, expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host,
	      GlineIsLocal(gline) ? "local" : "global",
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
	      gline->gl_reason);
#endif /* GPATH */

  propagate_gline(cptr, sptr, gline);

  return GlineIsBadChan(gline) ? 0 : do_gline(cptr, sptr, gline);
}

int
gline_deactivate(struct Client *cptr, struct Client *sptr, struct Gline *gline,
		 time_t lastmod)
{
  assert(0 != gline);

  gline->gl_flags &= ~GLINE_ACTIVE;
  gline->gl_lastmod = lastmod;

  /* Inform ops and log it */
  sendto_op_mask(SNO_GLINE, "%s deactivating %s %s for %s%s%s, expiring at "
		 TIME_T_FMT ": %s",
		 IsServer(sptr) ? sptr->name : sptr->user->server->name,
		 GlineIsLocal(gline) ? "local" : "global",
		 GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
		 gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
		 GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
		 gline->gl_reason);

#ifdef GPATH
  if (IsServer(sptr))
    write_log(GPATH, "# " TIME_T_FMT " %s deactivating %s %s for %s%s%s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      GlineIsLocal(gline) ? "local" : "global",
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
	      gline->gl_reason);
  else
    write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s deactivating %s %s for "
	      "%s%s%s, expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host,
	      GlineIsLocal(gline) ? "local" : "global",
	      GlineIsBadChan(gline) ? "BADCHAN" : "GLINE",
	      gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	      GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
	      gline->gl_reason);
#endif /* GPATH */

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

      if (gline->gl_expire <= TStime())
	gline_free(gline);
      else if (match(gline->gl_user, userhost) == 0)
	return gline;
    }
  }

  if ((flags & (GLINE_BADCHAN | GLINE_ANY)) == GLINE_BADCHAN)
    return 0;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &user, &host, 0);

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= TStime())
      gline_free(gline);
    else if (match(gline->host, host) == 0 &&
	     ((!user && ircd_strcmp(gline->user, "*") == 0) ||
	      match(gline->user, user) == 0))
      break;
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

    if (gline->gl_expire <= TStime())
      gline_free(gline);
    else if ((GlineIsIpMask(gline) ?
	      match(gline->gl_host, cptr->sock_ip) :
	      match(gline->gl_host, cptr->sockhost)) == 0 &&
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

    if (gline->gl_expire <= TStime()) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendto_one(cptr, "%s " TOK_GLINE " * %c%s@%s " TIME_T_FMT " " TIME_T_FMT
		 " :%s", NumServ(&me), GlineIsActive(gline) ? '+' : '-',
		 gline->gl_user, gline->gl_host, gline->gl_expire - TStime(),
		 gline->gl_lastmod, gline->gl_reason);
  }

  for (gline = BadChanGlineList; gline; gline = sgline) { /* all glines */
    sgline = gline->gl_next;

    if (gline->gl_expire <= TStime()) /* expire any that need expiring */
      gline_free(gline);
    else if (!GlineIsLocal(gline) && gline->gl_lastmod)
      sendto_one(cptr, "%s " TOK_GLINE " * %c%s " TIME_T_FMT " " TIME_T_FMT
		 " :%s", NumServ(&me), GlineIsActive(gline) ? '+' : '-',
		 gline->gl_user, gline->gl_expire - TStime(),
		 gline->gl_lastmod, gline->gl_reason);
  }
}

int
gline_resend(struct Client *cptr, struct Gline *gline)
{
  if (GlineIsLocal(gline) || !gline->gl_lastmod)
    return 0;

  sendto_one(cptr, "%s " TOK_GLINE " * %c%s%s%s " TIME_T_FMT " " TIME_T_FMT
	     " :%s", NumServ(&me), GlineIsActive(gline) ? '+' : '-',
	     gline->gl_user, GlineIsBadChan(gline) ? "" : "@",
	     GlineIsBadChan(gline) ? "" : gline->gl_host,
	     gline->gl_expire - TStime(), gline->gl_lastmod, gline->gl_reason);

  return 0;
}

int
gline_list(struct Client *sptr, char *userhost)
{
  struct Gline *gline;
  struct Gline *sgline;

  if (userhost) {
    if (!(gline = gline_find(userhost, GLINE_ANY))) { /* no such gline */
      send_error_to_client(sptr, ERR_NOSUCHGLINE, userhost);
      return 0;
    }

    /* send gline information along */
    sendto_one(sptr, rpl_str(GLIST), me.name, sptr->name, gline->gl_user,
	       GlineIsBadChan(gline) ? "" : "@",
	       GlineIsBadChan(gline) ? "" : gline->gl_host, gline->gl_expire,
	       GlineIsLocal(gline) ? me.name : "*",
	       GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
  } else {
    for (gline = GlobalGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= TStime())
	gline_free(gline);
      else
	sendto_one(sptr, rpl_str(GLIST), me.name, sptr->name, gline->gl_user,
		   "@", gline->gl_host, gline->gl_expire,
		   GlineIsLocal(gline) ? me.name : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }

    for (gline = BadChanGlineList; gline; gline = sgline) {
      sgline = gline->gl_next;

      if (gline->gl_expire <= TStime())
	gline_free(gline);
      else
	sendto_one(sptr, rpl_str(GLIST), me.name, sptr->name, gline->gl_user,
		   "", "", gline->gl_expire,
		   GlineIsLocal(gline) ? me.name : "*",
		   GlineIsActive(gline) ? '+' : '-', gline->gl_reason);
    }
  }

  /* end of gline information */
  sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, sptr->name);
  return 0;
}

void
gline_stats(struct Client *sptr)
{
  struct Gline *gline;
  struct Gline *sgline;

  for (gline = GlobalGlineList; gline; gline = sgline) {
    sgline = gline->gl_next;

    if (gline->gl_expire <= TStime())
      gline_free(gline);
    else
      sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name, sptr->name, 'G',
		 gline->gl_user, gline->gl_host, gline->gl_expire,
		 gline->gl_reason);
  }
}


#if 0 /* forget about it! */
struct Gline *make_gline(int is_ipmask, char *host, char *reason,
                         char *name, time_t expire)
{
  struct Gline *agline;

#ifdef BADCHAN
  int gtype = 0;
  if ('#' == *host || '&' == *host || '+' == *host)
    gtype = 1; /* BAD CHANNEL GLINE */
#endif

  agline = (struct Gline*) MyMalloc(sizeof(struct Gline)); /* alloc memory */
  assert(0 != agline);
  DupString(agline->host, host);        /* copy vital information */
  DupString(agline->reason, reason);
  DupString(agline->name, name);
  agline->expire = expire;
  agline->gflags = GLINE_ACTIVE;        /* gline is active */
  if (is_ipmask)
    SetGlineIsIpMask(agline);
#ifdef BADCHAN
  if (gtype)
  { 
    agline->next = BadChanGlineList;    /* link it into the list */
    return (BadChanGlineList = agline);
  }
#endif
  agline->next = GlobalGlineList;       /* link it into the list */
  return (GlobalGlineList = agline);
}

struct Gline *find_gline(struct Client *cptr, struct Gline **pgline)
{
  struct Gline* gline = GlobalGlineList;
  struct Gline* prev = 0;

  while (gline) {
    /*
     * look through all glines
     */
    if (gline->expire <= TStime()) {
      /*
       * handle expired glines
       */
      free_gline(gline, prev);
      gline = prev ? prev->next : GlobalGlineList;
      if (!gline)
        break;                  /* gline == NULL means gline == NULL */
      continue;
    }

    /* Does gline match? */
    /* Added a check against the user's IP address as well -Kev */
    if ((GlineIsIpMask(gline) ?
        match(gline->host, ircd_ntoa((const char*) &cptr->ip)) :
        match(gline->host, cptr->sockhost)) == 0 &&
        match(gline->name, cptr->user->username) == 0) {
      if (pgline)
        *pgline = prev; /* If they need it, give them the previous gline
                                   entry (probably for free_gline, below) */
      return gline;
    }

    prev = gline;
    gline = gline->next;
  }

  return 0;                  /* found no glines */
}

void free_gline(struct Gline* gline, struct Gline* prev)
{
  assert(0 != gline);
  if (prev)
    prev->next = gline->next;   /* squeeze agline out */
  else { 
#ifdef BADCHAN
    assert(0 != gline->host);
    if ('#' == *gline->host ||
        '&' == *gline->host ||
        '+' == *gline->host) {
      BadChanGlineList = gline->next;
    }
    else
#endif
      GlobalGlineList = gline->next;
  }

  MyFree(gline->host);  /* and free up the memory */
  MyFree(gline->reason);
  MyFree(gline->name);
  MyFree(gline);
}

void gline_remove_expired(time_t now)
{
  struct Gline* gline;
  struct Gline* prev = 0;
  
  for (gline = GlobalGlineList; gline; gline = gline->next) {
    if (gline->expire < now) {
      free_gline(gline, prev);
      gline = (prev) ? prev : GlobalGlineList;
      if (!gline)
        break;
      continue;
    }
    prev = gline;
  }
}

#ifdef BADCHAN
int bad_channel(const char* name)
{ 
  struct Gline* agline = BadChanGlineList;

  while (agline)
  { 
    if ((agline->gflags & GLINE_ACTIVE) && (agline->expire > TStime()) && 
         !mmatch(agline->host, name)) { 
      return 1;
    }
    agline = agline->next;
  }
  return 0;
}

void bad_channel_remove_expired(time_t now)
{
  struct Gline* gline;
  struct Gline* prev = 0;
  
  for (gline = BadChanGlineList; gline; gline = gline->next) {
    if (gline->expire < now) {
      free_gline(gline, prev);
      gline = (prev) ? prev : BadChanGlineList;
      if (!gline)
        break;
      continue;
    }
    prev = gline;
  }
}

#endif


void add_gline(struct Client *sptr, int ip_mask, char *host, char *comment,
               char *user, time_t expire, int local)
{
  struct Client *acptr;
  struct Gline *agline;
  int fd;
  int gtype = 0;
  assert(0 != host);

#ifdef BADCHAN
  if ('#' == *host || '&' == *host || '+' == *host)
    gtype = 1;   /* BAD CHANNEL */
#endif

  /* Inform ops */
  sendto_op_mask(SNO_GLINE,
      "%s adding %s%s for %s@%s, expiring at " TIME_T_FMT ": %s", sptr->name,
      local ? "local " : "",
      gtype ? "BADCHAN" : "GLINE", user, host, expire, comment);

#ifdef GPATH
  write_log(GPATH,
      "# " TIME_T_FMT " %s adding %s %s for %s@%s, expiring at " TIME_T_FMT
      ": %s\n", TStime(), sptr->name, local ? "local" : "global",
      gtype ? "BADCHAN" : "GLINE", user, host, expire, comment);

  /* this can be inserted into the conf */
  if (!gtype)
    write_log(GPATH, "%c:%s:%s:%s\n", ip_mask ? 'k' : 'K', host, comment, 
      user);
#endif /* GPATH */

  agline = make_gline(ip_mask, host, comment, user, expire);
  if (local)
    SetGlineIsLocal(agline);

#ifdef BADCHAN
  if (gtype)
    return;
#endif

  for (fd = HighestFd; fd >= 0; --fd) { 
    /*
     * get the users!
     */ 
    if ((acptr = LocalClientArray[fd])) {
      if (!acptr->user)
        continue;
#if 0
      /*
       * whee!! :)
       */
      if (!acptr->user || strlen(acptr->sockhost) > HOSTLEN ||
          (acptr->user->username ? strlen(acptr->user->username) : 0) > HOSTLEN)
        continue;               /* these tests right out of
                                   find_kill for safety's sake */
#endif

      if ((GlineIsIpMask(agline) ?  match(agline->host, acptr->sock_ip) :
          match(agline->host, acptr->sockhost)) == 0 &&
          (!acptr->user->username ||
          match(agline->name, acptr->user->username) == 0))
      {

        /* ok, he was the one that got G-lined */
        sendto_one(acptr, ":%s %d %s :*** %s.", me.name,
            ERR_YOUREBANNEDCREEP, acptr->name, agline->reason);

        /* let the ops know about my first kill */
        sendto_op_mask(SNO_GLINE, "G-line active for %s",
            get_client_name(acptr, FALSE));

        /* and get rid of him */
        if (sptr != acptr)
          exit_client_msg(sptr->from, acptr, &me, "G-lined (%s)", agline->reason);
      }
    }
  }
}

#endif /* 0 */
