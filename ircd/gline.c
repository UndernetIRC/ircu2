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
            get_client_name(acptr, SHOW_IP));

        /* and get rid of him */
        if (sptr != acptr)
          exit_client_msg(sptr->from, acptr, &me, "G-lined (%s)", agline->reason);
      }
    }
  }
}

