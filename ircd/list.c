/*
 * IRC - Internet Relay Chat, ircd/list.c
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
 */

#include "sys.h"
#include "h.h"
#include "struct.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "class.h"
#include "match.h"
#include "ircd.h"
#include "s_serv.h"
#include "support.h"
#include "s_misc.h"
#include "s_bsd.h"
#include "whowas.h"
#include "res.h"
#include "common.h"
#include "list.h"
#include "s_user.h"
#include "opercmds.h"

RCSTAG_CC("$Id$");

#ifdef DEBUGMODE
static struct liststats {
  int inuse;
} cloc, crem, users, servs, links, classs, aconfs;
#endif

void outofmemory();

#ifdef DEBUGMODE
void initlists(void)
{
  memset(&cloc, 0, sizeof(cloc));
  memset(&crem, 0, sizeof(crem));
  memset(&users, 0, sizeof(users));
  memset(&servs, 0, sizeof(servs));
  memset(&links, 0, sizeof(links));
  memset(&classs, 0, sizeof(classs));
  memset(&aconfs, 0, sizeof(aconfs));
}
#endif

void outofmemory(void)
{
  Debug((DEBUG_FATAL, "Out of memory: restarting server..."));
  restart("Out of Memory");
}

/*
 * Create a new aClient structure and set it to initial state.
 *
 *   from == NULL,   create local client (a client connected to a socket).
 *
 *   from != NULL,   create remote client (behind a socket associated with
 *                   the client defined by 'from').
 *                   ('from' is a local client!!).
 */
aClient *make_client(aClient *from, int status)
{
  Reg1 aClient *cptr = NULL;
  Reg2 size_t size = CLIENT_REMOTE_SIZE;

  /*
   * Check freelists first to see if we can grab a client without
   * having to call malloc.
   */
  if (!from)
    size = CLIENT_LOCAL_SIZE;

  if (!(cptr = (aClient *)RunMalloc(size)))
    outofmemory();
  memset(cptr, 0, size);	/* All variables are 0 by default */

#ifdef	DEBUGMODE
  if (size == CLIENT_LOCAL_SIZE)
    cloc.inuse++;
  else
    crem.inuse++;
#endif

  /* Note: structure is zero (memset) */
  cptr->from = from ? from : cptr;	/* 'from' of local client is self! */
  cptr->fd = -1;
  cptr->status = status;
  strcpy(cptr->username, "unknown");
  if (size == CLIENT_LOCAL_SIZE)
  {
    cptr->since = cptr->lasttime = cptr->firsttime = now;
    cptr->lastnick = TStime();
    cptr->nextnick = now - NICK_DELAY;
    cptr->nexttarget = now - (TARGET_DELAY * (STARTTARGETS - 1));
    cptr->authfd = -1;
  }
  return (cptr);
}

void free_client(aClient *cptr)
{
  RunFree(cptr);
}

/*
 * 'make_user' add's an User information block to a client
 * if it was not previously allocated.
 */
anUser *make_user(aClient *cptr)
{
  Reg1 anUser *user;

  user = cptr->user;
  if (!user)
  {
    if (!(user = (anUser *)RunMalloc(sizeof(anUser))))
      outofmemory();
    memset(user, 0, sizeof(anUser));	/* All variables are 0 by default */
#ifdef	DEBUGMODE
    users.inuse++;
#endif
    user->refcnt = 1;
    *user->host = 0;
    cptr->user = user;
  }
  return user;
}

aServer *make_server(aClient *cptr)
{
  Reg1 aServer *serv = cptr->serv;

  if (!serv)
  {
    if (!(serv = (aServer *)RunMalloc(sizeof(aServer))))
      outofmemory();
    memset(serv, 0, sizeof(aServer));	/* All variables are 0 by default */
#ifdef	DEBUGMODE
    servs.inuse++;
#endif
    cptr->serv = serv;
    *serv->by = '\0';
    DupString(serv->last_error_msg, "<>");	/* String must be non-empty */
  }
  return cptr->serv;
}

/*
 * free_user
 *
 * Decrease user reference count by one and realease block, if count reaches 0.
 */
void free_user(anUser *user, aClient *cptr)
{
  if (--user->refcnt == 0)
  {
    if (user->away)
      RunFree(user->away);
    /*
     * sanity check
     */
    if (user->joined || user->invited || user->channel)
#ifdef DEBUGMODE
      dumpcore("%p user (%s!%s@%s) %p %p %p %d %d",
	  cptr, cptr ? cptr->name : "<noname>",
	  user->username, user->host, user,
	  user->invited, user->channel, user->joined, user->refcnt);
#else
      sendto_ops("* %p user (%s!%s@%s) %p %p %p %d %d *",
	  cptr, cptr ? cptr->name : "<noname>",
	  user->username, user->host, user,
	  user->invited, user->channel, user->joined, user->refcnt);
#endif
    RunFree(user);
#ifdef	DEBUGMODE
    users.inuse--;
#endif
  }
}

/*
 * Taken the code from ExitOneClient() for this and placed it here.
 * - avalon
 */
void remove_client_from_list(aClient *cptr)
{
  checklist();
  if (cptr->prev)
    cptr->prev->next = cptr->next;
  else
  {
    client = cptr->next;
    client->prev = NULL;
  }
  if (cptr->next)
    cptr->next->prev = cptr->prev;
  if (IsUser(cptr) && cptr->user)
  {
    add_history(cptr, 0);
    off_history(cptr);
  }
  if (cptr->user)
    free_user(cptr->user, cptr);
  if (cptr->serv)
  {
    if (cptr->serv->user)
      free_user(cptr->serv->user, cptr);
    if (cptr->serv->client_list)
      RunFree(cptr->serv->client_list);
    RunFree(cptr->serv->last_error_msg);
    RunFree(cptr->serv);
#ifdef	DEBUGMODE
    servs.inuse--;
#endif
  }
#ifdef	DEBUGMODE
  if (cptr->fd == -2)
    cloc.inuse--;
  else
    crem.inuse--;
#endif
  free_client(cptr);
  return;
}

/*
 * Although only a small routine, it appears in a number of places
 * as a collection of a few lines...functions like this *should* be
 * in this file, shouldnt they ?  after all, this is list.c, isn't it ?
 * -avalon
 */
void add_client_to_list(aClient *cptr)
{
  /*
   * Since we always insert new clients to the top of the list,
   * this should mean the "me" is the bottom most item in the list.
   */
  cptr->next = client;
  client = cptr;
  if (cptr->next)
    cptr->next->prev = cptr;
  return;
}

/*
 * Look for ptr in the linked listed pointed to by link.
 */
Link *find_user_link(Link *lp, aClient *ptr)
{
  if (ptr)
    while (lp)
    {
      if (lp->value.cptr == ptr)
	return (lp);
      lp = lp->next;
    }
  return NULL;
}

Link *make_link(void)
{
  Reg1 Link *lp;

  lp = (Link *)RunMalloc(sizeof(Link));
#ifdef	DEBUGMODE
  links.inuse++;
#endif
  return lp;
}

void free_link(Link *lp)
{
  RunFree(lp);
#ifdef	DEBUGMODE
  links.inuse--;
#endif
}

Dlink *add_dlink(Dlink **lpp, aClient *cp)
{
  register Dlink *lp;
  lp = (Dlink *)RunMalloc(sizeof(Dlink));
  lp->value.cptr = cp;
  lp->prev = NULL;
  if ((lp->next = *lpp))
    lp->next->prev = lp;
  *lpp = lp;
  return lp;
}

void remove_dlink(Dlink **lpp, Dlink *lp)
{
  if (lp->prev)
  {
    if ((lp->prev->next = lp->next))
      lp->next->prev = lp->prev;
  }
  else if ((*lpp = lp->next))
    lp->next->prev = NULL;
  RunFree(lp);
}

aConfClass *make_class(void)
{
  Reg1 aConfClass *tmp;

  tmp = (aConfClass *) RunMalloc(sizeof(aConfClass));
#ifdef	DEBUGMODE
  classs.inuse++;
#endif
  return tmp;
}

void free_class(aConfClass * tmp)
{
  RunFree(tmp);
#ifdef	DEBUGMODE
  classs.inuse--;
#endif
}

aConfItem *make_conf(void)
{
  Reg1 aConfItem *aconf;

  aconf = (struct ConfItem *)RunMalloc(sizeof(aConfItem));
#ifdef	DEBUGMODE
  aconfs.inuse++;
#endif
  memset(&aconf->ipnum, 0, sizeof(struct in_addr));
  aconf->next = NULL;
  aconf->host = aconf->passwd = aconf->name = NULL;
  aconf->status = CONF_ILLEGAL;
  aconf->clients = 0;
  aconf->port = 0;
  aconf->hold = 0;
  aconf->confClass = NULL;
  return (aconf);
}

void delist_conf(aConfItem *aconf)
{
  if (aconf == conf)
    conf = conf->next;
  else
  {
    aConfItem *bconf;

    for (bconf = conf; aconf != bconf->next; bconf = bconf->next);
    bconf->next = aconf->next;
  }
  aconf->next = NULL;
}

void free_conf(aConfItem *aconf)
{
  del_queries((char *)aconf);
  RunFree(aconf->host);
  if (aconf->passwd)
    memset(aconf->passwd, 0, strlen(aconf->passwd));
  RunFree(aconf->passwd);
  RunFree(aconf->name);
  RunFree(aconf);
#ifdef	DEBUGMODE
  aconfs.inuse--;
#endif
  return;
}

aGline *make_gline(int is_ipmask, char *host, char *reason,
    char *name, time_t expire)
{
  Reg4 aGline *agline;
#ifdef BADCHAN
  int gtype=0;
  if(*host == '#' || *host == '&' || *host == '+') 
    gtype=1; /* BAD CHANNEL GLINE */
#endif

  agline = (struct Gline *)RunMalloc(sizeof(aGline));	/* alloc memory */
  DupString(agline->host, host);	/* copy vital information */
  DupString(agline->reason, reason);
  DupString(agline->name, name);
  agline->expire = expire;
  agline->gflags = GLINE_ACTIVE;	/* gline is active */
  if (is_ipmask)
    SetGlineIsIpMask(agline);

#ifdef BADCHAN
  if(gtype)
  { agline->next = badchan;		/* link it into the list */
    return (badchan = agline);
  }
#endif
  agline->next = gline;		/* link it into the list */
  return (gline = agline);
}

aGline *find_gline(aClient *cptr, aGline **pgline)
{
  Reg3 aGline *agline = gline, *a2gline = NULL;

  while (agline)
  {				/* look through all glines */
    if (agline->expire <= TStime())
    {				/* handle expired glines */
      free_gline(agline, a2gline);
      agline = a2gline ? a2gline->next : gline;
      if (!agline)
	break;			/* agline == NULL means gline == NULL */
      continue;
    }

    /* Does gline match? */
    /* Added a check against the user's IP address as well -Kev */
    if ((GlineIsIpMask(agline) ?
	match(agline->host, inetntoa(cptr->ip)) :
	match(agline->host, cptr->sockhost)) == 0 &&
	match(agline->name, cptr->user->username) == 0)
    {
      if (pgline)
	*pgline = a2gline;	/* If they need it, give them the previous gline
				   entry (probably for free_gline, below) */
      return agline;
    }

    a2gline = agline;
    agline = agline->next;
  }

  return NULL;			/* found no glines */
}

void free_gline(aGline *agline, aGline *pgline)
{
  if (pgline)
    pgline->next = agline->next;	/* squeeze agline out */
  else
  { 
#ifdef BADCHAN
    if(*agline->host =='#' || *agline->host == '&' || *agline->host == '+')
    {
      badchan = agline->next;
    }
    else
#endif
      gline = agline->next;
  }

  RunFree(agline->host);	/* and free up the memory */
  RunFree(agline->reason);
  RunFree(agline->name);
  RunFree(agline);
}

#ifdef BADCHAN
int bad_channel(char *name)
{ aGline *agline;

  agline=badchan;
  while(agline)
  { 
    if ((agline->gflags&GLINE_ACTIVE) && (agline->expire >TStime()) && 
         !mmatch(agline->host,name))
    { return 1;
    }
    agline=agline->next;
  }
  return 0;
}
#endif

#ifdef	DEBUGMODE
void send_listinfo(aClient *cptr, char *name)
{
  int inuse = 0, mem = 0, tmp = 0;

  sendto_one(cptr, ":%s %d %s :Local: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name, inuse += cloc.inuse,
      tmp = cloc.inuse * CLIENT_LOCAL_SIZE);
  mem += tmp;
  sendto_one(cptr, ":%s %d %s :Remote: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name,
      crem.inuse, tmp = crem.inuse * CLIENT_REMOTE_SIZE);
  mem += tmp;
  inuse += crem.inuse;
  sendto_one(cptr, ":%s %d %s :Users: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name, users.inuse,
      tmp = users.inuse * sizeof(anUser));
  mem += tmp;
  inuse += users.inuse,
      sendto_one(cptr, ":%s %d %s :Servs: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name, servs.inuse,
      tmp = servs.inuse * sizeof(aServer));
  mem += tmp;
  inuse += servs.inuse,
      sendto_one(cptr, ":%s %d %s :Links: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name, links.inuse,
      tmp = links.inuse * sizeof(Link));
  mem += tmp;
  inuse += links.inuse,
      sendto_one(cptr, ":%s %d %s :Classes: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name, classs.inuse,
      tmp = classs.inuse * sizeof(aConfClass));
  mem += tmp;
  inuse += classs.inuse,
      sendto_one(cptr, ":%s %d %s :Confs: inuse: %d(%d)",
      me.name, RPL_STATSDEBUG, name, aconfs.inuse,
      tmp = aconfs.inuse * sizeof(aConfItem));
  mem += tmp;
  inuse += aconfs.inuse,
      sendto_one(cptr, ":%s %d %s :Totals: inuse %d %d",
      me.name, RPL_STATSDEBUG, name, inuse, mem);
}

#endif
