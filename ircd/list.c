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
 *
 * $Id$
 */
#include "list.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "listener.h"
#include "match.h"
#include "numeric.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "whowas.h"

#include <assert.h>
#include <stddef.h>  /* offsetof */
#include <unistd.h>  /* close */
#include <string.h>

#ifdef DEBUGMODE
static struct liststats {
  int inuse;
} cloc, crem, users, servs, links;
#endif

static unsigned int localClientAllocCount;
static struct Client* localClientFreeList;

static unsigned int remoteClientAllocCount;
static struct Client* remoteClientFreeList;

static unsigned int slinkAllocCount;
static struct SLink* slinkFreeList;

void init_list(void)
{
  struct Client* cptr;
  int i;
  /*
   * pre-allocate MAXCONNECTIONS local clients
   */
  for (i = 0; i < MAXCONNECTIONS; ++i) {
    cptr = (struct Client*) MyMalloc(CLIENT_LOCAL_SIZE);
    cptr->next = localClientFreeList;
    localClientFreeList = cptr;
    ++localClientAllocCount;
  }

#ifdef DEBUGMODE
  memset(&cloc, 0, sizeof(cloc));
  memset(&crem, 0, sizeof(crem));
  memset(&users, 0, sizeof(users));
  memset(&servs, 0, sizeof(servs));
  memset(&links, 0, sizeof(links));
#endif
}

/*
 * Create a new struct Client structure and set it to initial state.
 *
 *   from == NULL,   create local client (a client connected to a socket).
 *
 *   from != NULL,   create remote client (behind a socket associated with
 *                   the client defined by 'from').
 *                   ('from' is a local client!!).
 */
struct Client* make_client(struct Client *from, int status)
{
  struct Client* cptr = 0;
  /*
   * Check freelists first to see if we can grab a client without
   * having to call malloc.
   */
  if (from) {
    /*
     * remote client
     */
    if ((cptr = remoteClientFreeList))
      remoteClientFreeList = cptr->next;
    else {
      cptr = (struct Client*) MyMalloc(CLIENT_REMOTE_SIZE);
      ++remoteClientAllocCount;
    }
    assert(0 != cptr);
    /*
     * NOTE: Do not remove this, a lot of code depends on the entire
     * structure being zeroed out
     */
    memset(cptr, 0, CLIENT_REMOTE_SIZE);        /* All variables are 0 by default */
    cptr->from = from;
  }
  else {
    /*
     * local client
     */
    if ((cptr = localClientFreeList))
      localClientFreeList = cptr->next;
    else {
      cptr = (struct Client*) MyMalloc(CLIENT_LOCAL_SIZE);
      ++localClientAllocCount;
    }
    assert(0 != cptr);
    /*
     * NOTE: Do not remove this, a lot of code depends on the entire
     * structure being zeroed out
     */
    memset(cptr, 0, CLIENT_LOCAL_SIZE);        /* All variables are 0 by default */
    cptr->fd = -1;
    cptr->local = 1;
    cptr->since = cptr->lasttime = cptr->firsttime = CurrentTime;
    cptr->lastnick = TStime();
    cptr->nextnick = CurrentTime - NICK_DELAY;
    cptr->nexttarget = CurrentTime - (TARGET_DELAY * (STARTTARGETS - 1));
    cptr->handler = UNREGISTERED_HANDLER;
    cptr->from = cptr;      /* 'from' of local client is self! */
  }
  cptr->status = status;
  cptr->hnext = cptr;
  strcpy(cptr->username, "unknown");

#ifdef  DEBUGMODE
  if (from)
    crem.inuse++;
  else
    cloc.inuse++;
#endif

  return cptr;
}

void free_client(struct Client* cptr)
{
  if (!cptr)
    return;
  /*
   * forget to remove the client from the hash table?
   */
  assert(cptr->hnext == cptr);

#ifdef  DEBUGMODE
  if (cptr->local)
    --cloc.inuse;
  else
    --crem.inuse;
#endif

  if (cptr->local) {
    /*
     * make sure we have cleaned up local resources
     */
    if (cptr->dns_reply)
      --cptr->dns_reply->ref_count;
    if (-1 < cptr->fd) {
      close(cptr->fd);
    }
    DBufClear(&cptr->sendQ);
    DBufClear(&cptr->recvQ);
    if (cptr->listener)
      release_listener(cptr->listener);
    cptr->next = localClientFreeList;
    localClientFreeList = cptr;
  }    
  else {
    cptr->next = remoteClientFreeList;
    remoteClientFreeList = cptr;
  }
}

struct Server *make_server(struct Client *cptr)
{
  struct Server *serv = cptr->serv;

  if (!serv)
  {
    serv = (struct Server*) MyMalloc(sizeof(struct Server));
    assert(0 != serv);
    memset(serv, 0, sizeof(struct Server)); /* All variables are 0 by default */
#ifdef  DEBUGMODE
    servs.inuse++;
#endif
    cptr->serv = serv;
    cptr->serv->lag = 60000;
    *serv->by = '\0';
    DupString(serv->last_error_msg, "<>");      /* String must be non-empty */
  }
  return cptr->serv;
}

/*
 * Taken the code from ExitOneClient() for this and placed it here.
 * - avalon
 */
void remove_client_from_list(struct Client *cptr)
{
  if (cptr->prev)
    cptr->prev->next = cptr->next;
  else {
    GlobalClientList = cptr->next;
    GlobalClientList->prev = 0;
  }
  if (cptr->next)
    cptr->next->prev = cptr->prev;

  cptr->next = cptr->prev = 0;

  if (IsUser(cptr) && cptr->user) {
    add_history(cptr, 0);
    off_history(cptr);
  }
  if (cptr->user) {
    free_user(cptr->user);
    cptr->user = 0;
  }

  if (cptr->serv) {
    if (cptr->serv->user) {
      free_user(cptr->serv->user);
      cptr->serv->user = 0;
    }
    if (cptr->serv->client_list)
      MyFree(cptr->serv->client_list);
    MyFree(cptr->serv->last_error_msg);
    MyFree(cptr->serv);
#ifdef  DEBUGMODE
    --servs.inuse;
#endif
  }
  free_client(cptr);
}

/*
 * Although only a small routine, it appears in a number of places
 * as a collection of a few lines...functions like this *should* be
 * in this file, shouldnt they ?  after all, this is list.c, isn't it ?
 * -avalon
 */
void add_client_to_list(struct Client *cptr)
{
  /*
   * Since we always insert new clients to the top of the list,
   * this should mean the "me" is the bottom most item in the list.
   * XXX - don't always count on the above, things change
   */
  cptr->prev = 0;
  cptr->next = GlobalClientList;
  GlobalClientList = cptr;
  if (cptr->next)
    cptr->next->prev = cptr;
}

/*
 * Look for ptr in the linked listed pointed to by link.
 */
struct SLink *find_user_link(struct SLink *lp, struct Client *ptr)
{
  if (ptr) {
    while (lp) {
      if (lp->value.cptr == ptr)
        return (lp);
      lp = lp->next;
    }
  }
  return NULL;
}

struct SLink* make_link(void)
{
  struct SLink* lp = slinkFreeList;
  if (lp)
    slinkFreeList = lp->next;
  else {
    lp = (struct SLink*) MyMalloc(sizeof(struct SLink));
    ++slinkAllocCount;
  }
  assert(0 != lp);
#ifdef  DEBUGMODE
  links.inuse++;
#endif
  return lp;
}

void free_link(struct SLink* lp)
{
  if (lp) {
    lp->next = slinkFreeList;
    slinkFreeList = lp;
  }
#ifdef  DEBUGMODE
  links.inuse--;
#endif
}

struct DLink *add_dlink(struct DLink **lpp, struct Client *cp)
{
  struct DLink* lp = (struct DLink*) MyMalloc(sizeof(struct DLink));
  assert(0 != lp);
  lp->value.cptr = cp;
  lp->prev = 0;
  if ((lp->next = *lpp))
    lp->next->prev = lp;
  *lpp = lp;
  return lp;
}

void remove_dlink(struct DLink **lpp, struct DLink *lp)
{
  assert(0 != lpp);
  assert(0 != lp);

  if (lp->prev) {
    if ((lp->prev->next = lp->next))
      lp->next->prev = lp->prev;
  }
  else if ((*lpp = lp->next))
    lp->next->prev = NULL;
  MyFree(lp);
}

#ifdef  DEBUGMODE
void send_listinfo(struct Client *cptr, char *name)
{
  int inuse = 0, mem = 0, tmp = 0;

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Local: inuse: %d(%d)",
	     inuse += cloc.inuse, tmp = cloc.inuse * CLIENT_LOCAL_SIZE);
  mem += tmp;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Remote: inuse: %d(%d)",
	     crem.inuse, tmp = crem.inuse * CLIENT_REMOTE_SIZE);
  mem += tmp;
  inuse += crem.inuse;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Users: inuse: %d(%d)",
	     users.inuse, tmp = users.inuse * sizeof(struct User));
  mem += tmp;
  inuse += users.inuse;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Servs: inuse: %d(%d)",
	     servs.inuse, tmp = servs.inuse * sizeof(struct Server));
  mem += tmp;
  inuse += servs.inuse;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Links: inuse: %d(%d)",
	     links.inuse, tmp = links.inuse * sizeof(struct SLink));
  mem += tmp;
  inuse += links.inuse;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Confs: inuse: %d(%d)",
	     GlobalConfCount, tmp = GlobalConfCount * sizeof(struct ConfItem));
  mem += tmp;
  inuse += GlobalConfCount;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Totals: inuse %d %d",
	     inuse, mem);
}

#endif
