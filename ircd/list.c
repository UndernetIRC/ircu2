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
#include "config.h"

#include "list.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "listener.h"
#include "match.h"
#include "numeric.h"
#include "res.h"
#include "s_auth.h"
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
} clients, connections, users, servs, links;
#endif

static unsigned int clientAllocCount;
static struct Client* clientFreeList;

static unsigned int connectionAllocCount;
static struct Connection* connectionFreeList;

static unsigned int slinkAllocCount;
static struct SLink* slinkFreeList;

void init_list(void)
{
  struct Client* cptr;
  struct Connection* con;
  int i;
  /*
   * pre-allocate MAXCONNECTIONS clients and connections
   */
  for (i = 0; i < MAXCONNECTIONS; ++i) {
    cptr = (struct Client*) MyMalloc(sizeof(struct Client));
    cli_next(cptr) = clientFreeList;
    clientFreeList = cptr;
    ++clientAllocCount;

    con = (struct Connection*) MyMalloc(sizeof(struct Connection));
    con_next(con) = connectionFreeList;
    connectionFreeList = con;
    ++connectionAllocCount;
  }

#ifdef DEBUGMODE
  memset(&clients, 0, sizeof(clients));
  memset(&connections, 0, sizeof(connections));
  memset(&users, 0, sizeof(users));
  memset(&servs, 0, sizeof(servs));
  memset(&links, 0, sizeof(links));
#endif
}

static struct Client* alloc_client(void)
{
  struct Client* cptr = clientFreeList;

  if (!cptr) {
    cptr = (struct Client*) MyMalloc(sizeof(struct Client));
    ++clientAllocCount;
  } else
    clientFreeList = cli_next(cptr);

#ifdef DEBUGMODE
  clients.inuse++;
#endif

  memset(cptr, 0, sizeof(struct Client));

  return cptr;
}

static void dealloc_client(struct Client* cptr)
{
  assert(cli_verify(cptr));
  assert(0 == cli_connect(cptr));

#ifdef DEBUGMODE
  --clients.inuse;
#endif

  cli_next(cptr) = clientFreeList;
  clientFreeList = cptr;

  cli_magic(cptr) = 0;
}

static struct Connection* alloc_connection(void)
{
  struct Connection* con = connectionFreeList;

  if (!con) {
    con = (struct Connection*) MyMalloc(sizeof(struct Connection));
    ++connectionAllocCount;
  } else
    connectionFreeList = con_next(con);

#ifdef DEBUGMODE
  connections.inuse++;
#endif

  memset(con, 0, sizeof(struct Connection));
  timer_init(&(con_proc(con)));

  return con;
}

static void dealloc_connection(struct Connection* con)
{
  assert(con_verify(con));
  assert(!t_active(&(con_proc(con))));
  assert(!t_onqueue(&(con_proc(con))));

  Debug((DEBUG_LIST, "Deallocating connection %p", con));

  if (con_dns_reply(con))
    --(con_dns_reply(con)->ref_count);
  if (-1 < con_fd(con))
    close(con_fd(con));
  MsgQClear(&(con_sendQ(con)));
  client_drop_sendq(con);
  DBufClear(&(con_recvQ(con)));
  if (con_listener(con))
    release_listener(con_listener(con));

#ifdef DEBUGMODE
  --connections.inuse;
#endif

  con_next(con) = connectionFreeList;
  connectionFreeList = con;

  con_magic(con) = 0;
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
  struct Connection* con = 0;

  assert(!from || cli_verify(from));

  cptr = alloc_client();

  assert(0 != cptr);
  assert(!cli_magic(cptr));
  assert(0 == from || 0 != cli_connect(from));

  if (!from) { /* local client, allocate a struct Connection */
    con = alloc_connection();

    assert(0 != con);
    assert(!con_magic(con));

    con_magic(con) = CONNECTION_MAGIC;
    con_fd(con) = -1; /* initialize struct Connection */
    con_freeflag(con) = 0;
    con_nextnick(con) = CurrentTime - NICK_DELAY;
    con_nexttarget(con) = CurrentTime - (TARGET_DELAY * (STARTTARGETS - 1));
    con_handler(con) = UNREGISTERED_HANDLER;
    con_client(con) = cptr;

    cli_local(cptr) = 1; /* Set certain fields of the struct Client */
    cli_since(cptr) = cli_lasttime(cptr) = cli_firsttime(cptr) = CurrentTime;
    cli_lastnick(cptr) = TStime();
  } else
    con = cli_connect(from); /* use 'from's connection */

  assert(0 != con);
  assert(con_verify(con));

  cli_magic(cptr) = CLIENT_MAGIC;
  cli_connect(cptr) = con; /* set the connection and other fields */
  cli_status(cptr) = status;
  cli_hnext(cptr) = cptr;
  strcpy(cli_username(cptr), "unknown");

  return cptr;
}

void free_connection(struct Connection* con)
{
  if (!con)
    return;

  assert(con_verify(con));
  assert(0 == con_client(con));

  dealloc_connection(con); /* deallocate the connection */
}

void free_client(struct Client* cptr)
{
  if (!cptr)
    return;
  /*
   * forget to remove the client from the hash table?
   */
  assert(cli_verify(cptr));
  assert(cli_hnext(cptr) == cptr);
  /* or from linked list? */
  assert(cli_next(cptr) == 0);
  assert(cli_prev(cptr) == 0);

  Debug((DEBUG_LIST, "Freeing client %s [%p], connection %p", cli_name(cptr),
	 cptr, cli_connect(cptr)));

  if (cli_auth(cptr))
    destroy_auth_request(cli_auth(cptr), 0);

  /* Make sure we didn't magically get re-added to the list */
  assert(cli_next(cptr) == 0);
  assert(cli_prev(cptr) == 0);

  if (cli_from(cptr) == cptr) { /* in other words, we're local */
    cli_from(cptr) = 0;
    /* timer must be marked as not active */
    if (!cli_freeflag(cptr) && !t_active(&(cli_proc(cptr))))
      dealloc_connection(cli_connect(cptr)); /* connection not open anymore */
    else {
      if (-1 < cli_fd(cptr) && cli_freeflag(cptr) & FREEFLAG_SOCKET)
	socket_del(&(cli_socket(cptr))); /* queue a socket delete */
      if (cli_freeflag(cptr) & FREEFLAG_TIMER)
	timer_del(&(cli_proc(cptr))); /* queue a timer delete */
    }
  }

  cli_connect(cptr) = 0;

  dealloc_client(cptr); /* actually destroy the client */
}

struct Server *make_server(struct Client *cptr)
{
  struct Server *serv = cli_serv(cptr);

  assert(cli_verify(cptr));

  if (!serv)
  {
    serv = (struct Server*) MyMalloc(sizeof(struct Server));
    assert(0 != serv);
    memset(serv, 0, sizeof(struct Server)); /* All variables are 0 by default */
#ifdef  DEBUGMODE
    servs.inuse++;
#endif
    cli_serv(cptr) = serv;
    cli_serv(cptr)->lag = 60000;
    *serv->by = '\0';
    DupString(serv->last_error_msg, "<>");      /* String must be non-empty */
  }
  return cli_serv(cptr);
}

/*
 * Taken the code from ExitOneClient() for this and placed it here.
 * - avalon
 */
void remove_client_from_list(struct Client *cptr)
{
  assert(cli_verify(cptr));
  assert(con_verify(cli_connect(cptr)));
  assert(!cli_prev(cptr) || cli_verify(cli_prev(cptr)));
  assert(!cli_next(cptr) || cli_verify(cli_next(cptr)));
  assert(!IsMe(cptr));

  /* Only remove from the list if it actually IS in the list.
   * cli_next(cptr) cannot be NULL here if cptr is in the list,
   * only &me is at the end, and we never try to remove &me  -GW 
   */ 
  if(cli_next(cptr))
  {
    if (cli_prev(cptr))
      cli_next(cli_prev(cptr)) = cli_next(cptr);
    else {
      GlobalClientList = cli_next(cptr);
      cli_prev(GlobalClientList) = 0;
    }
    cli_prev(cli_next(cptr)) = cli_prev(cptr);
  }
  cli_next(cptr) = cli_prev(cptr) = 0;

  if (IsUser(cptr) && cli_user(cptr)) {
    add_history(cptr, 0);
    off_history(cptr);
  }
  if (cli_user(cptr)) {
    free_user(cli_user(cptr));
    cli_user(cptr) = 0;
  }

  if (cli_serv(cptr)) {
    if (cli_serv(cptr)->user) {
      free_user(cli_serv(cptr)->user);
      cli_serv(cptr)->user = 0;
    }
    if (cli_serv(cptr)->client_list)
      MyFree(cli_serv(cptr)->client_list);
    MyFree(cli_serv(cptr)->last_error_msg);
    MyFree(cli_serv(cptr));
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
  assert(cli_verify(cptr));
  assert(cli_next(cptr) == 0);
  assert(cli_prev(cptr) == 0);

  /*
   * Since we always insert new clients to the top of the list,
   * this should mean the "me" is the bottom most item in the list.
   * XXX - don't always count on the above, things change
   */
  cli_prev(cptr) = 0;
  cli_next(cptr) = GlobalClientList;
  GlobalClientList = cptr;
  if (cli_next(cptr))
    cli_prev(cli_next(cptr)) = cptr;
}

#if 0
/* WARNING: Major CPU sink!
 *
 * This is a debugging routine meant to verify the integrity of the client
 * linked list.  It is meant to be comprehensive, to detect *any* corruption
 * of that list.  This means that it will be majorly CPU-intensive, and
 * should *only* be enabled on servers that have DEBUGMODE enabled.  Ignore
 * this warning at your peril!
 */
void verify_client_list(void)
{
  struct Client *client, *prev = 0, *sentinel = 0;
  extern unsigned int ircrandom(void);

  for (client = GlobalClientList; client; client = cli_next(client)) {
    /* Verify that this is a valid client, not a free'd one */
    assert(cli_verify(client));
    /* Verify that the list hasn't suddenly jumped around */
    assert(cli_prev(client) == prev);
    /* Verify that the list hasn't become circular */
    assert(cli_next(client) != GlobalClientList);
    assert(!sentinel || client != sentinel);

    prev = client; /* Remember what should preceed us */
    if (!(ircrandom() % 50)) /* probabilistic loop detector */
      sentinel = client;
  }
}
#endif /* DEBUGMODE */

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

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Clients: inuse: %d(%d)",
	     clients.inuse, tmp = clients.inuse * sizeof(struct Client));
  mem += tmp;
  inuse += clients.inuse;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, "Connections: inuse: %d(%d)",
	     connections.inuse,
	     tmp = connections.inuse * sizeof(struct Connection));
  mem += tmp;
  inuse += connections.inuse;
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
