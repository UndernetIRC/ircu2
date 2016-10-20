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
/** @file
 * @brief Singly and doubly linked list manipulation implementation.
 * @version $Id$
 */
#include "config.h"

#include "list.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_log.h"
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
#include "whowas.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stddef.h>  /* offsetof */
#include <unistd.h>  /* close */
#include <string.h>

/** Stores linked list statistics for various types of lists. */
static struct liststats {
  size_t alloc; /**< Number of structures ever allocated. */
  size_t inuse; /**< Number of structures currently in use. */
  size_t mem;   /**< Memory used by in-use structures. */
} clients, connections, servs, links;

/** Linked list of currently unused Client structures. */
static struct Client* clientFreeList;

/** Linked list of currently unused Connection structures. */
static struct Connection* connectionFreeList;

/** Linked list of currently unused SLink structures. */
static struct SLink* slinkFreeList;

/** Initialize the list manipulation support system.
 * Pre-allocate MAXCONNECTIONS Client and Connection structures.
 */
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
    clients.alloc++;

    con = (struct Connection*) MyMalloc(sizeof(struct Connection));
    con_next(con) = connectionFreeList;
    connectionFreeList = con;
    connections.alloc++;
  }
}

/** Allocate a new Client structure.
 * If #clientFreeList != NULL, use the head of that list.
 * Otherwise, allocate a new structure.
 * @return Newly allocated Client.
 */
static struct Client* alloc_client(void)
{
  struct Client* cptr = clientFreeList;

  if (!cptr) {
    cptr = (struct Client*) MyMalloc(sizeof(struct Client));
    clients.alloc++;
  } else
    clientFreeList = cli_next(cptr);

  clients.inuse++;

  memset(cptr, 0, sizeof(struct Client));

  return cptr;
}

/** Release a Client structure by prepending it to #clientFreeList.
 * @param[in] cptr Client that is no longer being used.
 */
static void dealloc_client(struct Client* cptr)
{
  assert(cli_verify(cptr));
  assert(0 == cli_connect(cptr));

  --clients.inuse;

  cli_next(cptr) = clientFreeList;
  clientFreeList = cptr;

  cli_magic(cptr) = 0;
}

/** Allocate a new Connection structure.
 * If #connectionFreeList != NULL, use the head of that list.
 * Otherwise, allocate a new structure.
 * @return Newly allocated Connection.
 */
static struct Connection* alloc_connection(void)
{
  struct Connection* con = connectionFreeList;

  if (!con) {
    con = (struct Connection*) MyMalloc(sizeof(struct Connection));
    connections.alloc++;
  } else
    connectionFreeList = con_next(con);

  connections.inuse++;

  memset(con, 0, sizeof(struct Connection));
  timer_init(&(con_proc(con)));

  return con;
}

/** Release a Connection and all memory associated with it.
 * The connection's DNS reply field is freed, its file descriptor is
 * closed, its msgq and sendq are cleared, and its associated Listener
 * is dereferenced.  Then it is prepended to #connectionFreeList.
 * @param[in] con Connection to free.
 */
static void dealloc_connection(struct Connection* con)
{
  assert(con_verify(con));
  assert(!t_active(&(con_proc(con))));
  assert(!t_onqueue(&(con_proc(con))));

  Debug((DEBUG_LIST, "Deallocating connection %p", con));

  if (-1 < con_fd(con))
    close(con_fd(con));
  MsgQClear(&(con_sendQ(con)));
  client_drop_sendq(con);
  DBufClear(&(con_recvQ(con)));
  if (con_listener(con))
    release_listener(con_listener(con));

  --connections.inuse;

  con_next(con) = connectionFreeList;
  connectionFreeList = con;

  con_magic(con) = 0;
}

/** Allocate a new client and initialize it.
 * If \a from == NULL, initialize the fields for a local client,
 * including allocating a Connection for him; otherwise initialize the
 * fields for a remote client..
 * @param[in] from Server connection that introduced the client (or
 * NULL).
 * @param[in] status Initial Client::cli_status value.
 * @return Newly allocated and initialized Client.
 */
struct Client* make_client(struct Client *from, int status)
{
  struct Client* cptr = 0;

  assert(!from || cli_verify(from));

  cptr = alloc_client();

  assert(0 != cptr);
  assert(!cli_magic(cptr));
  assert(0 == from || 0 != cli_connect(from));

  if (!from) { /* local client, allocate a struct Connection */
    struct Connection *con = alloc_connection();

    assert(0 != con);
    assert(!con_magic(con));

    con_magic(con) = CONNECTION_MAGIC;
    con_fd(con) = -1; /* initialize struct Connection */
    con_freeflag(con) = 0;
    con_nextnick(con) = CurrentTime - NICK_DELAY;
    con_nexttarget(con) = CurrentTime - (TARGET_DELAY * (STARTTARGETS - 1));
    con_handler(con) = UNREGISTERED_HANDLER;
    con_client(con) = cptr;

    cli_connect(cptr) = con; /* set the connection and other fields */
    cli_since(cptr) = cli_lasttime(cptr) = cli_firsttime(cptr) = CurrentTime;
    cli_lastnick(cptr) = TStime();
  } else
    cli_connect(cptr) = cli_connect(from); /* use 'from's connection */

  assert(con_verify(cli_connect(cptr)));

  cli_magic(cptr) = CLIENT_MAGIC;
  cli_status(cptr) = status;
  cli_hnext(cptr) = cptr;
  strcpy(cli_username(cptr), "");

  return cptr;
}

/** Release a Connection.
 * @param[in] con Connection to free.
 */
void free_connection(struct Connection* con)
{
  if (!con)
    return;

  assert(con_verify(con));
  assert(0 == con_client(con));

  dealloc_connection(con); /* deallocate the connection */
}

/** Release a Client.
 * In addition to the cleanup done by dealloc_client(), this will free
 * any pending auth request, free the connection for local clients,
 * and delete the processing timer for the client.
 * @param[in] cptr Client to free.
 */
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
    destroy_auth_request(cli_auth(cptr));

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

/** Allocate a new Server object for a client.
 * If Client::cli_serv == NULL, allocate a Server structure for it and
 * initialize it.
 * @param[in] cptr %Client to make into a server.
 * @return The value of cli_serv(\a cptr).
 */
struct Server *make_server(struct Client *cptr)
{
  struct Server *serv = cli_serv(cptr);

  assert(cli_verify(cptr));

  if (!serv)
  {
    serv = (struct Server*) MyMalloc(sizeof(struct Server));
    assert(0 != serv);
    memset(serv, 0, sizeof(struct Server)); /* All variables are 0 by default */
    servs.inuse++;
    servs.alloc++;
    cli_serv(cptr) = serv;
    cli_serv(cptr)->lag = 60000;
    *serv->by = '\0';
    DupString(serv->last_error_msg, "<>");      /* String must be non-empty */
  }
  return cli_serv(cptr);
}

/** Remove \a cptr from lists that it is a member of.
 * Specifically, this delinks \a cptr from #GlobalClientList, updates
 * the whowas history list, frees its Client::cli_user and
 * Client::cli_serv fields, and finally calls free_client() on it.
 * @param[in] cptr Client to remove from lists and free.
 */
void remove_client_from_list(struct Client *cptr)
{
  assert(cli_verify(cptr));
  assert(con_verify(cli_connect(cptr)));
  assert(!cli_prev(cptr) || cli_verify(cli_prev(cptr)));
  assert(!cli_next(cptr) || cli_verify(cli_next(cptr)));
  assert(!IsMe(cptr));

  /* Only try remove cptr from the list if it IS in the list.
   * cli_next(cptr) cannot be NULL here, as &me is always the end
   * the list, and we never remove &me.    -GW 
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
    --servs.inuse;
    --servs.alloc;
  }
  free_client(cptr);
}

/** Link \a cptr into #GlobalClientList.
 * @param[in] cptr Client to link into the global list.
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
/** Perform a very CPU-intensive verification of %GlobalClientList.
 * This checks the Client::cli_magic and Client::cli_prev field for
 * each element in the list, and also checks that there are no loops.
 * Any detected error will lead to an assertion failure.
 */
void verify_client_list(void)
{
  struct Client *client, *prev = 0;
  unsigned int visited = 0;

  for (client = GlobalClientList; client; client = cli_next(client), ++visited) {
    /* Verify that this is a valid client, not a free'd one */
    assert(cli_verify(client));
    /* Verify that the list hasn't suddenly jumped around */
    assert(cli_prev(client) == prev);
    /* Verify that the list hasn't become circular */
    assert(cli_next(client) != GlobalClientList);
    assert(visited <= clients.alloc);
    /* Remember what should precede us */
    prev = client;
  }
}
#endif /* DEBUGMODE */

/** Allocate a new SLink element.
 * Pulls from #slinkFreeList if it contains anything, else it
 * allocates a new one from the heap.
 * @return Newly allocated list element.
 */
struct SLink* make_link(void)
{
  struct SLink* lp = slinkFreeList;
  if (lp)
    slinkFreeList = lp->next;
  else {
    lp = (struct SLink*) MyMalloc(sizeof(struct SLink));
    links.alloc++;
  }
  assert(0 != lp);
  links.inuse++;
  memset(lp, 0, sizeof(*lp));
  return lp;
}

/** Release a singly linked list element.
 * @param[in] lp List element to mark as unused.
 */
void free_link(struct SLink* lp)
{
  if (lp) {
    lp->next = slinkFreeList;
    slinkFreeList = lp;
    links.inuse--;
  }
}

/** Add an element to a doubly linked list.
 * If \a lpp points to a non-NULL pointer, its DLink::prev field is
 * updated to point to the newly allocated element.  Regardless,
 * \a lpp is overwritten with the pointer to the new link.
 * @param[in,out] lpp Pointer to insertion location.
 * @param[in] cp %Client to put in newly allocated element.
 * @return Allocated link structure (same as \a lpp on output).
 */
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

/** Remove a node from a doubly linked list.
 * @param[out] lpp Pointer to next list element.
 * @param[in] lp List node to unlink.
 */
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

/** Report memory usage of a list to \a cptr.
 * @param[in] cptr Client requesting information.
 * @param[in] lstats List statistics descriptor.
 * @param[in] itemname Plural name of item type.
 * @param[in,out] totals If non-null, accumulates item counts and memory usage.
 */
void send_liststats(struct Client *cptr, const struct liststats *lstats,
                    const char *itemname, struct liststats *totals)
{
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":%s: inuse %zu(%zu) alloc %zu",
	     itemname, lstats->inuse, lstats->mem, lstats->alloc);
  if (totals)
  {
    totals->inuse += lstats->inuse;
    totals->alloc += lstats->alloc;
    totals->mem += lstats->mem;
  }
}

/** Report memory usage of list elements to \a cptr.
 * @param[in] cptr Client requesting information.
 * @param[in] name Unused pointer.
 */
void send_listinfo(struct Client *cptr, char *name)
{
  struct liststats total;
  struct liststats confs;
  struct ConfItem *conf;

  memset(&total, 0, sizeof(total));

  clients.mem = clients.inuse * sizeof(struct Client);
  send_liststats(cptr, &clients, "Clients", &total);

  connections.mem = connections.inuse * sizeof(struct Connection);
  send_liststats(cptr, &connections, "Connections", &total);

  servs.mem = servs.inuse * sizeof(struct Server);
  send_liststats(cptr, &servs, "Servers", &total);

  links.mem = links.inuse * sizeof(struct SLink);
  send_liststats(cptr, &links, "Links", &total);

  confs.alloc = GlobalConfCount;
  confs.mem = confs.alloc * sizeof(GlobalConfCount);
  for (confs.inuse = 0, conf = GlobalConfList; conf; conf = conf->next)
    confs.inuse++;
  send_liststats(cptr, &confs, "Confs", &total);

  send_liststats(cptr, &total, "Totals", NULL);
}
