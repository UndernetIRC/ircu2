/*
 * IRC - Internet Relay Chat, ircd/class.c
 * Copyright (C) 1990 Darren Reed
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

#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "list.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

#include <assert.h>

#define BAD_CONF_CLASS          ((unsigned int)-1)
#define BAD_PING                ((unsigned int)-2)
#define BAD_CLIENT_CLASS        ((unsigned int)-3)

static struct ConnectionClass* connClassList = 0;
static unsigned int connClassAllocCount;

const struct ConnectionClass* get_class_list(void)
{
  return connClassList;
}

struct ConnectionClass* make_class(void)
{
  struct ConnectionClass *tmp;

  tmp = (struct ConnectionClass*) MyMalloc(sizeof(struct ConnectionClass));
  assert(0 != tmp);
  tmp->ref_count = 0;
  ++connClassAllocCount;
  return tmp;
}

void free_class(struct ConnectionClass* p)
{
  if (p) {
    assert(0 == p->valid);
    MyFree(p);
    --connClassAllocCount;
  }
}

/*
 * init_class - initialize the class list
 */
void init_class(void)
{
  if (!connClassList)
    connClassList = (struct ConnectionClass*) make_class();

  ConClass(connClassList) = 0;
  PingFreq(connClassList) = feature_int(FEAT_PINGFREQUENCY);
  ConFreq(connClassList)  = feature_int(FEAT_CONNECTFREQUENCY);
  MaxLinks(connClassList) = feature_int(FEAT_MAXIMUM_LINKS);
  MaxSendq(connClassList) = feature_int(FEAT_DEFAULTMAXSENDQLENGTH);
  connClassList->valid    = 1;
  Links(connClassList)    = 0;
  connClassList->next     = 0;
}

/*
 * class_mark_delete - mark classes for delete
 * We don't delete the class table, rather mark all entries
 * for deletion. The table is cleaned up by class_delete_marked(). - avalon
 * XXX - This destroys data
 */
void class_mark_delete(void)
{
  struct ConnectionClass* p;
  assert(0 != connClassList);

  for (p = connClassList->next; p; p = p->next)
    p->valid = 0;
}

/*
 * class_delete_marked
 * delete classes marked for deletion
 * XXX - memory leak, no one deletes classes that become unused
 * later
 */
void class_delete_marked(void)
{
  struct ConnectionClass* cl;
  struct ConnectionClass* prev;

  Debug((DEBUG_DEBUG, "Class check:"));

  for (prev = cl = connClassList; cl; cl = prev->next) {
    Debug((DEBUG_DEBUG, "Class %d : CF: %d PF: %d ML: %d LI: %d SQ: %d",
           ConClass(cl), ConFreq(cl), PingFreq(cl), MaxLinks(cl), Links(cl), MaxSendq(cl)));
    /*
     * unlink marked classes, delete unreferenced ones
     */
    if (cl->valid)
      prev = cl;
    else {
      prev->next = cl->next;
      if (0 == cl->ref_count)
        free_class(cl);
    }
  }
}

unsigned int get_conf_class(const struct ConfItem* aconf)
{
  if ((aconf) && (aconf->conn_class))
    return (ConfClass(aconf));

  Debug((DEBUG_DEBUG, "No Class For %s", (aconf) ? aconf->name : "*No Conf*"));

  return (BAD_CONF_CLASS);
}

int get_conf_ping(const struct ConfItem* aconf)
{
  assert(0 != aconf);
  if (aconf->conn_class)
    return (ConfPingFreq(aconf));

  Debug((DEBUG_DEBUG, "No Ping For %s", aconf->name));

  return -1;
}

unsigned int get_client_class(struct Client *acptr)
{
  struct SLink *tmp;
  struct ConnectionClass *cl;
  unsigned int retc = BAD_CLIENT_CLASS;

  if (acptr && !IsMe(acptr) && (cli_confs(acptr)))
    for (tmp = cli_confs(acptr); tmp; tmp = tmp->next)
    {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->conn_class))
        continue;
      if (ConClass(cl) > retc || retc == BAD_CLIENT_CLASS)
        retc = ConClass(cl);
    }

  Debug((DEBUG_DEBUG, "Returning Class %d For %s", retc, cli_name(acptr)));

  return (retc);
}

unsigned int get_con_freq(struct ConnectionClass * clptr)
{
  if (clptr)
    return (ConFreq(clptr));
  else
    return feature_int(FEAT_CONNECTFREQUENCY);
}

/*
 * When adding a class, check to see if it is already present first.
 * if so, then update the information for that class, rather than create
 * a new entry for it and later delete the old entry.
 * if no present entry is found, then create a new one and add it in
 * immeadiately after the first one (class 0).
 */
void add_class(unsigned int conClass, unsigned int ping, unsigned int confreq,
               unsigned int maxli, unsigned int sendq)
{
  struct ConnectionClass* t;
  struct ConnectionClass* p;

  t = find_class(conClass);
  if ((t == connClassList) && (conClass != 0))
  {
    p = (struct ConnectionClass *) make_class();
    p->next = t->next;
    t->next = p;
  }
  else
    p = t;
  Debug((DEBUG_DEBUG, "Add Class %u: cf: %u pf: %u ml: %u sq: %d",
         conClass, confreq, ping, maxli, sendq));
  ConClass(p) = conClass;
  ConFreq(p) = confreq;
  PingFreq(p) = ping;
  MaxLinks(p) = maxli;
  MaxSendq(p) = (sendq > 0) ? sendq : feature_int(FEAT_DEFAULTMAXSENDQLENGTH);
  p->valid = 1;
  if (p != t)
    Links(p) = 0;
}

struct ConnectionClass* find_class(unsigned int cclass)
{
  struct ConnectionClass *cltmp;

  for (cltmp = connClassList; cltmp; cltmp = cltmp->next) {
    if (ConClass(cltmp) == cclass)
      return cltmp;
  }
  return connClassList;
}

void report_classes(struct Client *sptr, struct StatDesc *sd, int stat,
		    char *param)
{
  struct ConnectionClass *cltmp;

  for (cltmp = connClassList; cltmp; cltmp = cltmp->next)
    send_reply(sptr, RPL_STATSYLINE, 'Y', ConClass(cltmp), PingFreq(cltmp),
	       ConFreq(cltmp), MaxLinks(cltmp), MaxSendq(cltmp),
	       Links(cltmp));
}

unsigned int get_sendq(struct Client *cptr)
{
  assert(0 != cptr);
  assert(0 != cli_local(cptr));

  if (cli_max_sendq(cptr))
    return cli_max_sendq(cptr);

  else if (cli_confs(cptr)) {
    struct SLink*     tmp;
    struct ConnectionClass* cl;

    for (tmp = cli_confs(cptr); tmp; tmp = tmp->next) {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->conn_class))
        continue;
      if (ConClass(cl) != BAD_CLIENT_CLASS) {
        cli_max_sendq(cptr) = MaxSendq(cl);
        return cli_max_sendq(cptr);
      }
    }
  }
  return feature_int(FEAT_DEFAULTMAXSENDQLENGTH);
}

void class_send_meminfo(struct Client* cptr)
{
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Classes: inuse: %d(%d)",
             connClassAllocCount, connClassAllocCount * sizeof(struct ConnectionClass));
}


