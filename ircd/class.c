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
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
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

static struct ConnectionClass* connClassList;
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
  ++connClassAllocCount;
  return tmp;
}

void free_class(struct ConnectionClass* tmp)
{
  if (tmp) {
    MyFree(tmp);
    --connClassAllocCount;
  }
}

/*
 * init_class - initialize the class list
 */
void init_class(void)
{
  connClassList = (struct ConnectionClass*) make_class();

  ConClass(connClassList) = 0;
  ConFreq(connClassList)  = CONNECTFREQUENCY;
  PingFreq(connClassList) = PINGFREQUENCY;
  MaxLinks(connClassList) = MAXIMUM_LINKS;
  MaxSendq(connClassList) = DEFAULTMAXSENDQLENGTH;
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
    p->maxLinks = BAD_CONF_CLASS;
}

/*
 * check_class
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
    if (BAD_CONF_CLASS == cl->maxLinks) {
      prev->next = cl->next;
      if (0 == cl->links)
        free_class(cl);
    }
    else
      prev = cl;
  }
}

unsigned int get_conf_class(const struct ConfItem* aconf)
{
  if ((aconf) && (aconf->confClass))
    return (ConfClass(aconf));

  Debug((DEBUG_DEBUG, "No Class For %s", (aconf) ? aconf->name : "*No Conf*"));

  return (BAD_CONF_CLASS);
}

unsigned int get_conf_ping(const struct ConfItem *aconf)
{
  if ((aconf) && (aconf->confClass))
    return (ConfPingFreq(aconf));

  Debug((DEBUG_DEBUG, "No Ping For %s", (aconf) ? aconf->name : "*No Conf*"));

  return (BAD_PING);
}

unsigned int get_client_class(struct Client *acptr)
{
  struct SLink *tmp;
  struct ConnectionClass *cl;
  unsigned int retc = BAD_CLIENT_CLASS;

  if (acptr && !IsMe(acptr) && (acptr->confs))
    for (tmp = acptr->confs; tmp; tmp = tmp->next)
    {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->confClass))
        continue;
      if (ConClass(cl) > retc || retc == BAD_CLIENT_CLASS)
        retc = ConClass(cl);
    }

  Debug((DEBUG_DEBUG, "Returning Class %d For %s", retc, acptr->name));

  return (retc);
}

unsigned int get_client_ping(struct Client *acptr)
{
  unsigned int ping = 0;
  unsigned int ping2;
  struct ConfItem *aconf;
  struct SLink *link;

  link = acptr->confs;

  if (link) {
    while (link) {
      aconf = link->value.aconf;
      if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
        ping2 = get_conf_ping(aconf);
        if ((ping2 != BAD_PING) && ((ping > ping2) || !ping))
          ping = ping2;
      }
      link = link->next;
    }
  }
  else {
    ping = PINGFREQUENCY;
    Debug((DEBUG_DEBUG, "No Attached Confs for: %s", acptr->name));
  }
  if (ping <= 0)
    ping = PINGFREQUENCY;
  Debug((DEBUG_DEBUG, "Client %s Ping %d", acptr->name, ping));
  return (ping);
}

unsigned int get_con_freq(struct ConnectionClass * clptr)
{
  if (clptr)
    return (ConFreq(clptr));
  else
    return (CONNECTFREQUENCY);
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
  MaxSendq(p) = (sendq > 0) ? sendq : DEFAULTMAXSENDQLENGTH;
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

void report_classes(struct Client *sptr)
{
  struct ConnectionClass *cltmp;

  for (cltmp = connClassList; cltmp; cltmp = cltmp->next)
    send_reply(sptr, RPL_STATSYLINE, 'Y', ConClass(cltmp), PingFreq(cltmp),
	       ConFreq(cltmp), MaxLinks(cltmp), MaxSendq(cltmp));
}

unsigned int get_sendq(struct Client *cptr)
{
  assert(0 != cptr);
  assert(0 != cptr->local);

  if (cptr->max_sendq)
    return cptr->max_sendq;

  else if (cptr->confs) {
    struct SLink*     tmp;
    struct ConnectionClass* cl;

    for (tmp = cptr->confs; tmp; tmp = tmp->next) {
      if (!tmp->value.aconf || !(cl = tmp->value.aconf->confClass))
        continue;
      if (ConClass(cl) != BAD_CLIENT_CLASS) {
        cptr->max_sendq = MaxSendq(cl);
        return cptr->max_sendq;
      }
    }
  }
  return DEFAULTMAXSENDQLENGTH;
}

void class_send_meminfo(struct Client* cptr)
{
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Classes: inuse: %d(%d)",
             connClassAllocCount, connClassAllocCount * sizeof(struct ConnectionClass));
}


