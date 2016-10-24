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
 */
/** @file
 * @brief Implementation of connection class handling functions.
 * @version $Id$
 */
#include "config.h"

#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** List of all connection classes. */
static struct ConnectionClass* connClassList;
/** Number of allocated connection classes. */
static unsigned int connClassAllocCount;

/** Get start of connection class linked list. */
const struct ConnectionClass* get_class_list(void)
{
  return connClassList;
}

/** Allocate a new connection class.
 * If #connClassList is not null, insert the new class just after it.
 * @return Newly allocated connection class structure.
 */
struct ConnectionClass* make_class(void)
{
  struct ConnectionClass *tmp;

  tmp = (struct ConnectionClass*) MyCalloc(1, sizeof(struct ConnectionClass));
  assert(0 != tmp);
  tmp->ref_count = 1;
  if (connClassList)
  {
    tmp->next = connClassList->next;
    connClassList->next = tmp;
  }
  ++connClassAllocCount;
  return tmp;
}

/** Dereference a connection class.
 * @param[in] p Connection class to dereference.
 */
void free_class(struct ConnectionClass* p)
{
  if (p)
  {
    assert(0 == p->valid);
    MyFree(p->cc_name);
    MyFree(p->default_umode);
    MyFree(p);
    --connClassAllocCount;
  }
}

/** Initialize the connection class list.
 * A connection class named "default" is created, with ping frequency,
 * connection frequency, maximum links and max SendQ values from the
 * corresponding configuration features.
 */
void init_class(void)
{
  if (!connClassList) {
    connClassList = (struct ConnectionClass*) make_class();
    connClassList->next   = 0;
  }

  /* We had better not try and free this... */
  ConClass(connClassList) = "default";
  PingFreq(connClassList) = feature_int(FEAT_PINGFREQUENCY);
  ConFreq(connClassList)  = feature_int(FEAT_CONNECTFREQUENCY);
  MaxLinks(connClassList) = feature_int(FEAT_MAXIMUM_LINKS);
  MaxSendq(connClassList) = feature_int(FEAT_DEFAULTMAXSENDQLENGTH);
  connClassList->valid    = 1;
  Links(connClassList)    = 1;
}

/** Mark current connection classes as invalid.
 */
void class_mark_delete(void)
{
  struct ConnectionClass* p;
  assert(0 != connClassList);

  for (p = connClassList->next; p; p = p->next)
    p->valid = 0;
}

/** Unlink (and dereference) invalid connection classes.
 * This is used in combination with class_mark_delete() during rehash
 * to get rid of connection classes that are no longer in the
 * configuration.
 */
void class_delete_marked(void)
{
  struct ConnectionClass* cl;
  struct ConnectionClass* prev;

  Debug((DEBUG_DEBUG, "Class check:"));

  for (prev = cl = connClassList; cl; cl = prev->next) {
    Debug((DEBUG_DEBUG, "Class %s : CF: %d PF: %d ML: %d LI: %d SQ: %d",
           ConClass(cl), ConFreq(cl), PingFreq(cl), MaxLinks(cl),
           Links(cl), MaxSendq(cl)));
    /*
     * unlink marked classes, delete unreferenced ones
     */
    if (cl->valid || Links(cl) > 1)
      prev = cl;
    else
    {
      prev->next = cl->next;
      free_class(cl);
    }
  }
}

/** Get connection class name for a configuration item.
 * @param[in] aconf Configuration item to check.
 * @return Name of connection class associated with \a aconf.
 */
char*
get_conf_class(const struct ConfItem* aconf)
{
  if ((aconf) && (aconf->conn_class))
    return (ConfClass(aconf));

  Debug((DEBUG_DEBUG, "No Class For %s", (aconf) ? aconf->name : "*No Conf*"));

  return NULL;
}

/** Get ping time for a configuration item.
 * @param[in] aconf Configuration item to check.
 * @return Ping time for connection class associated with \a aconf.
 */
int get_conf_ping(const struct ConfItem* aconf)
{
  assert(0 != aconf);
  if (aconf->conn_class)
    return (ConfPingFreq(aconf));

  Debug((DEBUG_DEBUG, "No Ping For %s", aconf->name));

  return -1;
}

/** Get connection class name for a particular client.
 * @param[in] acptr Client to check.
 * @return Name of connection class to which \a acptr belongs.
 */
char*
get_client_class(struct Client *acptr)
{
  struct SLink *tmp;
  struct ConnectionClass *cl;

  /* Return the most recent(first on LL) client class... */
  if (acptr && !IsMe(acptr) && (cli_confs(acptr)))
    for (tmp = cli_confs(acptr); tmp; tmp = tmp->next)
    {
      if (tmp->value.aconf && (cl = tmp->value.aconf->conn_class))
        return ConClass(cl);
    }
  return "(null-class)";
}

/** Make sure we have a connection class named \a name.
 * If one does not exist, create it.  Then set its ping frequency,
 * connection frequency, maximum link count, and max SendQ according
 * to the parameters.
 * @param[in] name Connection class name.
 * @param[in] ping Ping frequency for clients in this class.
 * @param[in] confreq Connection frequency for clients.
 * @param[in] maxli Maximum link count for class.
 * @param[in] sendq Max SendQ for clients.
 */
void add_class(char *name, unsigned int ping, unsigned int confreq,
               unsigned int maxli, unsigned int sendq)
{
  struct ConnectionClass* p;

  Debug((DEBUG_DEBUG, "Add Class %s: cf: %u pf: %u ml: %u sq: %d",
         name, confreq, ping, maxli, sendq));
  assert(name != NULL);
  p = do_find_class(name, 1);
  if (!p)
    p = make_class();
  else
    MyFree(ConClass(p));
  ConClass(p) = name;
  ConFreq(p) = confreq;
  PingFreq(p) = ping;
  MaxLinks(p) = maxli;
  MaxSendq(p) = (sendq > 0) ?
     sendq : feature_int(FEAT_DEFAULTMAXSENDQLENGTH);
  p->valid = 1;
}

/** Find a connection class by name.
 * @param[in] name Name of connection class to search for.
 * @param[in] extras If non-zero, include unreferenced classes.
 * @return Pointer to connection class structure (or NULL if none match).
 */
struct ConnectionClass* do_find_class(const char *name, int extras)
{
  struct ConnectionClass *cltmp;

  for (cltmp = connClassList; cltmp; cltmp = cltmp->next) {
    if (!cltmp->valid && !extras)
      continue;
    if (!ircd_strcmp(ConClass(cltmp), name))
      return cltmp;
  }
  return NULL;
}

/** Report connection classes to a client.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
report_classes(struct Client *sptr, const struct StatDesc *sd,
               char *param)
{
  struct ConnectionClass *cltmp;

  for (cltmp = connClassList; cltmp; cltmp = cltmp->next)
    send_reply(sptr, RPL_STATSYLINE, (cltmp->valid ? 'Y' : 'y'),
               ConClass(cltmp), PingFreq(cltmp), ConFreq(cltmp),
               MaxLinks(cltmp), MaxSendq(cltmp), Links(cltmp) - 1,
               CCUmode(cltmp) ? CCUmode(cltmp) : "+");
}

/** Return maximum SendQ length for a client.
 * @param[in] cptr Local client to check.
 * @return Number of bytes allowed in SendQ for \a cptr.
 */
unsigned int
get_sendq(struct Client *cptr)
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
      if (ConClass(cl) != NULL) {
        cli_max_sendq(cptr) = MaxSendq(cl);
        return cli_max_sendq(cptr);
      }
    }
  }
  return feature_int(FEAT_DEFAULTMAXSENDQLENGTH);
}

/** Report connection class memory statistics to a client.
 * Send number of classes and number of bytes allocated for them.
 * @param[in] cptr Client requesting statistics.
 */
void class_send_meminfo(struct Client* cptr)
{
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Classes: inuse: %d(%d)",
             connClassAllocCount,
             connClassAllocCount * sizeof(struct ConnectionClass));
}


