/*
 * IRC - Internet Relay Chat, ircd/IPcheck.c
 * Copyright (C) 1998 Carlo Wood ( Run @ undernet.org )
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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

/* This file should be edited in a window with a width of 141 characters */

#include "sys.h"
#include <netinet/in.h>
#include "h.h"
#include "IPcheck.h"
#include "querycmds.h"
#include "struct.h"
#include "s_user.h"
#include "s_bsd.h"
#include "struct.h"
#ifdef GODMODE
#include "numnicks.h"
#endif
#include "send.h"

RCSTAG_CC("$Id$");

extern aClient me;
extern time_t now;

/*
 * IP number and last targets of a user that just disconnected.
 * Used to allow a user that shortly disconnected to rejoin
 * the channels he/she was on.
 */
struct ip_targets_st {
  struct in_addr ip;
  unsigned char free_targets;
  unsigned char targets[MAXTARGETS];
};

/* We keep one IPregistry for each IP number (for both, remote and local clients) */
struct IPregistry {
  union {
    struct in_addr ip;		/* The IP number of the registry entry. */
    struct ip_targets_st *ptr;	/* The IP number of the registry entry, and a list of targets */
  } ip_targets;
  unsigned int last_connect:16;	/* Time of last connect (attempt), see BITMASK below,
				   or time of last disconnect when `connected' is zero. */
  unsigned int connected:8;	/* Used for IP# throttling: Number of currently on-line clients with this IP number */
  unsigned int connect_attempts:4;	/* Used for connect speed throttling: Number of clients that connected with this IP number
					   or `15' when then real value is >= 15.  This value is only valid when the last connect
					   was less then IPCHECK_CLONE_PERIOD seconds ago, it should considered to be 0 otherwise. */
  unsigned int free_targets:4;	/* Number of free targets that the next local client will inherit on connect,
				   or HAS_TARGETS_MAGIC when ip_targets.ptr is a pointer to a ip_targets_st. */
};

struct IPregistry_vector {
  unsigned short length;
  unsigned short allocated_length;
  struct IPregistry *vector;
};

#define HASHTABSIZE 0x2000	/* Must be power of 2 */
static struct IPregistry_vector IPregistry_hashtable[HASHTABSIZE];

/*
 * Calculate a `hash' value between 0 and HASHTABSIZE, from the internet address `in_addr'.
 * Apply it immedeately to the table, effectively hiding the table itself.
 */
#define CALCULATE_HASH(in_addr) \
  struct IPregistry_vector *hash; \
  do { register unsigned int ip = (in_addr).s_addr; \
       hash = &IPregistry_hashtable[((ip >> 14) + (ip >> 7) + ip) & (HASHTABSIZE - 1)]; } while(0)

/*
 * Fit `now' in an unsigned short, the advantage is that we use less memory `struct IPregistry::last_connect' can be smaller
 * while the only disadvantage is that if someone reconnects after exactly 18 hours and 12 minutes, and NOBODY with the
 * same _hash_ value for this IP-number did disconnect in the meantime, then the server will think he reconnected immedeately.
 * In other words: No disadvantage at all.
 */
#define BITMASK 0xffff		/* Same number of bits as `struct IPregistry::last_connect' */
#define NOW ((unsigned short)(now & BITMASK))
#define CONNECTED_SINCE(x) ((unsigned short)((now & BITMASK) - (x)->last_connect))

#define IPCHECK_CLONE_LIMIT 2
#define IPCHECK_CLONE_PERIOD 20
#define IPCHECK_CLONE_DELAY 600

#define HAS_TARGETS_MAGIC 15
#define HAS_TARGETS(entry) ((entry)->free_targets == HAS_TARGETS_MAGIC)

#if STARTTARGETS >= HAS_TARGETS_MAGIC
#error "That doesn't fit in 4 bits, does it?"
#endif

/* IP(entry) returns the `struct in_addr' of the IPregistry. */
#define IP(entry) (HAS_TARGETS(entry) ? (entry)->ip_targets.ptr->ip : (entry)->ip_targets.ip)
#define FREE_TARGETS(entry) (HAS_TARGETS(entry) ? (entry)->ip_targets.ptr->free_targets : (entry)->free_targets)

static unsigned short count = 10000, average_length = 4;

static struct IPregistry *IPregistry_add(struct IPregistry_vector *iprv)
{
  if (iprv->length == iprv->allocated_length)
  {
    iprv->allocated_length += 4;
    iprv->vector =
	(struct IPregistry *)RunRealloc(iprv->vector,
	iprv->allocated_length * sizeof(struct IPregistry));
  }
  return &iprv->vector[iprv->length++];
}

static struct IPregistry *IPregistry_find(struct IPregistry_vector *iprv,
    struct in_addr ip)
{
  if (iprv->length > 0)
  {
    struct IPregistry *i, *end = &iprv->vector[iprv->length];
    for (i = &iprv->vector[0]; i < end; ++i)
      if (IP(i).s_addr == ip.s_addr)
	return i;
  }
  return NULL;
}

static struct IPregistry *IPregistry_find_with_expire(struct IPregistry_vector
    *iprv, struct in_addr ip)
{
  struct IPregistry *last = &iprv->vector[iprv->length - 1];	/* length always > 0 because searched element always exists */
  struct IPregistry *curr;
  struct IPregistry *retval = NULL;	/* Core dump if we find nothing :/ - can be removed when code is stable */

  for (curr = &iprv->vector[0]; curr < last;)
  {
    if (IP(curr).s_addr == ip.s_addr)
      /* `curr' is element we looked for */
      retval = curr;
    else if (curr->connected == 0)
    {
      if (CONNECTED_SINCE(curr) > 600U)	/* Don't touch this number, it has statistical significance */
      {
	/* `curr' expired */
	if (HAS_TARGETS(curr))
	  RunFree(curr->ip_targets.ptr);
	*curr = *last--;
	iprv->length--;
	if (--count == 0)
	{
	  /* Make ever 10000 disconnects an estimation of the average vector length */
	  count = 10000;
	  average_length =
	      (nrof.clients + nrof.unknowns + nrof.local_servers) / HASHTABSIZE;
	}
	/* Now check the new element (last) that was moved to this position */
	continue;
      }
      else if (CONNECTED_SINCE(curr) > 120U && HAS_TARGETS(curr))
      {
	/* Expire storage of targets */
	struct in_addr ip1 = curr->ip_targets.ptr->ip;
	curr->free_targets = curr->ip_targets.ptr->free_targets;
	RunFree(curr->ip_targets.ptr);
	curr->ip_targets.ip = ip1;
      }
    }
    /* Did not expire, check next element */
    ++curr;
  }
  /* Now check the last element in the list (curr == last) */
  if (IP(curr).s_addr == ip.s_addr)
    /* `curr' is element we looked for */
    retval = curr;
  else if (curr->connected == 0)
  {
    if (CONNECTED_SINCE(curr) > 600U)	/* Don't touch this number, it has statistical significance */
    {
      /* `curr' expired */
      if (HAS_TARGETS(curr))
	RunFree(curr->ip_targets.ptr);
      iprv->length--;
      if (--count == 0)
      {
	/* Make ever 10000 disconnects an estimation of the average vector length */
	count = 10000;
	average_length =
	    (nrof.clients + nrof.unknowns + nrof.local_servers) / HASHTABSIZE;
      }
    }
    else if (CONNECTED_SINCE(curr) > 120U && HAS_TARGETS(curr))
    {
      /* Expire storage of targets */
      struct in_addr ip1 = curr->ip_targets.ptr->ip;
      curr->free_targets = curr->ip_targets.ptr->free_targets;
      RunFree(curr->ip_targets.ptr);
      curr->ip_targets.ip = ip1;
    }
  }
  /* Do we need to shrink the vector? */
  if (iprv->allocated_length > average_length
      && iprv->allocated_length - iprv->length >= 4)
  {
    struct IPregistry *newpos;
    iprv->allocated_length = iprv->length;
    newpos =
	(struct IPregistry *)RunRealloc(iprv->vector,
	iprv->allocated_length * sizeof(struct IPregistry));
    if (newpos != iprv->vector)	/* Is this ever true? */
    {
      retval =
	  (struct IPregistry *)((char *)retval + ((char *)newpos -
	  (char *)iprv->vector));
      iprv->vector = newpos;
    }
  }
  return retval;
}

static void reset_connect_time(struct IPregistry *entry)
{
  unsigned int previous_free_targets;

  /* Apply aging */
  previous_free_targets =
      FREE_TARGETS(entry) + CONNECTED_SINCE(entry) / TARGET_DELAY;
  if (previous_free_targets > STARTTARGETS)
    previous_free_targets = STARTTARGETS;
  if (HAS_TARGETS(entry))
    entry->ip_targets.ptr->free_targets = previous_free_targets;
  else
    entry->free_targets = previous_free_targets;

  entry->last_connect = NOW;
}

/*
 * IPcheck_local_connect
 *
 * Event:
 *   A new connection was accept()-ed with IP number `cptr->ip.s_addr'.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Return < 0 if the connection should be rejected, otherwise 0.
 *     -1 : Throttled
 *     -2 : Too many connections from your host
 *
 * Throttling:
 *
 * A connection should be rejected when a connection from the same IP number was
 * received IPCHECK_CLONE_LIMIT times before this connect attempt, with
 * reconnect intervals of IPCHECK_CLONE_PERIOD seconds or less.
 *
 * Free target inheritance:
 *
 * When the client is accepted, then the number of Free Targets
 * of the cptr is set to the value stored in the found IPregistry
 * structure, or left at STARTTARGETS.  This can be done by changing
 * cptr->nexttarget to be `now - (TARGET_DELAY * (FREE_TARGETS - 1))',
 * where FREE_TARGETS may range from 0 till STARTTARGETS.
 */
int IPcheck_local_connect(aClient *cptr)
{
  struct IPregistry *entry;
  CALCULATE_HASH(cptr->ip);
  SetIPChecked(cptr);		/* Mark that we did add/update an IPregistry entry */
  if (!(entry = IPregistry_find(hash, cptr->ip)))
  {
    entry = IPregistry_add(hash);
    entry->ip_targets.ip = cptr->ip;	/* The IP number of registry entry */
    entry->last_connect = NOW;	/* Seconds since last connect (attempt) */
    entry->connected = 1;	/* Number of currently connected clients with this IP number */
    entry->connect_attempts = 1;	/* Number of clients that connected with this IP number */
    entry->free_targets = STARTTARGETS;	/* Number of free targets that a client gets on connect */
    return 0;
  }
#ifdef GODMODE
  sendto_one(cptr,
      "ERROR :I saw your face before my friend (connected: %u; connect_attempts %u; free_targets %u)",
      entry->connected, entry->connect_attempts, FREE_TARGETS(entry));
#endif
  /* Note that this also connects server connects.  It is hard and not interesting, to change that. */
  if (++(entry->connected) == 0)	/* Don't allow more then 255 connects from one IP number, ever */
    return -2;
  if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_PERIOD)
    entry->connect_attempts = 0;
  reset_connect_time(entry);
  if (++(entry->connect_attempts) == 0)	/* Check for overflow */
    --(entry->connect_attempts);
  if (entry->connect_attempts <= IPCHECK_CLONE_LIMIT)
    cptr->nexttarget = now - (TARGET_DELAY * (FREE_TARGETS(entry) - 1));
#ifdef DEBUGMODE
  else
#else
  else if (now - me.since > IPCHECK_CLONE_DELAY)	/* Don't refuse connection when we just rebooted the server */
#endif
    return -1;
  return 0;
}

/*
 * IPcheck_remote_connect
 *
 * Event:
 *   A remote client connected to Undernet, with IP number `cptr->ip.s_addr'
 *   and hostname `hostname'.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Return -1 on failure, 0 on success.
 */
int IPcheck_remote_connect(aClient *cptr, const char *UNUSED(hostname),
    int is_burst)
{
  struct IPregistry *entry;
  CALCULATE_HASH(cptr->ip);
  SetIPChecked(cptr);		/* Mark that we did add/update an IPregistry entry */
  if (!(entry = IPregistry_find(hash, cptr->ip)))
  {
    entry = IPregistry_add(hash);
    entry->ip_targets.ip = cptr->ip;	/* The IP number of registry entry */
    entry->last_connect = NOW;	/* Seconds since last connect (attempt) */
    entry->connected = 1;	/* Number of currently connected clients with this IP number */
    entry->connect_attempts = is_burst ? 1 : 0;	/* Number of clients that connected with this IP number */
    entry->free_targets = STARTTARGETS;	/* Number of free targets that a client gets on connect */
  }
  else
  {
#ifdef GODMODE
    sendto_one(cptr,
	"%s NOTICE %s%s :I saw your face before my friend (connected: %u; connect_attempts %u; free_targets %u)",
	NumServ(&me), NumNick(cptr), entry->connected, entry->connect_attempts,
	FREE_TARGETS(entry));
#endif
    if (++(entry->connected) == 0)	/* Don't allow more then 255 connects from one IP number, ever */
      return -1;
    if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_PERIOD)
      entry->connect_attempts = 0;
    if (!is_burst)
    {
      if (++(entry->connect_attempts) == 0)	/* Check for overflow */
	--(entry->connect_attempts);
      reset_connect_time(entry);
    }
  }
  return 0;
}

/*
 * IPcheck_connect_fail
 *
 * Event:
 *   This local client failed to connect due to legal reasons.
 *
 * Action:
 *   Neutralize the effect of calling IPcheck_local_connect, in such
 *   a way that the client won't be penalized when trying to reconnect
 *   again.
 */
void IPcheck_connect_fail(aClient *cptr)
{
  struct IPregistry *entry;
  CALCULATE_HASH(cptr->ip);
  entry = IPregistry_find(hash, cptr->ip);
  entry->connect_attempts--;
}

/*
 * IPcheck_connect_succeeded
 *
 * Event:
 *   A client succeeded to finish the registration.
 *
 * Finish IPcheck registration of a successfully, locally connected client.
 */
void IPcheck_connect_succeeded(aClient *cptr)
{
  struct IPregistry *entry;
  const char *tr = "";
  CALCULATE_HASH(cptr->ip);
  entry = IPregistry_find(hash, cptr->ip);
  if (HAS_TARGETS(entry))
  {
    memcpy(cptr->targets, entry->ip_targets.ptr->targets, MAXTARGETS);
    tr = " tr";
  }
  sendto_one(cptr, ":%s NOTICE %s :on %u ca %u(%u) ft %u(%u)%s",
      me.name, cptr->name, entry->connected, entry->connect_attempts,
      IPCHECK_CLONE_LIMIT, FREE_TARGETS(entry), STARTTARGETS, tr);
}

/*
 * IPcheck_disconnect
 *
 * Event:
 *   A local client disconnected or a remote client left Undernet.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Remove all expired IPregistry structures from the hash bucket
 *     that belongs to this clients IP number.
 */
void IPcheck_disconnect(aClient *cptr)
{
  struct IPregistry *entry;
  CALCULATE_HASH(cptr->ip);
  entry = IPregistry_find_with_expire(hash, cptr->ip);
  if (--(entry->connected) == 0)	/* If this was the last one, set `last_connect' to disconnect time (used for expiration) */
  {
    if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_LIMIT * IPCHECK_CLONE_PERIOD)
      entry->connect_attempts = 0;	/* Otherwise we'd penetalize for this old value if the client reconnects within 20 seconds */
    reset_connect_time(entry);
  }
  if (MyConnect(cptr))
  {
    unsigned int inheritance;
    /* Copy the clients targets */
    if (HAS_TARGETS(entry))
    {
      entry->free_targets = entry->ip_targets.ptr->free_targets;
      RunFree(entry->ip_targets.ptr);
    }
    entry->ip_targets.ptr =
	(struct ip_targets_st *)RunMalloc(sizeof(struct ip_targets_st));
    entry->ip_targets.ptr->ip = cptr->ip;
    entry->ip_targets.ptr->free_targets = entry->free_targets;
    entry->free_targets = HAS_TARGETS_MAGIC;
    memcpy(entry->ip_targets.ptr->targets, cptr->targets, MAXTARGETS);
    /*
     * This calculation can be pretty unfair towards large multi-user hosts, but
     * there is "nothing" we can do without also allowing spam bots to send more
     * messages or by drastically increasing the ammount of memory used in the IPregistry.
     *
     * The problem is that when a client disconnects, leaving no free targets, then
     * the next client from that IP number has to pay for it (getting no free targets).
     * But ALSO the next client, and the next client, and the next client etc - until
     * another client disconnects that DOES leave free targets.  The reason for this
     * is that if there are 10 SPAM bots, and they all disconnect at once, then they
     * ALL should get no free targets when reconnecting.  We'd need to store an entry
     * per client (instead of per IP number) to avoid this.
     */
    if (cptr->nexttarget <= now)
      inheritance = (now - cptr->nexttarget) / TARGET_DELAY + 1;	/* Number of free targets */
    else
      inheritance = 0;
    /* Add bonus, this is pretty fuzzy, but it will help in some cases. */
    if (now - cptr->firsttime > 600)	/* Was longer then 10 minutes online? */
      inheritance += (now - cptr->firsttime - 600) / TARGET_DELAY;
    /* Finally, store smallest value for Judgement Day */
    if (inheritance < entry->ip_targets.ptr->free_targets)
      entry->ip_targets.ptr->free_targets = inheritance;
  }
}

/*
 * IPcheck_nr
 *
 * Returns number of clients with the same IP number
 */
unsigned short IPcheck_nr(aClient *cptr)
{
  struct IPregistry *entry;
  CALCULATE_HASH(cptr->ip);
  entry = IPregistry_find(hash, cptr->ip);
  return (entry ? entry->connected : 0);
}
