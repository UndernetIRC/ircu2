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
 *
 * $Id$
 *
 */
#include "IPcheck.h"
#include "client.h"
#include "ircd.h"
#include "numnicks.h"
#include "ircd_alloc.h"
#include "msg.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#if 0
#warning Nick collisions are horribly broken in
#warning this version, and its known to core on
#warning a whim.  If your even concidering
#warning running this on something resembling a
#warning production network, dont bother, its
#warning not worth your time.  To those of you
#warning who grabbed the latest CVS version to
#warning bug test it, thanks, but I recommend
#warning you stick to previous versions for the
#warning time being.
#error --- Broken code ---
#endif

struct IPTargetEntry {
  int           count;
  unsigned char targets[MAXTARGETS];
};

struct IPRegistryEntry {
  struct IPRegistryEntry *next;
  struct IPTargetEntry   *target;
  unsigned int             addr;
  time_t                  last_connect;
  unsigned char            connected;
  unsigned char            attempts;
};


/*
 * Hash table for IPv4 address registry
 *
 * Hash table size must be a power of 2
 * Use 64K hash table to conserve memory
 */
/*----------------------------------------------------------------------------
 * Compile-time Configuration
 *--------------------------------------------------------------------------*/
#define IP_REGISTRY_TABLE_SIZE 0x10000
#define MASK_16                0xffff

/* We allow 6 connections in 60 seconds */
#define IPCHECK_CLONE_LIMIT 6
#define IPCHECK_CLONE_PERIOD 60
#define IPCHECK_CLONE_DELAY  600


/*----------------------------------------------------------------------------
 * Handy Macros
 *--------------------------------------------------------------------------*/
#define NOW (CurrentTime)
#define CONNECTED_SINCE(x) (NOW - (x->last_connect))


/*----------------------------------------------------------------------------
 * Global Data (ugly!)
 *--------------------------------------------------------------------------*/
static struct IPRegistryEntry *hashTable[IP_REGISTRY_TABLE_SIZE];
static struct IPRegistryEntry *freeList = 0;


/*----------------------------------------------------------------------------
 * ip_registry_hash:  Create a hash key for an IP registry entry and return
 *                    the value.  (Is unsigned int really a good type to give
 *                    to the IP argument?  Ugly.  This should probably be a
 *                    struct in_addr.  This is asking for trouble.  --ZS)
 *--------------------------------------------------------------------------*/
static unsigned int ip_registry_hash(unsigned int ip)
{
  return ((ip >> 16) ^ ip) & (IP_REGISTRY_TABLE_SIZE - 1);
}


/*----------------------------------------------------------------------------
 * ip_registry_find:  Find a given IP registry entry and return it.
 *--------------------------------------------------------------------------*/
static struct IPRegistryEntry *ip_registry_find(unsigned int ip) 
{
  struct IPRegistryEntry *entry = 0;

  for (entry = hashTable[ip_registry_hash(ip)]; entry; entry = entry->next) {
    if (entry->addr == ip)
      return entry;
  }

  return NULL;
}


/*----------------------------------------------------------------------------
 * ip_registry_add:  Add an entry to the IP registry
 *--------------------------------------------------------------------------*/
static void ip_registry_add(struct IPRegistryEntry *entry) 
{
  unsigned int bucket = ip_registry_hash(entry->addr);

  entry->next = hashTable[bucket];
  hashTable[bucket] = entry;
}
  

/*----------------------------------------------------------------------------
 * ip_registry_remove:  Remove an entry from the IP registry
 *--------------------------------------------------------------------------*/
static void ip_registry_remove(struct IPRegistryEntry* entry) 
{
  unsigned int bucket = ip_registry_hash(entry->addr);

  if (hashTable[bucket] == entry)
    hashTable[bucket] = entry->next;
  else {
    struct IPRegistryEntry *prev;

    for (prev = hashTable[bucket]; prev; prev = prev->next) {
      if (prev->next == entry) {
        prev->next = entry->next;
        break;
      }
    }
  }
}
 

/*----------------------------------------------------------------------------
 * ip_registry_new_entry():  Creates and initializes an IP Registry entry.
 *                           NOW ALSO ADDS IT TO THE LIST! --ZS
 *--------------------------------------------------------------------------*/
static struct IPRegistryEntry *ip_registry_new_entry(unsigned int addr, int attempt)
{
  struct IPRegistryEntry* entry = freeList;

  if (entry)
    freeList = entry->next;
  else
    entry = (struct IPRegistryEntry *)MyMalloc(sizeof(struct IPRegistryEntry));

  assert(0 != entry);

  memset(entry, 0, sizeof(struct IPRegistryEntry));
  entry->last_connect = NOW;     /* Seconds since last connect attempt */
  entry->connected    = 1;       /* connected clients for this IP */
  entry->attempts     = attempt; /* Number attempts for this IP        */
  entry->addr         = addr;    /* Entry's IP Address                 */

  ip_registry_add(entry);

  return entry;
}


/*----------------------------------------------------------------------------
 * ip_registry_delete_entry:  Frees an entry and adds the structure to a list
 *                            of free structures.  (We should probably reclaim
 *                            the freelist every once in a while!  This is
 *                            potentially a way to DoS the server...  -ZS)
 *--------------------------------------------------------------------------*/
static void ip_registry_delete_entry(struct IPRegistryEntry *entry)
{
  if (entry->target)
    MyFree(entry->target);

  entry->next = freeList;
  freeList = entry;
}


/*----------------------------------------------------------------------------
 * ip_registry_update_free_targets:  
 *--------------------------------------------------------------------------*/
static unsigned int ip_registry_update_free_targets(struct IPRegistryEntry  *entry)
{
  unsigned int free_targets = STARTTARGETS;

  if (entry->target) {
    free_targets = (entry->target->count +
		    (CONNECTED_SINCE(entry) / TARGET_DELAY));

    if (free_targets > STARTTARGETS)
      free_targets = STARTTARGETS;

    entry->target->count = free_targets;
  }

  return free_targets;
}


/*----------------------------------------------------------------------------
 * ip_registry_expire_entry:  expire an IP entry if it needs to be.  If an
 *                            entry isn't expired, then also check the target
 *                            list to see if it needs to be expired.
 *--------------------------------------------------------------------------*/
static void ip_registry_expire_entry(struct IPRegistryEntry *entry)
{
  /*
   * Don't touch this number, it has statistical significance
   * XXX - blah blah blah
   * ZS - Just -what- statistical significance does it -have-?
   * Iso - Noone knows, we've just been told not to touch it.
   */
  if (CONNECTED_SINCE(entry) > 120 && 0 != entry->target) {
    MyFree(entry->target);
    entry->target = 0;
  }
  if (CONNECTED_SINCE(entry) > 600) {
    ip_registry_remove(entry);
    ip_registry_delete_entry(entry);
  }
}


/*----------------------------------------------------------------------------
 * ip_registry_expire:  Expire all of the needed entries in the hash table
 *--------------------------------------------------------------------------*/
void ip_registry_expire(void)
{
  struct IPRegistryEntry *entry;
  struct IPRegistryEntry *entry_next;
  static time_t   next_expire = 0;
  int i;

  /* Only do this if we're ready to */
  if (next_expire >= CurrentTime)
    return;

  for (i = 0; i < IP_REGISTRY_TABLE_SIZE; ++i) {
    for (entry = hashTable[i]; entry; entry = entry_next) {
      entry_next = entry->next;
      if (0 == entry->connected)
        ip_registry_expire_entry(entry);
    }
  }

  next_expire = CurrentTime + 60;
}


/*----------------------------------------------------------------------------
 *
 * Event:
 *   A new connection was accept()-ed with IP number `cptr->ip.s_addr'.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Return:
 *     1 : You're allowed to connect.
 *     0 : You're not allowed to connect.
 *
 * Throttling:
 *
 * A connection should be rejected when a connection from the same IP
 * number was received IPCHECK_CLONE_LIMIT times before this connect
 * attempt, with reconnect intervals of IPCHECK_CLONE_PERIOD seconds
 * or less.
 *
 * Free target inheritance:
 *
 * When the client is accepted, then the number of Free Targets
 * of the cptr is set to the value stored in the found IPregistry
 * structure, or left at STARTTARGETS.  This can be done by changing
 * cptr->nexttarget to be `now - (TARGET_DELAY * (FREE_TARGETS - 1))',
 * where FREE_TARGETS may range from 0 till STARTTARGETS.
 *--------------------------------------------------------------------------*/
int ip_registry_check_local(unsigned int addr, time_t *next_target_out)
{
  struct IPRegistryEntry *entry        = ip_registry_find(addr);
  unsigned int free_targets = STARTTARGETS;
 
  assert(0 != next_target_out);

  /* If they've never connected before, let them on */
  if (0 == entry) {
    Debug((DEBUG_DEBUG,"IPcheck: Local user allowed - unseen"));
    entry = ip_registry_new_entry(addr, 1);
    return 1;
  }
  
  /* Keep track of how many people have connected */
  entry->connected++;

  /* Do not allow more than 250 connects from a single IP, EVER. */
  if (250 <= entry->connected) {
    Debug((DEBUG_DEBUG,"IPcheck: Local user disallowed - Too many connections"));
    entry->connected--;
    return 0;
  }

  /* If our threshhold has elapsed, reset the counter so we don't throttle,
   * IPCHECK_CLONE_LIMIT connections every IPCHECK_CLONE_PERIOD
   */
  if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_PERIOD) {
    entry->attempts = 0;
    entry->last_connect = NOW;
  }

  /* Count the number of recent attempts */ 
  entry->attempts++;
  
  if (250 <= entry->attempts)
    --entry->attempts;  /* Disallow overflow */


  free_targets = ip_registry_update_free_targets(entry);

  /* Have they connected less than IPCHECK_CLONE_LIMIT times && next_target_out */
  if (entry->attempts < IPCHECK_CLONE_LIMIT && next_target_out) {
      *next_target_out = CurrentTime - (TARGET_DELAY * free_targets - 1);
      entry->last_connect = NOW;
      Debug((DEBUG_DEBUG,"IPcheck: Local user allowed"));
      return 1;
  }
  
  /* If the server is younger than IPCHECK_CLONE_DELAY then the person
   * is allowed on.
   */
  if ((CurrentTime - me.since) < IPCHECK_CLONE_DELAY) {
    Debug((DEBUG_DEBUG,"IPcheck: Local user allowed during server startup"));
    return 1;
  }
  
  /* Otherwise they're throttled */
  entry->connected--;
  Debug((DEBUG_DEBUG,"IPcheck: Throttling local user"));
  return 0;
}

/*
 * Add someone to the ip registry without throttling them.
 * This is used for server connections.
 */
void ip_registry_add_local(unsigned int addr)
{
  struct IPRegistryEntry *entry        = ip_registry_find(addr);
 
  /* If they've never connected before, let them on */
  if (0 == entry) {
    Debug((DEBUG_DEBUG,"IPcheck: Local user allowed - unseen"));
    entry = ip_registry_new_entry(addr, 1);
    return;
  }
  
  /* Keep track of how many people have connected */
  entry->connected++;

  assert(250 <= entry->connected);

  return;
}

/*----------------------------------------------------------------------------
 * ip_registry_remote_connect
 *
 * Does anything that needs to be done once we actually have a client
 * structure to play with on a remote connection.
 * returns:
 *  1 - allowed to connect
 *  0 - disallowed.
 *--------------------------------------------------------------------------*/
int ip_registry_remote_connect(struct Client *cptr)
{
  struct IPRegistryEntry *entry        = ip_registry_find(cptr->ip.s_addr);
  assert(0 != cptr);

  /* If they've never connected before, let them on */
  if (0 == entry) {
    entry = ip_registry_new_entry(cptr->ip.s_addr, 1);
    SetIPChecked(cptr);
    Debug((DEBUG_DEBUG,"IPcheck: First remote connection.  connected=%i",entry->connected));
    return 1;
  }
  
  /* Keep track of how many people have connected */
  entry->connected++;
  SetIPChecked(cptr);

  /* Do not allow more than 250 connections from one IP.
   * This can happen by having 128 clients on one server, and 128 on another
   * and then the servers joining after a netsplit
   */ 
  if (250 <= entry->connected) {
    sendto_ops("IPcheck Ghost! [%s]",inet_ntoa(cptr->ip));
    Debug((DEBUG_DEBUG,"IPcheck: Too many connected from IP: %i",entry->connected));
    return 0;
  }
  
  Debug((DEBUG_DEBUG,"IPcheck: %i people connected",entry->connected));
  
  /* They are allowed to connect */
  return 1;
}

/*----------------------------------------------------------------------------
 * IPcheck_connect_succeeded
 *
 * Event:
 *   A client succeeded to finish the registration.
 *
 * Finish IPcheck registration of a successfully, locally connected client.
 *--------------------------------------------------------------------------*/
void ip_registry_connect_succeeded(struct Client *cptr)
{
  unsigned int free_targets     = STARTTARGETS;
  struct IPRegistryEntry *entry;

  assert(cptr);

  entry = ip_registry_find(cptr->ip.s_addr);


  assert(entry);

  if (entry->target) {
    memcpy(cptr->targets, entry->target->targets, MAXTARGETS);
    free_targets = entry->target->count;
  }

  sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :connected %u attempts %u/%u free targets %u/%u%s"
  		" IPcheck: %s",
		cptr, entry->connected, entry->attempts, IPCHECK_CLONE_LIMIT,
		free_targets, STARTTARGETS, 
		((entry->target) ? " [Inherited Targets]" : ""), 
		((CurrentTime - me.since) < IPCHECK_CLONE_DELAY) ? "Disabled" : "Enabled");
		
  SetIPChecked(cptr);
}


/*----------------------------------------------------------------------------
 * IPcheck_disconnect
 *
 * Event:
 *   A local client disconnected.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Remove all expired IPregistry structures from the hash bucket
 *     that belongs to this clients IP number.
 *--------------------------------------------------------------------------*/
void ip_registry_local_disconnect(struct Client *cptr)
{
  struct IPRegistryEntry *entry;
  unsigned int free_targets;

  assert(0 != cptr);

  entry = ip_registry_find(cptr->ip.s_addr);

  Debug((DEBUG_DEBUG,"IPcheck: Local Disconnect"));
  	
  assert(IsIPChecked(cptr));
  
  assert(entry);

  assert(entry->connected > 0);
  
  if (entry->connected > 0) {
    entry->connected--;
  }

  /*
   * If this was the last one, set `last_connect' to disconnect time
   * (used for expiration)   Note that we reset attempts here as well if our
   * threshhold hasn't been crossed.
   */
  if (0 == entry->connected) {
    ip_registry_update_free_targets(entry);
    entry->last_connect = NOW;
  }
  
  assert(MyConnect(cptr));

  if (0 == entry->target) {
    entry->target = (struct IPTargetEntry *)MyMalloc(sizeof(struct IPTargetEntry));
    assert(0 != entry->target);
    entry->target->count = STARTTARGETS;
  }
  memcpy(entry->target->targets, cptr->targets, MAXTARGETS);

  /*
   * This calculation can be pretty unfair towards large multi-user hosts,
   * but there is "nothing" we can do without also allowing spam bots to
   * send more messages or by drastically increasing the ammount of memory
   * used in the IPregistry.
   *
   * The problem is that when a client disconnects, leaving no free targets,
   * then the next client from that IP number has to pay for it (getting no
   * free targets).  But ALSO the next client, and the next client, and the
   * next client etc - until another client disconnects that DOES leave free
   * targets.  The reason for this is that if there are 10 SPAM bots, and
   * they all disconnect at once, then they ALL should get no free targets
   * when reconnecting.  We'd need to store an entry per client (instead of
   * per IP number) to avoid this.  
   */
  if (cptr->nexttarget < CurrentTime)
    free_targets = (CurrentTime - cptr->nexttarget) / TARGET_DELAY + 1;
  else
    free_targets = 0;

  /* Add bonus, if you've been connected for more than 10 minutes you
   * get a free target every TARGET_DELAY seconds.
   * this is pretty fuzzy, but it will help in some cases. 
   */
  if ((CurrentTime - cptr->firsttime) > 600)
    free_targets += (CurrentTime - cptr->firsttime - 600) / TARGET_DELAY;

  /* Finally, store smallest value for Judgement Day */
  if (free_targets < entry->target->count)
    entry->target->count = free_targets;
  
}

/*----------------------------------------------------------------------------
 * ip_registry_remote_disconnect
 *
 * Event:
 *   A remote client disconnected.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Remove all expired IPregistry structures from the hash bucket
 *     that belongs to this clients IP number.
 *--------------------------------------------------------------------------*/
void ip_registry_remote_disconnect(struct Client *cptr)
{
  struct IPRegistryEntry *entry;

  assert(0 != cptr);

  entry = ip_registry_find(cptr->ip.s_addr);
  
  assert(entry);
  
  assert(entry->connected > 0);
  Debug((DEBUG_DEBUG,"IPcheck: Remote Disconnect"));

  if (entry->connected > 0) {
    entry->connected--;
  }

  /*
   * If this was the last one, set `last_connect' to disconnect time
   * (used for expiration)   Note that we reset attempts here as well if our
   * threshhold hasn't been crossed.
   */
  if (0 == entry->connected) {
    ip_registry_update_free_targets(entry);
    entry->last_connect=NOW;
  }
}

/*----------------------------------------------------------------------------
 * IPcheck_nr
 *
 * Returns number of clients with the same IP number
 *--------------------------------------------------------------------------*/
int ip_registry_count(unsigned int addr)
{
  struct IPRegistryEntry *entry = ip_registry_find(addr);
  return (entry) ? entry->connected : 0;
}
