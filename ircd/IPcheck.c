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

/*----------------------------------------------------------------------------
 * Platform Includes
 *--------------------------------------------------------------------------*/
#include <assert.h>
#include <stdio.h>
#include <string.h>


/*----------------------------------------------------------------------------
 * Application Includes
 *--------------------------------------------------------------------------*/
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


/*----------------------------------------------------------------------------
 * Data Structures (should be moved to IPcheck.h)
 *--------------------------------------------------------------------------*/
typedef struct IPTargetEntry {
  int           count;
  unsigned char targets[MAXTARGETS];
} iptarget_entry_t;

typedef struct IPRegistryEntry {
  struct IPRegistryEntry *next;
  struct IPTargetEntry   *target;
  unsigned int             addr;
  time_t                  last_connect;
  unsigned char            connected;
  unsigned char            attempts;
} ip_reg_entry_t;


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

#define IPCHECK_CLONE_LIMIT 2
#define IPCHECK_CLONE_PERIOD 20
#define IPCHECK_CLONE_DELAY  1


/*----------------------------------------------------------------------------
 * Handy Macros
 *--------------------------------------------------------------------------*/
#define NOW (CurrentTime)
#define CONNECTED_SINCE(x) (NOW - (x->last_connect))


/*----------------------------------------------------------------------------
 * Global Data (ugly!)
 *--------------------------------------------------------------------------*/
static ip_reg_entry_t *hashTable[IP_REGISTRY_TABLE_SIZE];
static ip_reg_entry_t *freeList = 0;


/*----------------------------------------------------------------------------
 * ip_registry_hash:  Create a hash key for an IP registry entry and return
 *                    the value.  (Is unsigned int really a good type to give
 *                    to the IP argument?  Ugly.  This should probably be a
 *                    struct in_addr.  This is asking for trouble.  --ZS)
 *--------------------------------------------------------------------------*/
static unsigned int ip_registry_hash(unsigned int ip) {
  return ((ip >> 16) ^ ip) & (IP_REGISTRY_TABLE_SIZE - 1);
}


/*----------------------------------------------------------------------------
 * ip_registry_find:  Find a given IP registry entry and return it.
 *--------------------------------------------------------------------------*/
static ip_reg_entry_t *ip_registry_find(unsigned int ip) {
  ip_reg_entry_t *entry;

  for (entry = hashTable[ip_registry_hash(ip)]; entry; entry = entry->next) {
    if (entry->addr == ip)
      break;
  }

  return entry;
}


/*----------------------------------------------------------------------------
 * ip_registry_add:  Add an entry to the IP registry
 *--------------------------------------------------------------------------*/
static void ip_registry_add(ip_reg_entry_t *entry) {
  unsigned int bucket = ip_registry_hash(entry->addr);

  entry->next = hashTable[bucket];
  hashTable[bucket] = entry;
}
  

/*----------------------------------------------------------------------------
 * ip_registry_remove:  Remove an entry from the IP registry
 *--------------------------------------------------------------------------*/
static void ip_registry_remove(ip_reg_entry_t *entry) {
  unsigned int bucket = ip_registry_hash(entry->addr);

  if (hashTable[bucket] == entry)
    hashTable[bucket] = entry->next;
  else {
    ip_reg_entry_t *prev;

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
static ip_reg_entry_t *ip_registry_new_entry(unsigned int addr, int attempt) {
  ip_reg_entry_t *entry = freeList;

  if (entry)
    freeList = entry->next;
  else
    entry = (ip_reg_entry_t *)MyMalloc(sizeof(ip_reg_entry_t));

  assert(0 != entry);

  memset(entry, 0, sizeof(ip_reg_entry_t));
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
static void ip_registry_delete_entry(ip_reg_entry_t *entry) {
  if (entry->target)
    MyFree(entry->target);

  entry->next = freeList;
  freeList = entry;
}


/*----------------------------------------------------------------------------
 * ip_registry_update_free_targets:  
 *--------------------------------------------------------------------------*/
static unsigned int ip_registry_update_free_targets(ip_reg_entry_t  *entry) {
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
static void ip_registry_expire_entry(ip_reg_entry_t *entry) {
  /*
   * Don't touch this number, it has statistical significance
   * XXX - blah blah blah
   * ZS - Just -what- statistical significance does it -have-?
   */
  if (CONNECTED_SINCE(entry) > 600) {
    ip_registry_remove(entry);
    ip_registry_delete_entry(entry);
  } else if (CONNECTED_SINCE(entry) > 120 && 0 != entry->target) {
    MyFree(entry->target);
    entry->target = 0;
  }
}


/*----------------------------------------------------------------------------
 * ip_registry_expire:  Expire all of the needed entries in the hash table
 *--------------------------------------------------------------------------*/
static void ip_registry_expire(void) {
  ip_reg_entry_t *entry;
  ip_reg_entry_t *entry_next;
  int i;

  for (i = 0; i < IP_REGISTRY_TABLE_SIZE; ++i) {
    for (entry = hashTable[i]; entry; entry = entry_next) {
      entry_next = entry->next;
      if (0 == entry->connected)
        ip_registry_expire_entry(entry);
    }
  }
}


/*----------------------------------------------------------------------------
 * IPcheck_local_connect
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
  ip_reg_entry_t *entry        = ip_registry_find(addr);
  unsigned int free_targets = STARTTARGETS;
 
  if (0 == entry) {
    entry = ip_registry_new_entry(addr, 1);
    return 1;
  }

  /* Do not allow more than 255 connects from a single IP, EVER. */
  if (0 == ++entry->connected)
    return 0;

  /* If our threshhold has elapsed, reset the counter so we don't throttle */
  if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_PERIOD)
    entry->attempts = 0;
  else if (0 == ++entry->attempts)
    --entry->attempts;  /* Disallow overflow */

  entry->last_connect = NOW;
  free_targets = ip_registry_update_free_targets(entry);

  if (entry->attempts < IPCHECK_CLONE_LIMIT && next_target_out)
      *next_target_out = CurrentTime - (TARGET_DELAY * free_targets - 1);
  else if ((CurrentTime - me.since) > IPCHECK_CLONE_DELAY) {
#ifdef NOTHROTTLE 
    return 1;
#else
    --entry->connected;
    return 0;
#endif        
  }

  return 1;
}


/*----------------------------------------------------------------------------
 * IPcheck_remote_connect
 *
 * Event:
 *   A remote client connected to Undernet, with IP number `cptr->ip.s_addr'
 *   and hostname `hostname'.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Return 0 on failure, 1 on success.
 *--------------------------------------------------------------------------*/
int ip_registry_check_remote(struct Client* cptr, int is_burst) {
  ip_reg_entry_t *entry = ip_registry_find(cptr->ip.s_addr);

  SetIPChecked(cptr);

  if (0 == entry)
    entry = ip_registry_new_entry(cptr->ip.s_addr, (is_burst ? 0 : 1));
  else {
    /* NEVER more than 255 connections. */
    if (0 == ++entry->connected)
      return 0;

    /* Make sure we don't bounce if our threshhold has expired */
    if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_PERIOD)
      entry->attempts = 0;

    /* If we're not part of a burst, go ahead and process the rest */
    if (!is_burst) {
      if (0 == ++entry->attempts)
        --entry->attempts;  /* Overflows are bad, mmmkay? */
      ip_registry_update_free_targets(entry);
      entry->last_connect = NOW;
    }
  }

  return 1;
}

/*----------------------------------------------------------------------------
 * IPcheck_connect_fail
 *
 * Event:
 *   This local client failed to connect due to legal reasons.
 *
 * Action:
 *   Neutralize the effect of calling IPcheck_local_connect, in such
 *   a way that the client won't be penalized when trying to reconnect
 *   again.
 *--------------------------------------------------------------------------*/
void ip_registry_connect_fail(unsigned int addr) {
  ip_reg_entry_t *entry = ip_registry_find(addr);

  if (entry)
    --entry->attempts;
}


/*----------------------------------------------------------------------------
 * IPcheck_connect_succeeded
 *
 * Event:
 *   A client succeeded to finish the registration.
 *
 * Finish IPcheck registration of a successfully, locally connected client.
 *--------------------------------------------------------------------------*/
void ip_registry_connect_succeeded(struct Client *cptr) {
  const char     *tr           = "";
  unsigned int free_targets     = STARTTARGETS;
  ip_reg_entry_t *entry        = ip_registry_find(cptr->ip.s_addr);

  if (!entry) {
    Debug((DEBUG_ERROR, "Missing registry entry for: %s", cptr->sock_ip));
    return;
  }

  if (entry->target) {
    memcpy(cptr->targets, entry->target->targets, MAXTARGETS);
    free_targets = entry->target->count;
    tr = " tr";
  }

  sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :on %u ca %u(%u) ft %u(%u)%s",
		cptr, entry->connected, entry->attempts, IPCHECK_CLONE_LIMIT,
		free_targets, STARTTARGETS, tr);
}


/*----------------------------------------------------------------------------
 * IPcheck_disconnect
 *
 * Event:
 *   A local client disconnected or a remote client left Undernet.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Remove all expired IPregistry structures from the hash bucket
 *     that belongs to this clients IP number.
 *--------------------------------------------------------------------------*/
void ip_registry_disconnect(struct Client *cptr) {
  ip_reg_entry_t *entry = ip_registry_find(cptr->ip.s_addr);

  /* Entry is probably a server if this happens. */
  if (0 == entry)
    return;


  /*
   * If this was the last one, set `last_connect' to disconnect time
   * (used for expiration)   Note that we reset attempts here as well if our
   * threshhold hasn't been crossed.
   */
  if (0 == --entry->connected) {
    if (CONNECTED_SINCE(entry) > IPCHECK_CLONE_LIMIT * IPCHECK_CLONE_PERIOD)
      entry->attempts = 0;
    ip_registry_update_free_targets(entry);
    entry->last_connect = NOW;
  }


  if (MyConnect(cptr)) {
    unsigned int free_targets;

    if (0 == entry->target) {
      entry->target = (iptarget_entry_t *)MyMalloc(sizeof(iptarget_entry_t));
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

    /* Add bonus, this is pretty fuzzy, but it will help in some cases. */
    if ((CurrentTime - cptr->firsttime) > 600)
      free_targets += (CurrentTime - cptr->firsttime - 600) / TARGET_DELAY;

    /* Finally, store smallest value for Judgement Day */
    if (free_targets < entry->target->count)
      entry->target->count = free_targets;
  }
}

/*----------------------------------------------------------------------------
 * IPcheck_nr
 *
 * Returns number of clients with the same IP number
 *--------------------------------------------------------------------------*/
int ip_registry_count(unsigned int addr) {
  ip_reg_entry_t *entry = ip_registry_find(addr);
  return (entry) ? entry->connected : 0;
}


/*----------------------------------------------------------------------------
 * IPcheck_local_connect
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
 *--------------------------------------------------------------------------*/
int IPcheck_local_connect(struct in_addr a, time_t* next_target_out) {
  assert(0 != next_target_out);
  return ip_registry_check_local(a.s_addr, next_target_out);
}


/*----------------------------------------------------------------------------
 * IPcheck_remote_connect
 *
 * Event:
 *   A remote client connected to Undernet, with IP number `cptr->ip.s_addr'
 *   and hostname `hostname'.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Return 0 on failure, 1 on success.
 *--------------------------------------------------------------------------*/
int IPcheck_remote_connect(struct Client *cptr, int is_burst) {
  assert(0 != cptr);
  return ip_registry_check_remote(cptr, is_burst);
}


/*----------------------------------------------------------------------------
 * IPcheck_connect_fail
 *
 * Event:
 *   This local client failed to connect due to legal reasons.
 *
 * Action:
 *   Neutralize the effect of calling IPcheck_local_connect, in such
 *   a way that the client won't be penalized when trying to reconnect
 *   again.
 *--------------------------------------------------------------------------*/
void IPcheck_connect_fail(struct in_addr a) {
  ip_registry_connect_fail(a.s_addr);
}


/*----------------------------------------------------------------------------
 * IPcheck_connect_succeeded
 *
 * Event:
 *   A client succeeded to finish the registration.
 *
 * Finish IPcheck registration of a successfully, locally connected client.
 *--------------------------------------------------------------------------*/
void IPcheck_connect_succeeded(struct Client *cptr) {
  assert(0 != cptr);
  ip_registry_connect_succeeded(cptr);
}


/*----------------------------------------------------------------------------
 * IPcheck_disconnect
 *
 * Event:
 *   A local client disconnected or a remote client left Undernet.
 *
 * Action:
 *   Update the IPcheck registry.
 *   Remove all expired IPregistry structures from the hash bucket
 *     that belongs to this clients IP number.
 *--------------------------------------------------------------------------*/
void IPcheck_disconnect(struct Client *cptr) {
  assert(0 != cptr);
  ip_registry_disconnect(cptr);
}


/*----------------------------------------------------------------------------
 * IPcheck_nr
 *
 * Returns number of clients with the same IP number
 *--------------------------------------------------------------------------*/
unsigned short IPcheck_nr(struct Client *cptr) {
  assert(0 != cptr);
  return ip_registry_count(cptr->ip.s_addr);
}


/*----------------------------------------------------------------------------
 * IPcheck_expire
 *
 * Expire old entries
 *--------------------------------------------------------------------------*/
void IPcheck_expire() {
  static time_t next_expire = 0;

  if (next_expire < CurrentTime) {
    ip_registry_expire();
    next_expire = CurrentTime + 60;
  }
}
