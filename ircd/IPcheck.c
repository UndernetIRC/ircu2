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
 * 
 * This file should be edited in a window with a width of 141 characters
 * ick
 */
#include "config.h"

#include "IPcheck.h"
#include "client.h"
#include "ircd.h"
#include "msg.h"
#include "numnicks.h"       /* NumNick, NumServ (GODMODE) */
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "s_debug.h"        /* Debug */
#include "s_user.h"         /* TARGET_DELAY */
#include "send.h"

#include <assert.h>
#include <string.h>

struct IPTargetEntry {
  int           count;
  unsigned char targets[MAXTARGETS];
};

struct IPRegistryEntry {
  struct IPRegistryEntry*  next;
  struct IPTargetEntry*    target;
  unsigned int             addr;
  int		           last_connect;
  unsigned short           connected;
  unsigned char            attempts;
};

/*
 * Hash table for IPv4 address registry
 *
 * Hash table size must be a power of 2
 * Use 64K hash table to conserve memory
 */
#define IP_REGISTRY_TABLE_SIZE 0x10000
#define MASK_16                0xffff

#define NOW ((unsigned short)(CurrentTime & MASK_16))
#define CONNECTED_SINCE(x) (NOW - (x))

#define IPCHECK_CLONE_LIMIT 4
#define IPCHECK_CLONE_PERIOD 40
#define IPCHECK_CLONE_DELAY 600


static struct IPRegistryEntry* hashTable[IP_REGISTRY_TABLE_SIZE];
static struct IPRegistryEntry* freeList = 0;

static struct Timer expireTimer;

static unsigned int ip_registry_hash(unsigned int ip)
{
  return ((ip >> 16) ^ ip) & (IP_REGISTRY_TABLE_SIZE - 1);
}

static struct IPRegistryEntry* ip_registry_find(unsigned int ip)
{
  struct IPRegistryEntry* entry = hashTable[ip_registry_hash(ip)];
  for ( ; entry; entry = entry->next) {
    if (entry->addr == ip)
      break;
  }
  return entry;
}

static void ip_registry_add(struct IPRegistryEntry* entry)
{
  unsigned int bucket = ip_registry_hash(entry->addr);
  entry->next = hashTable[bucket];
  hashTable[bucket] = entry;
}
  
static void ip_registry_remove(struct IPRegistryEntry* entry)
{
  unsigned int bucket = ip_registry_hash(entry->addr);
  if (hashTable[bucket] == entry)
    hashTable[bucket] = entry->next;
  else {
    struct IPRegistryEntry* prev = hashTable[bucket];
    for ( ; prev; prev = prev->next) {
      if (prev->next == entry) {
        prev->next = entry->next;
        break;
      }
    }
  }
}
 
static struct IPRegistryEntry* ip_registry_new_entry()
{
  struct IPRegistryEntry* entry = freeList;
  if (entry)
    freeList = entry->next;
  else
    entry = (struct IPRegistryEntry*) MyMalloc(sizeof(struct IPRegistryEntry));

  assert(0 != entry);
  memset(entry, 0, sizeof(struct IPRegistryEntry));
  entry->last_connect = NOW;     /* Seconds since last connect attempt */
  entry->connected    = 1;       /* connected clients for this IP */
  entry->attempts     = 1;       /* Number attempts for this IP */
  return entry;
}

static void ip_registry_delete_entry(struct IPRegistryEntry* entry)
{
  if (entry->target)
    MyFree(entry->target);
  entry->next = freeList;
  freeList = entry;
}

static unsigned int ip_registry_update_free_targets(struct IPRegistryEntry* entry)
{
  unsigned int free_targets = STARTTARGETS;

  if (entry->target) {
    free_targets = entry->target->count + (CONNECTED_SINCE(entry->last_connect) / TARGET_DELAY);
    if (free_targets > STARTTARGETS)
      free_targets = STARTTARGETS;
    entry->target->count = free_targets;
  }
  return free_targets;
}

static void ip_registry_expire_entry(struct IPRegistryEntry* entry)
{
  /*
   * Don't touch this number, it has statistical significance
   * XXX - blah blah blah
   */
  if (CONNECTED_SINCE(entry->last_connect) > 600) {
    /*
     * expired
     */
    ip_registry_remove(entry);
    ip_registry_delete_entry(entry);
  }
  else if (CONNECTED_SINCE(entry->last_connect) > 120 && 0 != entry->target) {
    /*
     * Expire storage of targets
     */
    MyFree(entry->target);
    entry->target = 0;
  }
}

/* Callback to run an expiry of the IPcheck registry */
static void ip_registry_expire(struct Event* ev)
{
  int i;
  struct IPRegistryEntry* entry;
  struct IPRegistryEntry* entry_next;

  assert(ET_EXPIRE == ev_type(ev));
  assert(0 != ev_timer(ev));

  for (i = 0; i < IP_REGISTRY_TABLE_SIZE; ++i) {
    for (entry = hashTable[i]; entry; entry = entry_next) {
      entry_next = entry->next;
      if (0 == entry->connected)
        ip_registry_expire_entry(entry);
    }
  }
}

/*
 * IPcheck_init()
 *
 * Initializes the registry timer
 */
void IPcheck_init(void)
{
  timer_add(timer_init(&expireTimer), ip_registry_expire, 0, TT_PERIODIC, 60);
}

/*
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
 */
int ip_registry_check_local(unsigned int addr, time_t* next_target_out)
{
  struct IPRegistryEntry* entry = ip_registry_find(addr);
  unsigned int free_targets = STARTTARGETS;
 
  if (0 == entry) {
    entry       = ip_registry_new_entry();
    entry->addr = addr;    /* The IP number of registry entry */
    ip_registry_add(entry);
    return 1;
  }
  /* Note that this also connects server connects.
   * It is hard and not interesting, to change that.
   *
   * Don't allow more then 255 connects from one IP number, ever
   */
  if (0 == ++entry->connected)
    return 0;

  if (CONNECTED_SINCE(entry->last_connect) > IPCHECK_CLONE_PERIOD)
    entry->attempts = 0;

  free_targets = ip_registry_update_free_targets(entry);
  entry->last_connect = NOW;

  if (0 == ++entry->attempts)   /* Check for overflow */
    --entry->attempts;

  if (entry->attempts < IPCHECK_CLONE_LIMIT) {
    if (next_target_out)
      *next_target_out = CurrentTime - (TARGET_DELAY * free_targets - 1);
  }
  else if ((CurrentTime - cli_since(&me)) > IPCHECK_CLONE_DELAY) {
    /* 
     * Don't refuse connection when we just rebooted the server
     */
#ifdef NOTHROTTLE 
    return 1;
#else
    --entry->connected;
    return 0;
#endif        
  }
  return 1;
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
 *   Return 0 on failure, 1 on success.
 */
int ip_registry_check_remote(struct Client* cptr, int is_burst)
{
  struct IPRegistryEntry* entry = ip_registry_find((cli_ip(cptr)).s_addr);

  /*
   * Mark that we did add/update an IPregistry entry
   */
  SetIPChecked(cptr);
  if (0 == entry) {
    entry = ip_registry_new_entry();
    entry->addr = (cli_ip(cptr)).s_addr;
    if (is_burst)
      entry->attempts = 0;
    ip_registry_add(entry);
  }
  else {
    if (0 == ++entry->connected) {
      /* 
       * Don't allow more then 255 connects from one IP number, ever
       */
      return 0;
    }
    if (CONNECTED_SINCE(entry->last_connect) > IPCHECK_CLONE_PERIOD)
      entry->attempts = 0;
    if (!is_burst) {
      if (0 == ++entry->attempts) {
        /*
         * Check for overflow
         */
        --entry->attempts;
      }
      ip_registry_update_free_targets(entry);
      entry->last_connect = NOW;
    }
  }
  return 1;
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
void ip_registry_connect_fail(unsigned int addr)
{
  struct IPRegistryEntry* entry = ip_registry_find(addr);
  if (entry)
    --entry->attempts;
}

/*
 * IPcheck_connect_succeeded
 *
 * Event:
 *   A client succeeded to finish the registration.
 *
 * Finish IPcheck registration of a successfully, locally connected client.
 */
void ip_registry_connect_succeeded(struct Client *cptr)
{
  const char*             tr    = "";
  unsigned int free_targets     = STARTTARGETS;
  struct IPRegistryEntry* entry = ip_registry_find((cli_ip(cptr)).s_addr);

  if (!entry) {
    Debug((DEBUG_ERROR, "Missing registry entry for: %s", cli_sock_ip(cptr)));
    return;
  }
  if (entry->target) {
    memcpy(cli_targets(cptr), entry->target->targets, MAXTARGETS);
    free_targets = entry->target->count;
    tr = " tr";
  }
  sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :on %u ca %u(%u) ft %u(%u)%s",
		cptr, entry->connected, entry->attempts, IPCHECK_CLONE_LIMIT,
		free_targets, STARTTARGETS, tr);
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
void ip_registry_disconnect(struct Client *cptr)
{
  struct IPRegistryEntry* entry = ip_registry_find((cli_ip(cptr)).s_addr);
  if (0 == entry) {
    /*
     * trying to find an entry for a server causes this to happen,
     * servers should never have FLAG_IPCHECK set
     */
    return;
  }
  /*
   * If this was the last one, set `last_connect' to disconnect time (used for expiration)
   */
  if (0 == --entry->connected) {
    if (CONNECTED_SINCE(entry->last_connect) > IPCHECK_CLONE_LIMIT * IPCHECK_CLONE_PERIOD) {
      /*
       * Otherwise we'd penetalize for this old value if the client reconnects within 20 seconds
       */
      entry->attempts = 0;
    }
    ip_registry_update_free_targets(entry);
    entry->last_connect = NOW;
  }
  if (MyConnect(cptr)) {
    unsigned int free_targets;
    /*
     * Copy the clients targets
     */
    if (0 == entry->target) {
      entry->target = (struct IPTargetEntry*) MyMalloc(sizeof(struct IPTargetEntry));
      entry->target->count = STARTTARGETS;
    }
    assert(0 != entry->target);

    memcpy(entry->target->targets, cli_targets(cptr), MAXTARGETS);
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
    if (cli_nexttarget(cptr) < CurrentTime) {
        /*
         * Number of free targets
         */
      free_targets = (CurrentTime - cli_nexttarget(cptr)) / TARGET_DELAY + 1;
    }
    else
      free_targets = 0;
    /*
     * Add bonus, this is pretty fuzzy, but it will help in some cases.
     */
    if ((CurrentTime - cli_firsttime(cptr)) > 600)
      /*
       * Was longer then 10 minutes online?
       */
      free_targets += (CurrentTime - cli_firsttime(cptr) - 600) / TARGET_DELAY;
    /*
     * Finally, store smallest value for Judgement Day
     */
    if (free_targets < entry->target->count)
      entry->target->count = free_targets;
  }
}

/*
 * IPcheck_nr
 *
 * Returns number of clients with the same IP number
 */
int ip_registry_count(unsigned int addr)
{
  struct IPRegistryEntry* entry = ip_registry_find(addr);
  return (entry) ? entry->connected : 0;
}

/*
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
 */
int IPcheck_local_connect(struct in_addr a, time_t* next_target_out)
{
  assert(0 != next_target_out);
  return ip_registry_check_local(a.s_addr, next_target_out);
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
 *   Return 0 on failure, 1 on success.
 */
int IPcheck_remote_connect(struct Client *cptr, int is_burst)
{
  assert(0 != cptr);
  return ip_registry_check_remote(cptr, is_burst);
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
void IPcheck_connect_fail(struct in_addr a)
{
  ip_registry_connect_fail(a.s_addr);
}

/*
 * IPcheck_connect_succeeded
 *
 * Event:
 *   A client succeeded to finish the registration.
 *
 * Finish IPcheck registration of a successfully, locally connected client.
 */
void IPcheck_connect_succeeded(struct Client *cptr)
{
  assert(0 != cptr);
  ip_registry_connect_succeeded(cptr);
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
void IPcheck_disconnect(struct Client *cptr)
{
  assert(0 != cptr);
  ip_registry_disconnect(cptr);
}

/*
 * IPcheck_nr
 *
 * Returns number of clients with the same IP number
 */
unsigned short IPcheck_nr(struct Client *cptr)
{
  assert(0 != cptr);
  return ip_registry_count(cli_ip(cptr).s_addr);
}
