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
/** @file
 * @brief Code to count users connected from particular IP addresses.
 * @version $Id$
 */
#include "config.h"

#include "IPcheck.h"
#include "client.h"
#include "ircd.h"
#include "match.h"
#include "msg.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"    /* ircd_ntoa */
#include "s_debug.h"        /* Debug */
#include "s_user.h"         /* TARGET_DELAY */
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Stores free target information for a particular user. */
struct IPTargetEntry {
  unsigned int  count; /**< Number of free targets targets. */
  unsigned char targets[MAXTARGETS]; /**< Array of recent targets. */
};

/** Stores recent information about a particular IP address. */
struct IPRegistryEntry {
  struct IPRegistryEntry*  next;   /**< Next entry in the hash chain. */
  struct IPTargetEntry*    target; /**< Recent targets, if any. */
  struct irc_in_addr       addr;   /**< IP address for this user. */
  int		           last_connect; /**< Last connection attempt timestamp. */
  unsigned short           connected; /**< Number of currently connected clients. */
  unsigned char            attempts; /**< Number of recent connection attempts. */
};

/** Stores information about an IPv6/48 block's recent connections. */
struct IPRegistry48 {
  struct IPRegistry48* next;     /**< Next entry in the hash chain. */
  int              last_connect; /**< Last connection attempt timestamp. */
  uint16_t             addr[3];  /**< 48 MSBs of IP address. */
  unsigned short       attempts; /**< Number of recent connection attempts. */
};

/** Size of hash table (must be a power of two). */
#define IP_REGISTRY_TABLE_SIZE 0x10000
/** Report current time for tracking in IPRegistryEntry::last_connect. */
#define NOW ((unsigned short)(CurrentTime & 0xffff))
/** Time from \a x until now, in seconds. */
#define CONNECTED_SINCE(x) (NOW - (x))

/** Macro for easy access to configured IPcheck clone limit. */
#define IPCHECK_CLONE_LIMIT feature_int(FEAT_IPCHECK_CLONE_LIMIT)
/** Macro for easy access to configured IPcheck clone period. */
#define IPCHECK_CLONE_PERIOD feature_int(FEAT_IPCHECK_CLONE_PERIOD)
/** Macro for easy access to configured /48 clone limit. */
#define IPCHECK_48_CLONE_LIMIT feature_int(FEAT_IPCHECK_48_CLONE_LIMIT)
/** Macro for easy access to configured 48 clone period. */
#define IPCHECK_48_CLONE_PERIOD feature_int(FEAT_IPCHECK_48_CLONE_PERIOD)
/** Macro for easy access to configured IPcheck clone delay. */
#define IPCHECK_CLONE_DELAY feature_int(FEAT_IPCHECK_CLONE_DELAY)

/** Hash table for storing IPRegistryEntry entries. */
static struct IPRegistryEntry* hashTable[IP_REGISTRY_TABLE_SIZE];
/** Hash table for storing IPRegistry48 entries. */
static struct IPRegistry48* hashTable48[IP_REGISTRY_TABLE_SIZE];
/** List of allocated but unused IPRegistryEntry structs. */
static struct IPRegistryEntry* freeList;
/** List of allocated but unused IPRegistry48 structs. */
static struct IPRegistry48* freeList48;
/** Periodic timer to look for too-old registry entries. */
static struct Timer expireTimer;

/** Convert IP addresses to canonical form for comparison.  IPv4
 * addresses are translated into 6to4 form; IPv6 addresses are
 * truncated to their /64 prefix.
 *
 * @param[out] out Receives canonical format for address.
 * @param[in] in IP address to canonicalize.
 */
static void ip_registry_canonicalize(struct irc_in_addr *out, const struct irc_in_addr *in)
{
    if (irc_in_addr_is_ipv4(in)) {
        out->in6_16[0] = htons(0x2002);
        out->in6_16[1] = in->in6_16[6];
        out->in6_16[2] = in->in6_16[7];
        out->in6_16[3] = 0;
    } else {
        out->in6_16[0] = in->in6_16[0];
        out->in6_16[1] = in->in6_16[1];
        out->in6_16[2] = in->in6_16[2];
        out->in6_16[3] = in->in6_16[3];
    }

    out->in6_16[4] = out->in6_16[5] = 0;
    out->in6_16[6] = out->in6_16[7] = 0;
}

/** Calculate hash value for an IP address.
 * @param[in] ip Address to hash; must be in canonical form.
 * @return Hash value for address.
 */
static unsigned int ip_registry_hash(const struct irc_in_addr *ip)
{
  unsigned int res;
  /* Only use the first 64 bits of address, since the last 64 bits
   * tend to be under user control. */
  res = ip->in6_16[0] ^ ip->in6_16[1] ^ ip->in6_16[2] ^ ip->in6_16[3];
  return res & (IP_REGISTRY_TABLE_SIZE - 1);
}

/** Find an IP registry entry if one exists for the IP address.
 * If \a ip looks like an IPv6 address, only consider the first 64 bits
 * of the address. Otherwise, only consider the final 32 bits.
 * @param[in] ip IP address to search for.
 * @return Matching registry entry, or NULL if none exists.
 */
static struct IPRegistryEntry* ip_registry_find(const struct irc_in_addr *ip)
{
  struct irc_in_addr canon;
  struct IPRegistryEntry* entry;
  ip_registry_canonicalize(&canon, ip);
  entry = hashTable[ip_registry_hash(&canon)];
  for ( ; entry; entry = entry->next) {
    int bits = (canon.in6_16[0] == htons(0x2002)) ? 48 : 64;
    if (ipmask_check(&canon, &entry->addr, bits))
      break;
  }
  return entry;
}

/** Add an IP registry entry to the hash table.
 * @param[in] entry Registry entry to add.
 */
static void ip_registry_add(struct IPRegistryEntry* entry)
{
  unsigned int bucket = ip_registry_hash(&entry->addr);
  entry->next = hashTable[bucket];
  hashTable[bucket] = entry;
}

/** Remove an IP registry entry from the hash table.
 * @param[in] entry Registry entry to add.
 */
static void ip_registry_remove(struct IPRegistryEntry* entry)
{
  unsigned int bucket = ip_registry_hash(&entry->addr);
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

/** Allocate a new IP registry entry.
 * For members that have a sensible default value, that is used.
 * @return Newly allocated registry entry.
 */
static struct IPRegistryEntry* ip_registry_new_entry(void)
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

/** Deallocate memory for \a entry.
 * The entry itself is prepended to #freeList.
 * @param[in] entry IP registry entry to release.
 */
static void ip_registry_delete_entry(struct IPRegistryEntry* entry)
{
  if (entry->target)
    MyFree(entry->target);
  entry->next = freeList;
  freeList = entry;
}

/** Update free target count for \a entry.
 * @param[in,out] entry IP registry entry to update.
 */
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

/** Check whether all or part of \a entry needs to be expired.
 * If the entry is at least 600 seconds stale, free the entire thing.
 * If it is at least 120 seconds stale, expire its free targets list.
 * @param[in] entry Registry entry to check for expiration.
 */
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
    Debug((DEBUG_DNS, "IPcheck expiring registry for %s (no clients connected).", ircd_ntoa(&entry->addr)));
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

/** Calculate hash value for an IP address's /48 block.
 * @param[in] ip Address to hash; must be an IPv6 address.
 * @return Hash value for address.
 */
static unsigned int ip_48_hash(const struct irc_in_addr *ip)
{
  unsigned int res;
  res = ip->in6_16[0] ^ ip->in6_16[1] ^ ip->in6_16[2];
  return res & (IP_REGISTRY_TABLE_SIZE - 1);
}

/** Find or create an IPv6 /48 entry for the IP address.
 * @param[in] ip IPv6 address to search for.
 * @return Matching registry entry (possibly newly created).
 */
static struct IPRegistry48* ip_48_find(const struct irc_in_addr *ip)
{
  struct IPRegistry48* entry;
  unsigned int idx;

  /* Does it exist in the chain? */
  idx = ip_48_hash(ip);
  for (entry = hashTable48[idx]; entry; entry = entry->next) {
    if ((ip->in6_16[0] == entry->addr[0])
        && (ip->in6_16[1] == entry->addr[1])
        && (ip->in6_16[2] == entry->addr[2]))
      goto done;
  }

  /* Where do we get the next entry? */
  entry = freeList48;
  if (entry)
    freeList48 = entry->next;
  else
    entry = MyMalloc(sizeof(*entry));

  /* Initialize this entry. */
  entry->last_connect = NOW;
  entry->addr[0]  = ip->in6_16[0];
  entry->addr[1]  = ip->in6_16[1];
  entry->addr[2]  = ip->in6_16[2];
  entry->attempts = 0;

  /* Link it into the hash table. */
  entry->next = hashTable48[idx];
  hashTable48[idx] = entry;

done:
  return entry;
}

/** Periodic timer callback to check for expired registry entries.
 * @param[in] ev Timer event (ignored).
 */
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

  for (i = 0; i < IP_REGISTRY_TABLE_SIZE; ++i) {
    struct IPRegistry48** prev_p;
    struct IPRegistry48* entry;

    for (prev_p = &hashTable48[i]; (entry = *prev_p); ) {
      if (CONNECTED_SINCE(entry->last_connect) > 600) {
        *prev_p = entry->next;
        entry->next = freeList48;
        freeList48 = entry;
      } else
        prev_p = &entry->next;
    }
  }
}

/** Initialize the IPcheck subsystem. */
void IPcheck_init(void)
{
  timer_add(timer_init(&expireTimer), ip_registry_expire, 0, TT_PERIODIC, 60);
}

/** Check whether a new connection from a local client should be allowed.
 * A connection is rejected if someone from the "same" address (see
 * ip_registry_find()) connects IPCHECK_CLONE_LIMIT times, each time
 * separated by no more than IPCHECK_CLONE_PERIOD seconds.
 * @param[in] addr Address of client.
 * @param[out] next_target_out Receives time to grant another free target.
 * @return Non-zero if the connection is permitted, zero if denied.
 */
int ip_registry_check_local(const struct irc_in_addr *addr, time_t* next_target_out)
{
  struct IPRegistryEntry* entry = ip_registry_find(addr);
  unsigned int free_targets = STARTTARGETS;

  if (!irc_in_addr_is_ipv4(addr)) {
    struct IPRegistry48* entry_48 = ip_48_find(addr);

    if (CONNECTED_SINCE(entry_48->last_connect) > IPCHECK_48_CLONE_PERIOD)
      entry_48->attempts = 0;

    entry_48->last_connect = NOW;
    if (0 == ++entry_48->attempts)
      --entry_48->attempts;

#ifndef NOTHROTTLE
    if ((entry_48->attempts >= IPCHECK_48_CLONE_LIMIT)
        && ((CurrentTime - cli_since(&me) > IPCHECK_CLONE_DELAY)))
    {
      if (entry)
      {
        entry->last_connect = NOW;
        if (!++entry->connected)
        {
          entry->connected--;
          entry = NULL;
        }
      }
      goto reject;
    }
#endif
  }

  if (0 == entry) {
    entry       = ip_registry_new_entry();
    ip_registry_canonicalize(&entry->addr, addr);
    ip_registry_add(entry);
    Debug((DEBUG_DNS, "IPcheck added new registry for local connection from %s.", ircd_ntoa(&entry->addr)));
    return 1;
  }
  /* Note that this also counts server connects.
   * It is hard and not interesting, to change that.
   * Refuse connection if it would overflow the counter.
   */
  if (0 == ++entry->connected)
  {
    entry->connected--;
    Debug((DEBUG_DNS, "IPcheck refusing local connection from %s: counter overflow.", ircd_ntoa(&entry->addr)));
    return 0;
  }

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
#ifndef NOTHROTTLE
  else if ((CurrentTime - cli_since(&me)) > IPCHECK_CLONE_DELAY) {
    /*
     * Don't refuse connection when we just rebooted the server
     */
reject:
    if (entry)
    {
      assert(entry->connected > 0);
      --entry->connected;
    }
    Debug((DEBUG_DNS, "IPcheck refusing local connection from %s: too fast.", ircd_ntoa(addr)));
    return 0;
  }
#endif
  Debug((DEBUG_DNS, "IPcheck accepting local connection from %s.", ircd_ntoa(&entry->addr)));
  return 1;
}

/** Check whether a connection from a remote client should be allowed.
 * This is much more relaxed than ip_registry_check_local(): The only
 * cause for rejection is when the IPRegistryEntry::connected counter
 * would overflow.
 * @param[in] cptr Client that has connected.
 * @param[in] is_burst Non-zero if client was introduced during a burst.
 * @return Non-zero if the client should be accepted, zero if they must be killed.
 */
int ip_registry_check_remote(struct Client* cptr, int is_burst)
{
  struct IPRegistryEntry* entry;

  /*
   * Mark that we did add/update an IPregistry entry
   */
  SetIPChecked(cptr);
  if (!irc_in_addr_valid(&cli_ip(cptr))) {
    Debug((DEBUG_DNS, "IPcheck accepting remote connection from invalid %s.", ircd_ntoa(&cli_ip(cptr))));
    return 1;
  }

  if (!irc_in_addr_is_ipv4(&cli_ip(cptr))) {
    struct IPRegistry48* entry_48 = ip_48_find(&cli_ip(cptr));
    if (CONNECTED_SINCE(entry_48->last_connect) > IPCHECK_48_CLONE_PERIOD)
      entry_48->attempts = 0;
    if (0 == ++entry_48->attempts)
      --entry_48->attempts;
    entry_48->last_connect = NOW;
  }

  entry = ip_registry_find(&cli_ip(cptr));
  if (0 == entry) {
    entry = ip_registry_new_entry();
    ip_registry_canonicalize(&entry->addr, &cli_ip(cptr));
    if (is_burst)
      entry->attempts = 0;
    ip_registry_add(entry);
    Debug((DEBUG_DNS, "IPcheck added new registry for remote connection from %s.", ircd_ntoa(&entry->addr)));
    return 1;
  }
  /* Avoid overflowing the connection counter. */
  if (0 == ++entry->connected) {
    Debug((DEBUG_DNS, "IPcheck refusing remote connection from %s: counter overflow.", ircd_ntoa(&entry->addr)));
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
  Debug((DEBUG_DNS, "IPcheck counting remote connection from %s.", ircd_ntoa(&entry->addr)));
  return 1;
}

/** Handle a client being rejected during connection through no fault
 * of their own.  This "undoes" the effect of ip_registry_check_local()
 * so the client's address is not penalized for the failure.
 * @param[in] addr Address of rejected client.
 * @param[in] disconnect If true, also count the client as disconnecting.
 */
void ip_registry_connect_fail(const struct irc_in_addr *addr, int disconnect)
{
  struct IPRegistryEntry* entry = ip_registry_find(addr);

  if (!irc_in_addr_is_ipv4(addr)) {
    struct IPRegistry48* entry_48 = ip_48_find(addr);
    if (0 == --entry_48->attempts)
      ++entry_48->attempts;
  }

  if (entry) {
    if (0 == --entry->attempts) {
      Debug((DEBUG_DNS, "IPcheck noting local connection failure for %s.", ircd_ntoa(&entry->addr)));
      ++entry->attempts;
    }
    if (disconnect) {
      assert(entry->connected > 0);
      entry->connected--;
    }
  }
}

/** Handle a client that has successfully connected.
 * This copies free target information to \a cptr from his address's
 * registry entry and sends him a NOTICE describing the parameters for
 * the entry.
 * @param[in,out] cptr Client that has successfully connected.
 */
void ip_registry_connect_succeeded(struct Client *cptr)
{
  const char*             tr    = "";
  unsigned int free_targets     = STARTTARGETS;
  struct IPRegistryEntry* entry = ip_registry_find(&cli_ip(cptr));

  assert(entry);
  if (entry->target) {
    memcpy(cli_targets(cptr), entry->target->targets, MAXTARGETS);
    free_targets = entry->target->count;
    tr = " tr";
  }
  Debug((DEBUG_DNS, "IPcheck noting local connection success for %s.", ircd_ntoa(&entry->addr)));
  sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :on %u ca %u(%u) ft %u(%u)%s",
		cptr, entry->connected, entry->attempts, IPCHECK_CLONE_LIMIT,
		free_targets, STARTTARGETS, tr);
}

/** Handle a client that decided to disconnect (or was killed after
 * completing his connection).  This updates the free target
 * information for his IP registry entry.
 * @param[in] cptr Client that has exited.
 */
void ip_registry_disconnect(struct Client *cptr)
{
  struct IPRegistryEntry* entry = ip_registry_find(&cli_ip(cptr));
  if (!irc_in_addr_valid(&cli_ip(cptr))) {
    Debug((DEBUG_DNS, "IPcheck noting dicconnect from invalid %s.", ircd_ntoa(&cli_ip(cptr))));
    return;
  }
  assert(entry);
  assert(entry->connected > 0);
  Debug((DEBUG_DNS, "IPcheck noting disconnect from %s.", ircd_ntoa(&entry->addr)));
  /*
   * If this was the last one, set `last_connect' to disconnect time (used for expiration)
   */
  if (0 == --entry->connected) {
    if (CONNECTED_SINCE(entry->last_connect) > IPCHECK_CLONE_LIMIT * IPCHECK_CLONE_PERIOD) {
      /*
       * Otherwise we'd penalize for this old value if the client reconnects within 20 seconds
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
     * messages or by drastically increasing the amount of memory used in the IPregistry.
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
     * Finally, store smallest value for Judgment Day
     */
    if (free_targets < entry->target->count)
      entry->target->count = free_targets;
  }
}

/** Find number of clients from a particular IP address.
 * @param[in] addr Address to look up.
 * @return Number of clients known to be connected from that address.
 */
int ip_registry_count(const struct irc_in_addr *addr)
{
  struct IPRegistryEntry* entry = ip_registry_find(addr);
  return (entry) ? entry->connected : 0;
}

/** Check whether a client is allowed to connect locally.
 * @param[in] a Address of client.
 * @param[out] next_target_out Receives time to grant another free target.
 * @return Non-zero if the connection is permitted, zero if denied.
 */
int IPcheck_local_connect(const struct irc_in_addr *a, time_t* next_target_out)
{
  assert(0 != next_target_out);
  return ip_registry_check_local(a, next_target_out);
}

/** Check whether a client is allowed to connect remotely.
 * @param[in] cptr Client that has connected.
 * @param[in] is_burst Non-zero if client was introduced during a burst.
 * @return Non-zero if the client should be accepted, zero if they must be killed.
 */
int IPcheck_remote_connect(struct Client *cptr, int is_burst)
{
  assert(0 != cptr);
  assert(!IsIPChecked(cptr));
  return ip_registry_check_remote(cptr, is_burst);
}

/** Handle a client being rejected during connection through no fault
 * of their own.  This "undoes" the effect of ip_registry_check_local()
 * so the client's address is not penalized for the failure.
 * @param[in] cptr Client who has been rejected.
 * @param[in] disconnect If true, also count the client as disconnecting.
 */
void IPcheck_connect_fail(const struct Client *cptr, int disconnect)
{
  assert(IsIPChecked(cptr));
  ip_registry_connect_fail(&cli_ip(cptr), disconnect);
}

/** Handle a client that has successfully connected.
 * This copies free target information to \a cptr from his address's
 * registry entry and sends him a NOTICE describing the parameters for
 * the entry.
 * @param[in,out] cptr Client that has successfully connected.
 */
void IPcheck_connect_succeeded(struct Client *cptr)
{
  assert(0 != cptr);
  assert(IsIPChecked(cptr));
  ip_registry_connect_succeeded(cptr);
}

/** Handle a client that decided to disconnect (or was killed after
 * completing his connection).  This updates the free target
 * information for his IP registry entry.
 * @param[in] cptr Client that has exited.
 */
void IPcheck_disconnect(struct Client *cptr)
{
  assert(0 != cptr);
  assert(IsIPChecked(cptr));
  ip_registry_disconnect(cptr);
}

/** Find number of clones of a client.
 * @param[in] cptr Client whose address to look up.
 * @return Number of clients known to be connected from that address.
 */
unsigned short IPcheck_nr(struct Client *cptr)
{
  assert(0 != cptr);
  return ip_registry_count(&cli_ip(cptr));
}
