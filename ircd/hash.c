/*
 * IRC - Internet Relay Chat, ircd/hash.c
 * Copyright (C) 1998 Andrea Cocito, completely rewritten version.
 * Previous version was Copyright (C) 1991 Darren Reed, the concept
 * of linked lists for each hash bucket and the move-to-head 
 * optimization has been borrowed from there.
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
#include "config.h"

#include "hash.h"
#include "client.h"
#include "channel.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "random.h"
#include "send.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <limits.h>
#include <stdlib.h>
#include <string.h>


/** @file
 * @brief Hash table management.
 * @version $Id$
 *
 * This file used to use some very complicated hash function.  Now it
 * uses CRC-32, but effectively remaps each input byte according to a
 * table initialized at startup.
 */

/** Hash table for clients. */
static struct Client *clientTable[HASHSIZE];
/** Hash table for channels. */
static struct Channel *channelTable[HASHSIZE];
/** CRC-32 update table. */
static uint32_t crc32hash[256];

/** Initialize the map used by the hash function. */
void init_hash(void)
{
  unsigned int ii, jj, rand, poly;

  /* First calculate a normal CRC-32 table. */
  for (ii = 0, poly = 0xedb88320; ii < 256; ii++)
  {
    rand = ii;
    for (jj = 0; jj < 8; jj++)
      rand = (rand & 1) ? poly ^ (rand >> 1) : rand >> 1;
    crc32hash[ii] = rand;
  }

  /* Now reorder the hash table. */
  for (ii = 0, rand = 0; ii < 256; ii++)
  {
    if (!rand)
      rand = ircrandom();
    poly = ii + rand % (256 - ii);
    jj = crc32hash[ii];
    crc32hash[ii] = crc32hash[poly];
    crc32hash[poly] = jj;
    rand >>= 8;
  }
}

/** Output type of hash function. */
typedef unsigned int HASHREGS;

/** Calculate hash value for a string.
 * @param[in] n String to hash.
 * @return Hash value for string.
 */
static HASHREGS strhash(const char *n)
{
  HASHREGS hash = crc32hash[ToLower(*n++) & 255];
  while (*n)
    hash = (hash >> 8) ^ crc32hash[(hash ^ ToLower(*n++)) & 255];
  return hash % HASHSIZE;
}

/************************** Externally visible functions ********************/

/* Optimization note: in these functions I supposed that the CSE optimization
 * (Common Subexpression Elimination) does its work decently, this means that
 * I avoided introducing new variables to do the work myself and I did let
 * the optimizer play with more free registers, actual tests proved this
 * solution to be faster than doing things like tmp2=tmp->hnext... and then
 * use tmp2 myself which would have given less freedom to the optimizer.
 */

/** Prepend a client to the appropriate hash bucket.
 * @param[in] cptr Client to add to hash table.
 * @return Zero.
 */
int hAddClient(struct Client *cptr)
{
  HASHREGS hashv = strhash(cli_name(cptr));

  cli_hnext(cptr) = clientTable[hashv];
  clientTable[hashv] = cptr;

  return 0;
}

/** Prepend a channel to the appropriate hash bucket.
 * @param[in] chptr Channel to add to hash table.
 * @return Zero.
 */
int hAddChannel(struct Channel *chptr)
{
  HASHREGS hashv = strhash(chptr->chname);

  chptr->hnext = channelTable[hashv];
  channelTable[hashv] = chptr;

  return 0;
}

/** Remove a client from its hash bucket.
 * @param[in] cptr Client to remove from hash table.
 * @return Zero if the client is found and removed, -1 if not found.
 */
int hRemClient(struct Client *cptr)
{
  HASHREGS hashv = strhash(cli_name(cptr));
  struct Client *tmp = clientTable[hashv];

  if (tmp == cptr) {
    clientTable[hashv] = cli_hnext(cptr);
    cli_hnext(cptr) = cptr;
    return 0;
  }

  while (tmp) {
    if (cli_hnext(tmp) == cptr) {
      cli_hnext(tmp) = cli_hnext(cli_hnext(tmp));
      cli_hnext(cptr) = cptr;
      return 0;
    }
    tmp = cli_hnext(tmp);
  }
  return -1;
}

/** Rename a client in the hash table.
 * @param[in] cptr Client whose nickname is changing.
 * @param[in] newname New nickname for client.
 * @return Zero.
 */
int hChangeClient(struct Client *cptr, const char *newname)
{
  HASHREGS newhash = strhash(newname);

  assert(0 != cptr);
  hRemClient(cptr);

  cli_hnext(cptr) = clientTable[newhash];
  clientTable[newhash] = cptr;
  return 0;
}

/** Remove a channel from its hash bucket.
 * @param[in] chptr Channel to remove from hash table.
 * @return Zero if the channel is found and removed, -1 if not found.
 */
int hRemChannel(struct Channel *chptr)
{
  HASHREGS hashv = strhash(chptr->chname);
  struct Channel *tmp = channelTable[hashv];

  if (tmp == chptr) {
    channelTable[hashv] = chptr->hnext;
    chptr->hnext = chptr;
    return 0;
  }

  while (tmp) {
    if (tmp->hnext == chptr) {
      tmp->hnext = tmp->hnext->hnext;
      chptr->hnext = chptr;
      return 0;
    }
    tmp = tmp->hnext;
  }

  return -1;
}

/** Find a client by name, filtered by status mask.
 * If a client is found, it is moved to the top of its hash bucket.
 * @param[in] name Client name to search for.
 * @param[in] TMask Bitmask of status bits, any of which are needed to match.
 * @return Matching client, or NULL if none.
 */
struct Client* hSeekClient(const char *name, int TMask)
{
  HASHREGS hashv      = strhash(name);
  struct Client *cptr = clientTable[hashv];

  if (cptr) {
    if (0 == (cli_status(cptr) & TMask) || 0 != ircd_strcmp(name, cli_name(cptr))) {
      struct Client* prev;
      while (prev = cptr, cptr = cli_hnext(cptr)) {
        if ((cli_status(cptr) & TMask) && (0 == ircd_strcmp(name, cli_name(cptr)))) {
          cli_hnext(prev) = cli_hnext(cptr);
          cli_hnext(cptr) = clientTable[hashv];
          clientTable[hashv] = cptr;
          break;
        }
      }
    }
  }
  return cptr;
}

/** Find a channel by name.
 * If a channel is found, it is moved to the top of its hash bucket.
 * @param[in] name Channel name to search for.
 * @return Matching channel, or NULL if none.
 */
struct Channel* hSeekChannel(const char *name)
{
  HASHREGS hashv = strhash(name);
  struct Channel *chptr = channelTable[hashv];

  if (chptr) {
    if (0 != ircd_strcmp(name, chptr->chname)) {
      struct Channel* prev;
      while (prev = chptr, chptr = chptr->hnext) {
        if (0 == ircd_strcmp(name, chptr->chname)) {
          prev->hnext = chptr->hnext;
          chptr->hnext = channelTable[hashv];
          channelTable[hashv] = chptr;
          break;
        }
      }
    }
  }
  return chptr;

}

/* I will add some useful(?) statistics here one of these days,
   but not for DEBUGMODE: just to let the admins play with it,
   coders are able to SIGCORE the server and look into what goes
   on themselves :-) */

/** Report hash table statistics to a client.
 * @param[in] cptr Client that sent us this message.
 * @param[in] sptr Client that originated the message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument array.
 * @return Zero.
 */
int m_hash(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  int max_chain = 0;
  int buckets   = 0;
  int count     = 0;
  struct Client*  cl;
  struct Channel* ch;
  int i;
  
  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Hash Table Statistics", sptr);

  for (i = 0; i < HASHSIZE; ++i) {
    if ((cl = clientTable[i])) {
      int len = 0;
      ++buckets;
      for ( ; cl; cl = cli_hnext(cl))
        ++len; 
      if (len > max_chain)
        max_chain = len;
      count += len;
    }
  } 

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Client: entries: %d buckets: %d "
		"max chain: %d", sptr, count, buckets, max_chain);

  buckets = 0;
  count   = 0;
  max_chain = 0;

  for (i = 0; i < HASHSIZE; ++i) {
    if ((ch = channelTable[i])) {
      int len = 0;
      ++buckets;
      for ( ; ch; ch = ch->hnext)
        ++len; 
      if (len > max_chain)
        max_chain = len;
      count += len;
    }
  } 

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Channel: entries: %d buckets: %d "
		"max chain: %d", sptr, count, buckets, max_chain);
  return 0;
}

/* Nick jupe utilities, these are in a static hash table with entry/bucket
   ratio of one, collision shift up and roll in a circular fashion, the 
   lowest 12 bits of the hash value are used, deletion is not supported,
   only addition, test for existence and cleanup of the table are.. */

/** Number of bits in jupe hash value. */
#define JUPEHASHBITS 12         /* 4096 entries, 64 nick jupes allowed */
/** Size of jupe hash table. */
#define JUPEHASHSIZE (1<<JUPEHASHBITS)
/** Bitmask to select into jupe hash table. */
#define JUPEHASHMASK (JUPEHASHSIZE-1)
/** Maximum number of jupes allowed. */
#define JUPEMAX      (1<<(JUPEHASHBITS-6))

/** Hash table for jupes. */
static char jupeTable[JUPEHASHSIZE][NICKLEN + 1];       /* About 40k */
/** Count of jupes. */
static int jupesCount;

/** Check whether a nickname is juped.
 * @param[in] nick Nickname to check.
 * @return Non-zero of the nickname is juped, zero if not.
 */
int isNickJuped(const char *nick)
{
  int pos;

  if (nick && *nick) {
    for (pos = strhash(nick); (pos &= JUPEHASHMASK), jupeTable[pos][0]; pos++) {
      if (0 == ircd_strcmp(nick, jupeTable[pos]))
        return 1;
    }
  }
  return 0;                     /* A bogus pointer is NOT a juped nick, right ? :) */
}

/** Add a comma-separated list of nick jupes.
 * @param[in] nicks List of nicks to jupe, separated by commas.
 * @return Zero on success, non-zero on error.
 */
int addNickJupes(const char *nicks)
{
  static char temp[BUFSIZE + 1];
  char* one;
  char* p;
  int   pos;

  if (nicks && *nicks)
  {
    ircd_strncpy(temp, nicks, BUFSIZE);
    temp[BUFSIZE] = '\0';
    p = NULL;
    for (one = ircd_strtok(&p, temp, ","); one; one = ircd_strtok(&p, NULL, ","))
    {
      if (!*one)
        continue;
      pos = strhash(one);
loop:
      pos &= JUPEHASHMASK;
      if (!jupeTable[pos][0])
      {
        if (jupesCount == JUPEMAX)
          return 1;             /* Error: Jupe table is full ! */
        jupesCount++;
        ircd_strncpy(jupeTable[pos], one, NICKLEN);
        jupeTable[pos][NICKLEN] = '\000';       /* Better safe than sorry :) */
        continue;
      }
      if (0 == ircd_strcmp(one, jupeTable[pos]))
        continue;
      ++pos;
      goto loop;
    }
  }
  return 0;
}

/** Empty the table of juped nicknames. */
void clearNickJupes(void)
{
  int i;
  jupesCount = 0;
  for (i = 0; i < JUPEHASHSIZE; i++)
    jupeTable[i][0] = '\000';
}

/** Report all nick jupes to a user.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
stats_nickjupes(struct Client* to, const struct StatDesc* sd, char* param)
{
  int i;
  for (i = 0; i < JUPEHASHSIZE; i++)
    if (jupeTable[i][0])
      send_reply(to, RPL_STATSJLINE, jupeTable[i]);
}

/** Send more channels to a client in mid-LIST.
 * @param[in] cptr Client to send the list to.
 */
void list_next_channels(struct Client *cptr)
{
  struct ListingArgs *args;
  struct Channel *chptr;

  /* Walk consecutive buckets until we hit the end. */
  for (args = cli_listing(cptr); args->bucket < HASHSIZE; args->bucket++)
  {
    /* Send all the matching channels in the bucket. */
    for (chptr = channelTable[args->bucket]; chptr; chptr = chptr->hnext)
    {
      if (chptr->users > args->min_users
          && chptr->users < args->max_users
          && chptr->creationtime > args->min_time
          && chptr->creationtime < args->max_time
          && (!args->wildcard[0] || (args->flags & LISTARG_NEGATEWILDCARD) ||
              (!match(args->wildcard, chptr->chname)))
          && (!(args->flags & LISTARG_NEGATEWILDCARD) ||
              match(args->wildcard, chptr->chname))
          && (!(args->flags & LISTARG_TOPICLIMITS)
              || (chptr->topic[0]
                  && chptr->topic_time > args->min_topic_time
                  && chptr->topic_time < args->max_topic_time))
          && ((args->flags & LISTARG_SHOWSECRET)
              || ShowChannel(cptr, chptr)))
      {
        if (args->flags & LISTARG_SHOWMODES) {
          char modebuf[MODEBUFLEN];
          char parabuf[MODEBUFLEN];

          modebuf[0] = modebuf[1] = parabuf[0] = '\0';
          channel_modes(cptr, modebuf, parabuf, sizeof(parabuf), chptr, NULL);
          send_reply(cptr, RPL_LIST | SND_EXPLICIT, "%s %u %s %s :%s",
                     chptr->chname, chptr->users, modebuf, parabuf, chptr->topic);
        } else {
          send_reply(cptr, RPL_LIST, chptr->chname, chptr->users, chptr->topic);
        }
      }
    }
    /* If, at the end of the bucket, client sendq is more than half
     * full, stop. */
    if (MsgQLength(&cli_sendQ(cptr)) > cli_max_sendq(cptr) / 2)
      break;
  }

  /* If we did all buckets, clean the client and send RPL_LISTEND. */
  if (args->bucket >= HASHSIZE)
  {
    MyFree(cli_listing(cptr));
    cli_listing(cptr) = NULL;
    send_reply(cptr, RPL_LISTEND);
  }
}
