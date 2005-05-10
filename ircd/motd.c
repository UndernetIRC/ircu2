/*
 * IRC - Internet Relay Chat, ircd/motd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * @brief Message-of-the-day manipulation implementation.
 * @version $Id$
 */
#include "config.h"

#include "motd.h"
#include "class.h"
#include "client.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "s_stats.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/** Global list of messages of the day. */
static struct {
  struct Motd*	    local;     /**< Local MOTD. */
  struct Motd*	    remote;    /**< Remote MOTD. */
  struct Motd*	    other;     /**< MOTDs specified in configuration file. */
  struct Motd*	    freelist;  /**< Currently unused Motd structs. */
  struct MotdCache* cachelist; /**< List of MotdCache entries. */
} MotdList = { 0, 0, 0, 0, 0 };

/** Create a struct Motd and initialize it.
 * @param[in] hostmask Hostmask (or connection class name) to filter on.
 * @param[in] path Path to MOTD file.
 * @param[in] maxcount Maximum number of lines permitted for MOTD.
 */
static struct Motd *
motd_create(const char *hostmask, const char *path, int maxcount)
{
  struct Motd* tmp;

  assert(0 != path);

  /* allocate memory and initialize the structure */
  if (MotdList.freelist)
  {
    tmp = MotdList.freelist;
    MotdList.freelist = tmp->next;
  } else
    tmp = (struct Motd *)MyMalloc(sizeof(struct Motd));
  tmp->next = 0;

  if (hostmask == NULL)
    tmp->type = MOTD_UNIVERSAL;
  else if (find_class(hostmask))
    tmp->type = MOTD_CLASS;
  else if (ipmask_parse(hostmask, &tmp->address, &tmp->addrbits))
    tmp->type = MOTD_IPMASK;
  else
    tmp->type = MOTD_HOSTMASK;

  if (hostmask != NULL)
    DupString(tmp->hostmask, hostmask);
  else
    tmp->hostmask = NULL;

  DupString(tmp->path, path);
  tmp->maxcount = maxcount;
  tmp->cache = 0;

  return tmp;
}

/** This function reads a motd out of a file (if needed) and caches it.
 * If a matching cache entry already exists, reuse it.  Otherwise,
 * allocate and populate a new MotdCache for it.
 * @param[in] motd Specification for MOTD file.
 * @return Matching MotdCache entry.
 */
static struct MotdCache *
motd_cache(struct Motd *motd)
{
  FBFILE*		file;
  struct MotdCache*	cache;
  struct stat		sb;
  char			line[MOTD_LINESIZE + 2]; /* \r\n */
  char*			tmp;
  int			i;

  assert(0 != motd);
  assert(0 != motd->path);

  if (motd->cache)
    return motd->cache;

  /* try to find it in the list of cached files... */
  for (cache = MotdList.cachelist; cache; cache = cache->next) {
    if (!strcmp(cache->path, motd->path) &&
	cache->maxcount == motd->maxcount) { /* found one... */
      cache->ref++; /* increase reference count... */
      motd->cache = cache; /* remember cache... */
      return motd->cache; /* return it */
    }
  }

  /* gotta read in the file, now */
  if (!(file = fbopen(motd->path, "r"))) {
    Debug((DEBUG_ERROR, "Couldn't open \"%s\": %s", motd->path,
	   strerror(errno)));
    return 0;
  }

  /* need the file's modification time */
  if (-1 == fbstat(&sb, file)) {
    fbclose(file);
    return 0;
  }

  /* Ok, allocate a structure; we'll realloc later to trim memory */
  cache = (struct MotdCache *)MyMalloc(sizeof(struct MotdCache) +
				       (MOTD_LINESIZE * (MOTD_MAXLINES - 1)));

  cache->ref = 1;
  DupString(cache->path, motd->path);
  cache->maxcount = motd->maxcount;

  cache->modtime = *localtime((time_t *) &sb.st_mtime); /* store modtime */

  cache->count = 0;
  while (cache->count < cache->maxcount && fbgets(line, sizeof(line), file)) {
    /* copy over line, stopping when we overflow or hit line end */
    for (tmp = line, i = 0;
	 i < (MOTD_LINESIZE - 1) && *tmp && *tmp != '\r' && *tmp != '\n';
	 tmp++, i++)
      cache->motd[cache->count][i] = *tmp;
    cache->motd[cache->count][i] = '\0';

    cache->count++;
  }

  fbclose(file); /* close the file */

  /* trim memory usage a little */
  motd->cache = (struct MotdCache*)MyMalloc(sizeof(struct MotdCache) +
                                            (MOTD_LINESIZE * (cache->count - 1)));
  memcpy(motd->cache, cache, sizeof(struct MotdCache) +
         (MOTD_LINESIZE * (cache->count - 1)));
  MyFree(cache);

  /* now link it in... */
  motd->cache->next = MotdList.cachelist;
  motd->cache->prev_p = &MotdList.cachelist;
  if (MotdList.cachelist)
    MotdList.cachelist->prev_p = &motd->cache->next;
  MotdList.cachelist = motd->cache;

  return motd->cache;
}

/** Clear and dereference the Motd::cache element of \a motd.
 * If the MotdCache::ref count goes to zero, free it.
 * @param[in] motd MOTD to uncache.
 */
static void
motd_decache(struct Motd *motd)
{
  struct MotdCache* cache;

  assert(0 != motd);

  if (!(cache = motd->cache)) /* we can be called for records with no cache */
    return;

  motd->cache = 0; /* zero the cache */

  if (!--cache->ref) { /* reduce reference count... */
    if (cache->next) /* ref is 0, delink from list and free */
      cache->next->prev_p = cache->prev_p;
    *cache->prev_p = cache->next;

    MyFree(cache->path); /* free path info... */

    MyFree(cache); /* very simple for a reason... */
  }
}

/** Deallocate a MOTD structure.
 * If it has cached content, uncache it.
 * @param[in] motd MOTD to destroy.
 */
static void
motd_destroy(struct Motd *motd)
{
  assert(0 != motd);

  MyFree(motd->path); /* we always must have a path */
  MyFree(motd->hostmask);
  if (motd->cache) /* drop the cache */
    motd_decache(motd);

  motd->next = MotdList.freelist;
  MotdList.freelist = motd;
}

/** Find the first matching MOTD block for a user.
 * If the user is remote, always use remote MOTD.
 * Otherwise, if there is a hostmask- or class-based MOTD that matches
 * the user, use it.
 * Otherwise, use the local MOTD.
 * @param[in] cptr Client to find MOTD for.
 * @return Pointer to first matching MOTD for the client.
 */
static struct Motd *
motd_lookup(struct Client *cptr)
{
  struct Motd *ptr;
  char *c_class = NULL;

  assert(0 != cptr);

  if (!MyUser(cptr)) /* not my user, always return remote motd */
    return MotdList.remote;

  c_class = get_client_class(cptr);
  assert(c_class != NULL);

  /* check the motd blocks first */
  for (ptr = MotdList.other; ptr; ptr = ptr->next)
  {
    if (ptr->type == MOTD_CLASS
        && !match(ptr->hostmask, c_class))
      return ptr;
    else if (ptr->type == MOTD_HOSTMASK
             && !match(ptr->hostmask, cli_sockhost(cptr)))
      return ptr;
    else if (ptr->type == MOTD_IPMASK
             && ipmask_check(&cli_ip(cptr), &ptr->address, ptr->addrbits))
      return ptr;
  }

  return MotdList.local; /* Ok, return the default motd */
}

/** Send the content of a MotdCache to a user.
 * If \a cache is NULL, simply send ERR_NOMOTD to the client.
 * @param[in] cptr Client to send MOTD to.
 * @param[in] cache MOTD body to send to client.
 */
static int
motd_forward(struct Client *cptr, struct MotdCache *cache)
{
  int i;

  assert(0 != cptr);

  if (!cache) /* no motd to send */
    return send_reply(cptr, ERR_NOMOTD);

  /* send the motd */
  send_reply(cptr, RPL_MOTDSTART, cli_name(&me));
  send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":- %d-%d-%d %d:%02d",
	     cache->modtime.tm_year + 1900, cache->modtime.tm_mon + 1,
	     cache->modtime.tm_mday, cache->modtime.tm_hour,
	     cache->modtime.tm_min);

  for (i = 0; i < cache->count; i++)
    send_reply(cptr, RPL_MOTD, cache->motd[i]);

  return send_reply(cptr, RPL_ENDOFMOTD); /* end */
}

/** Find the MOTD for a client and send it.
 * @param[in] cptr Client being greeted.
 */
int
motd_send(struct Client* cptr)
{
  assert(0 != cptr);

  return motd_forward(cptr, motd_cache(motd_lookup(cptr)));
}

/** Send the signon MOTD to a user.
 * If FEAT_NODEFAULTMOTD is true and a matching MOTD exists for the
 * user, direct the client to type /MOTD to read it.  Otherwise, call
 * motd_forward() for the user.
 * @param[in] cptr Client that has just connected.
 */
void
motd_signon(struct Client* cptr)
{
  struct MotdCache *cache;
  const char *banner = NULL;

  cache = motd_cache(motd_lookup(cptr));

  if (!feature_bool(FEAT_NODEFAULTMOTD) || !cache)
    motd_forward(cptr, cache);
  else {
    send_reply(cptr, RPL_MOTDSTART, cli_name(&me));
    if ((banner = feature_str(FEAT_MOTD_BANNER)))
      send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":%s", banner);
    send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":\002Type /MOTD to read the "
	       "AUP before continuing using this service.\002");
    send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":The message of the day was "
	       "last changed: %d-%d-%d %d:%d", cache->modtime.tm_year + 1900,
	       cache->modtime.tm_mon + 1, cache->modtime.tm_mday,
	       cache->modtime.tm_hour, cache->modtime.tm_min);
    send_reply(cptr, RPL_ENDOFMOTD);
  }
}

/** Clear all cached MOTD bodies.
 * The local and remote MOTDs are re-cached immediately.
 */
void
motd_recache(void)
{
  struct Motd* tmp;

  motd_decache(MotdList.local); /* decache local and remote MOTDs */
  motd_decache(MotdList.remote);

  for (tmp = MotdList.other; tmp; tmp = tmp->next) /* now all the others */
    motd_decache(tmp);

  /* now recache local and remote MOTDs */
  motd_cache(MotdList.local);
  motd_cache(MotdList.remote);
}

/** Re-cache the local and remote MOTDs.
 * If they already exist, they are deallocated first.
 */
void
motd_init(void)
{
  if (MotdList.local) /* destroy old local... */
    motd_destroy(MotdList.local);

  MotdList.local = motd_create(0, feature_str(FEAT_MPATH), MOTD_MAXLINES);
  motd_cache(MotdList.local); /* init local and cache it */

  if (MotdList.remote) /* destroy old remote... */
    motd_destroy(MotdList.remote);

  MotdList.remote = motd_create(0, feature_str(FEAT_RPATH), MOTD_MAXREMOTE);
  motd_cache(MotdList.remote); /* init remote and cache it */
}

/** Add a new MOTD.
 * @param[in] hostmask Hostmask (or connection class name) to send this to.
 * @param[in] path Pathname of file to send.
 */
void
motd_add(const char *hostmask, const char *path)
{
  struct Motd *tmp;

  tmp = motd_create(hostmask, path, MOTD_MAXLINES); /* create the motd */

  tmp->next = MotdList.other; /* link it into the list */
  MotdList.other = tmp;
}

/** Clear out all MOTDs.
 * Compared to motd_recache(), this destroys all hostmask- or
 * class-based MOTDs rather than simply uncaching them.
 * Re-cache the local and remote MOTDs.
 */
void
motd_clear(void)
{
  struct Motd *ptr, *next;

  motd_decache(MotdList.local); /* decache local and remote MOTDs */
  motd_decache(MotdList.remote);

  if (MotdList.other) /* destroy other MOTDs */
    for (ptr = MotdList.other; ptr; ptr = next)
    {
      next = ptr->next;
      motd_destroy(ptr);
    }

  MotdList.other = 0;

  /* now recache local and remote MOTDs */
  motd_cache(MotdList.local);
  motd_cache(MotdList.remote);
}

/** Report list of non-default MOTDs.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
motd_report(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct Motd *ptr;

  for (ptr = MotdList.other; ptr; ptr = ptr->next)
    send_reply(to, SND_EXPLICIT | RPL_STATSTLINE, "T %s %s",
               ptr->hostmask, ptr->path);
}

/** Report MOTD memory usage to a client.
 * @param[in] cptr Client requesting memory usage.
 */
void
motd_memory_count(struct Client *cptr)
{
  struct Motd *ptr;
  struct MotdCache *cache;
  unsigned int mt = 0,   /* motd count */
               mtc = 0,  /* motd cache count */
               mtf = 0;  /* motd free list count */
  size_t mtm = 0,  /* memory consumed by motd */
         mtcm = 0; /* memory consumed by motd cache */
  if (MotdList.local)
  {
    mt++;
    mtm += sizeof(struct Motd);
    mtm += MotdList.local->path ? (strlen(MotdList.local->path) + 1) : 0;
  }

  if (MotdList.remote)
  {
    mt++;
    mtm += sizeof(struct Motd);
    mtm += MotdList.remote->path ? (strlen(MotdList.remote->path) + 1) : 0;
  }

  for (ptr = MotdList.other; ptr; ptr = ptr->next)
  {
    mt++;
    mtm += sizeof(struct Motd);
    mtm += ptr->path ? (strlen(ptr->path) + 1) : 0;
  }

  for (cache = MotdList.cachelist; cache; cache = cache->next)
  {
    mtc++;
    mtcm += sizeof(struct MotdCache) + (MOTD_LINESIZE * (cache->count - 1));
  }

  if (MotdList.freelist)
    for (ptr = MotdList.freelist; ptr; ptr = ptr->next)
      mtf++;

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":Motds %d(%zu) Cache %d(%zu) Free %d(%zu)",
             mt, mtm, mtc, mtcm, mtf, (mtf * sizeof(struct Motd)));
}
