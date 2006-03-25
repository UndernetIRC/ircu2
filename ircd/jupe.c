/*
 * IRC - Internet Relay Chat, ircd/jupe.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
 * @brief Implementation of juped server handling functions.
 * @version $Id$
 */
#include "config.h"

#include "jupe.h"
#include "client.h"
#include "hash.h"
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
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"    /* FALSE bleah */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** List of jupes. */
static struct Jupe *GlobalJupeList = 0;

/** Allocate a new jupe with the given parameters.
 * @param[in] server Server name to jupe.
 * @param[in] reason Reason for jupe.
 * @param[in] expire Expiration time for jupe.
 * @param[in] lastmod Last modification time for jupe.
 * @param[in] flags Flags to set for the jupe.
 */
static struct Jupe *
make_jupe(char *server, char *reason, time_t expire, time_t lastmod,
	  unsigned int flags)
{
  struct Jupe *ajupe;

  ajupe = (struct Jupe*) MyMalloc(sizeof(struct Jupe)); /* alloc memory */
  assert(0 != ajupe);

  memset(ajupe, 0, sizeof(*ajupe));
  DupString(ajupe->ju_server, server); /* copy vital information */
  DupString(ajupe->ju_reason, reason);
  ajupe->ju_expire = expire;
  ajupe->ju_lastmod = lastmod;
  ajupe->ju_flags = flags & JUPE_MASK; /* set jupe flags */

  ajupe->ju_next = GlobalJupeList; /* link it into the list */
  ajupe->ju_prev_p = &GlobalJupeList;
  if (GlobalJupeList)
    GlobalJupeList->ju_prev_p = &ajupe->ju_next;
  GlobalJupeList = ajupe;

  return ajupe;
}

/** Apply a jupe.
 * @param[in] cptr Local client that sent us the jupe.
 * @param[in] sptr Originator of the jupe.
 * @param[in] jupe Jupe to check.
 */
static int
do_jupe(struct Client *cptr, struct Client *sptr, struct Jupe *jupe)
{
  struct Client *acptr;

  if (!JupeIsActive(jupe)) /* no action to be taken on inactive jupes */
    return 0;

  acptr = FindServer(jupe->ju_server);

  /* server isn't online or isn't local or is me */
  if (!acptr || !MyConnect(acptr) || IsMe(acptr))
    return 0;

  return exit_client_msg(cptr, acptr, &me, "Juped: %s", jupe->ju_reason);
}

/** Forward a jupe to another server.
 * @param[in] cptr Local client that sent us the jupe.
 * @param[in] sptr Originator of the jupe.
 * @param[in] jupe Jupe to forward.
 */
static void
propagate_jupe(struct Client *cptr, struct Client *sptr, struct Jupe *jupe)
{
  if (JupeIsLocal(jupe)) /* don't propagate local jupes */
    return;

  sendcmdto_serv_butone(sptr, CMD_JUPE, cptr, "* %c%s %Tu %Tu :%s",
			JupeIsRemActive(jupe) ? '+' : '-', jupe->ju_server,
			jupe->ju_expire - CurrentTime, jupe->ju_lastmod,
			jupe->ju_reason);
}

/** Add a new server jupe.
 * @param[in] cptr Local client that sent us the jupe.
 * @param[in] sptr Originator of the jupe.
 * @param[in] server Server name to jupe.
 * @param[in] reason Reason for the jupe.
 * @param[in] expire Jupe duration in seconds.
 * @param[in] lastmod Last modification timestamp (or NULL).
 * @param[in] flags Flags to set on jupe.
 * @return Zero, unless the jupe causes \a cptr to be SQUIT, in which
 * case CPTR_KILLED.
 */
int
jupe_add(struct Client *cptr, struct Client *sptr, char *server, char *reason,
	 time_t expire, time_t lastmod, unsigned int flags)
{
  struct Jupe *ajupe;

  assert(0 != server);
  assert(0 != reason);

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than JUPE_MAX_EXPIRE.
   */
  if (expire <= 0 || expire > JUPE_MAX_EXPIRE) {
    if (!IsServer(cptr) && MyConnect(cptr))
      send_reply(cptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_NETWORK, "%s adding %sJUPE for %s, expiring at "
                       "%Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
		       flags & JUPE_LOCAL ? "local " : "", server,
		       expire + TSoffset, reason);

  log_write(LS_JUPE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %sJUPE for %s, expiring at %Tu: %s", sptr,
	    flags & JUPE_LOCAL ? "local " : "", server, expire + TSoffset,
	    reason);

  /* make the jupe */
  ajupe = make_jupe(server, reason, expire, lastmod, flags);

  propagate_jupe(cptr, sptr, ajupe);

  return do_jupe(cptr, sptr, ajupe); /* remove server if necessary */
}

/** Activate a jupe, optionally changing its lastmod and flags.
 * @param[in] cptr Local client that sent us the jupe.
 * @param[in] sptr Originator of the jupe.
 * @param[in] jupe Jupe to activate.
 * @param[in] lastmod New timestamp for last modification of the jupe.
 * @param[in] flags Flags to set on the jupe.
 * @return Zero, unless the jupe causes \a cptr to be SQUIT, in which
 * case CPTR_KILLED.
 */
int
jupe_activate(struct Client *cptr, struct Client *sptr, struct Jupe *jupe,
	      time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != jupe);

  saveflags = jupe->ju_flags;

  if (flags & JUPE_LOCAL)
    jupe->ju_flags &= ~JUPE_LDEACT;
  else {
    jupe->ju_flags |= JUPE_ACTIVE;

    if (jupe->ju_lastmod >= lastmod) /* force lastmod to increase */
      jupe->ju_lastmod++;
    else
      jupe->ju_lastmod = lastmod;
  }

  if ((saveflags & JUPE_ACTMASK) == JUPE_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_NETWORK, "%s activating JUPE for %s, expiring "
		       "at %Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
		       jupe->ju_server, jupe->ju_expire + TSoffset,
		       jupe->ju_reason);

  log_write(LS_JUPE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating JUPE for %s, expiring at %Tu: %s",sptr,
	    jupe->ju_server, jupe->ju_expire + TSoffset, jupe->ju_reason);

  if (!(flags & JUPE_LOCAL)) /* don't propagate local changes */
    propagate_jupe(cptr, sptr, jupe);

  return do_jupe(cptr, sptr, jupe);
}

/** Deactivate a jupe.
 * @param[in] cptr Local client that sent us the jupe.
 * @param[in] sptr Originator of the jupe.
 * @param[in] jupe Jupe to deactivate.
 * @param[in] lastmod New timestamp for last modification of the jupe.
 * @param[in] flags Flags to set on the jupe.
 * @return Zero.
 */
int
jupe_deactivate(struct Client *cptr, struct Client *sptr, struct Jupe *jupe,
		time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != jupe);

  saveflags = jupe->ju_flags;

  if (!JupeIsLocal(jupe)) {
    if (flags & JUPE_LOCAL)
      jupe->ju_flags |= JUPE_LDEACT;
    else {
      jupe->ju_flags &= ~JUPE_ACTIVE;

      if (jupe->ju_lastmod >= lastmod) /* force lastmod to increase */
	jupe->ju_lastmod++;
      else
	jupe->ju_lastmod = lastmod;
    }

    if ((saveflags & JUPE_ACTMASK) != JUPE_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_NETWORK, "%s %s JUPE for %s, expiring at %Tu: "
		       "%s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
		       JupeIsLocal(jupe) ? "removing local" : "deactivating",
		       jupe->ju_server, jupe->ju_expire + TSoffset,
		       jupe->ju_reason);

  log_write(LS_JUPE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s JUPE for %s, expiring at %Tu: %s", sptr,
	    JupeIsLocal(jupe) ? "removing local" : "deactivating",
	    jupe->ju_server, jupe->ju_expire + TSoffset, jupe->ju_reason);

  if (JupeIsLocal(jupe))
    jupe_free(jupe);
  else if (!(flags & JUPE_LOCAL)) /* don't propagate local changes */
    propagate_jupe(cptr, sptr, jupe);

  return 0;
}

/** Find a jupe by name.
 * @param[in] server %Jupe name to search for.
 * @return Matching jupe (or NULL if none match).
 */
struct Jupe *
jupe_find(char *server)
{
  struct Jupe* jupe;
  struct Jupe* sjupe;

  for (jupe = GlobalJupeList; jupe; jupe = sjupe) { /* go through jupes */
    sjupe = jupe->ju_next;

    if (jupe->ju_expire <= CurrentTime) /* expire any that need expiring */
      jupe_free(jupe);
    else if (0 == ircd_strcmp(server, jupe->ju_server)) /* found it yet? */
      return jupe;
  }

  return 0;
}

/** Unlink and free an unused jupe.
 * @param[in] jupe Server jupe to free.
 */
void
jupe_free(struct Jupe* jupe)
{
  assert(0 != jupe);

  *jupe->ju_prev_p = jupe->ju_next; /* squeeze this jupe out */
  if (jupe->ju_next)
    jupe->ju_next->ju_prev_p = jupe->ju_prev_p;

  MyFree(jupe->ju_server);  /* and free up the memory */
  MyFree(jupe->ju_reason);
  MyFree(jupe);
}

/** Send the full list of active global jupes to \a cptr.
 * @param[in] cptr Local server to send jupes to.
 */
void
jupe_burst(struct Client *cptr)
{
  struct Jupe *jupe;
  struct Jupe *sjupe;

  for (jupe = GlobalJupeList; jupe; jupe = sjupe) { /* go through jupes */
    sjupe = jupe->ju_next;

    if (jupe->ju_expire <= CurrentTime) /* expire any that need expiring */
      jupe_free(jupe);
    else if (!JupeIsLocal(jupe)) /* forward global jupes */
      sendcmdto_one(&me, CMD_JUPE, cptr, "* %c%s %Tu %Tu :%s",
		    JupeIsRemActive(jupe) ? '+' : '-', jupe->ju_server,
		    jupe->ju_expire - CurrentTime, jupe->ju_lastmod,
		    jupe->ju_reason);
  }
}

/** Forward a jupe to another server.
 * @param[in] cptr %Server to send jupe to.
 * @param[in] jupe Jupe to forward.
 */
int
jupe_resend(struct Client *cptr, struct Jupe *jupe)
{
  if (JupeIsLocal(jupe)) /* don't propagate local jupes */
    return 0;

  sendcmdto_one(&me, CMD_JUPE, cptr, "* %c%s %Tu %Tu :%s",
		JupeIsRemActive(jupe) ? '+' : '-', jupe->ju_server,
		jupe->ju_expire - CurrentTime, jupe->ju_lastmod,
		jupe->ju_reason);

  return 0;
}

/** Send a jupe (or a list of jupes) to a server.
 * @param[in] sptr Client searching for jupes.
 * @param[in] server Name of jupe to search for (if NULL, list all).
 * @return Zero.
 */
int
jupe_list(struct Client *sptr, char *server)
{
  struct Jupe *jupe;
  struct Jupe *sjupe;

  if (server) {
    if (!(jupe = jupe_find(server))) /* no such jupe */
      return send_reply(sptr, ERR_NOSUCHJUPE, server);

    /* send jupe information along */
    send_reply(sptr, RPL_JUPELIST, jupe->ju_server, jupe->ju_expire + TSoffset,
	       JupeIsLocal(jupe) ? cli_name(&me) : "*",
	       JupeIsActive(jupe) ? '+' : '-', jupe->ju_reason);
  } else {
    for (jupe = GlobalJupeList; jupe; jupe = sjupe) { /* go through jupes */
      sjupe = jupe->ju_next;

      if (jupe->ju_expire <= CurrentTime) /* expire any that need expiring */
	jupe_free(jupe);
      else /* send jupe information along */
	send_reply(sptr, RPL_JUPELIST, jupe->ju_server,
		   jupe->ju_expire + TSoffset,
		   JupeIsLocal(jupe) ? cli_name(&me) : "*",
		   JupeIsActive(jupe) ? '+' : '-', jupe->ju_reason);
    }
  }

  /* end of jupe information */
  return send_reply(sptr, RPL_ENDOFJUPELIST);
}

/** Count jupes and memory used by them.
 * @param[out] ju_size Receives total number of bytes allocated for jupes.
 * @return Number of jupes currently allocated.
 */
int
jupe_memory_count(size_t *ju_size)
{
  struct Jupe *jupe;
  unsigned int ju = 0;

  for (jupe = GlobalJupeList; jupe; jupe = jupe->ju_next)
  {
    ju++;
    *ju_size += sizeof(struct Jupe);
    *ju_size += jupe->ju_server ? (strlen(jupe->ju_server) + 1) : 0;
    *ju_size += jupe->ju_reason ? (strlen(jupe->ju_reason) + 1) : 0;
  }
  return ju;
}
