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
 *
 * $Id$
 */
#include "jupe.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"    /* FALSE bleah */

#include <assert.h>

static struct Jupe* GlobalJupeList  = 0;

static struct Jupe *
make_jupe(char *server, char *reason, time_t expire, time_t lastmod,
	  unsigned int flags)
{
  struct Jupe *ajupe;

  ajupe = (struct Jupe*) MyMalloc(sizeof(struct Jupe)); /* alloc memory */
  assert(0 != ajupe);

  DupString(ajupe->ju_server, server);        /* copy vital information */
  DupString(ajupe->ju_reason, reason);
  ajupe->ju_expire = expire;
  ajupe->ju_lastmod = lastmod;
  ajupe->ju_flags = flags;        /* set jupe flags */

  ajupe->ju_next = GlobalJupeList;       /* link it into the list */
  ajupe->ju_prev_p = &GlobalJupeList;
  if (GlobalJupeList)
    GlobalJupeList->ju_prev_p = &ajupe->ju_next;
  GlobalJupeList = ajupe;

  return ajupe;
}

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

static void
propagate_jupe(struct Client *cptr, struct Client *sptr, struct Jupe *jupe)
{
  if (JupeIsLocal(jupe)) /* don't propagate local jupes */
    return;

  if (IsUser(sptr)) /* select correct prefix */
    sendto_serv_butone(cptr, "%s%s " TOK_JUPE " * %c%s " TIME_T_FMT " "
		       TIME_T_FMT " :%s", NumNick(sptr),
		       JupeIsActive(jupe) ? '+' : '-', jupe->ju_server,
		       jupe->ju_expire - TStime(), jupe->ju_lastmod,
		       jupe->ju_reason);
  else
    sendto_serv_butone(cptr, "%s " TOK_JUPE " * %c%s " TIME_T_FMT " "
		       TIME_T_FMT " :%s", NumServ(sptr),
		       JupeIsActive(jupe) ? '+' : '-', jupe->ju_server,
		       jupe->ju_expire - TStime(), jupe->ju_lastmod,
		       jupe->ju_reason);
}

int
jupe_add(struct Client *cptr, struct Client *sptr, char *server, char *reason,
	 time_t expire, time_t lastmod, int local, int active)
{
  struct Jupe *ajupe;
  unsigned int flags = 0;

  assert(0 != server);
  assert(0 != reason);

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than JUPE_MAX_EXPIRE.
   */
  if (expire <= 0 || expire > JUPE_MAX_EXPIRE) {
    if (!IsServer(cptr) && MyConnect(cptr))
      sendto_one(cptr, err_str(ERR_BADEXPIRE), me.name, cptr->name, expire);
    return 0;
  }

  expire += TStime(); /* convert from lifetime to timestamp */

  /* Inform ops and log it */
  if (IsServer(sptr)) {
    sendto_op_mask(SNO_NETWORK, "%s adding %sJUPE for %s, expiring at "
		   TIME_T_FMT ": %s", sptr->name, local ? "local " : "",
		   server, expire, reason);
#ifdef JPATH
    write_log(JPATH, TIME_T_FMT " %s adding %sJUPE for %s, expiring at "
	      TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      local ? "local " : "", server, expire, reason);
#endif /* JPATH */
  } else {
    sendto_op_mask(SNO_NETWORK, "%s adding %sJUPE for %s, expiring at "
		   TIME_T_FMT ": %s", sptr->user->server->name,
		   local ? "local " : "", server, expire,
		   reason);
#ifdef JPATH
    write_log(JPATH, TIME_T_FMT, " %s!%s@%s adding %sJUPE for %s, expiring at "
	      TIME_T_FMT ": %s\n", TStime(), sptr->name, sptr->user->username,
	      sptr->user->host, local ? "local " : "", server, expire, reason);
#endif /* JPATH */
  }

  if (active) /* compute initial flags */
    flags |= JUPE_ACTIVE;
  if (local)
    flags |= JUPE_LOCAL;

  /* make the jupe */
  ajupe = make_jupe(server, reason, expire, lastmod, flags);

  propagate_jupe(cptr, sptr, ajupe);

  return do_jupe(cptr, sptr, ajupe); /* remove server if necessary */
}

int
jupe_activate(struct Client *cptr, struct Client *sptr, struct Jupe *jupe,
	      time_t lastmod)
{
  assert(0 != jupe);

  jupe->ju_flags |= JUPE_ACTIVE;
  jupe->ju_lastmod = lastmod;

  /* Inform ops and log it */
  if (IsServer(sptr)) {
    sendto_op_mask(SNO_NETWORK, "%s activating %sJUPE for %s, expiring at "
		   TIME_T_FMT ": %s", sptr->name, JupeIsLocal(jupe) ?
		   "local " : "", jupe->ju_server, jupe->ju_expire,
		   jupe->ju_reason);
#ifdef JPATH
    write_log(JPATH, TIME_T_FMT " %s activating %sJUPE for %s, expiring at "
	      TIME_T_FMT ": %s\n", TStime(), sptr->name, JupeIsLocal(jupe) ?
	      "local " : "", jupe->ju_server, jupe->ju_expire,
	      jupe->ju_reason);
#endif /* JPATH */
  } else {
    sendto_op_mask(SNO_NETWORK, "%s activating %sJUPE for %s, expiring at "
		   TIME_T_FMT ": %s", sptr->user->server->name,
		   JupeIsLocal(jupe) ? "local " : "", jupe->ju_server,
		   jupe->ju_expire, jupe->ju_reason);
#ifdef JPATH
    write_log(JPATH, TIME_T_FMT, " %s!%s@%s activating %sJUPE for %s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host, JupeIsLocal(jupe) ?
	      "local " : "", jupe->ju_server, jupe->ju_expire,
	      jupe->ju_reason);
#endif /* JPATH */
  }

  propagate_jupe(cptr, sptr, jupe);

  return do_jupe(cptr, sptr, jupe);
}

int
jupe_deactivate(struct Client *cptr, struct Client *sptr, struct Jupe *jupe,
		time_t lastmod)
{
  assert(0 != jupe);

  jupe->ju_flags &= ~JUPE_ACTIVE;
  jupe->ju_lastmod = lastmod;

  /* Inform ops and log it */
  if (IsServer(sptr)) {
    sendto_op_mask(SNO_NETWORK, "%s deactivating %sJUPE for %s, expiring at "
		   TIME_T_FMT ": %s", sptr->name, JupeIsLocal(jupe) ?
		   "local " : "", jupe->ju_server, jupe->ju_expire,
		   jupe->ju_reason);
#ifdef JPATH
    write_log(JPATH, TIME_T_FMT " %s deactivating %sJUPE for %s, expiring at "
	      TIME_T_FMT ": %s\n", TStime(), sptr->name, JupeIsLocal(jupe) ?
	      "local " : "", jupe->ju_server, jupe->ju_expire,
	      jupe->ju_reason);
#endif /* JPATH */
  } else {
    sendto_op_mask(SNO_NETWORK, "%s deactivating %sJUPE for %s, expiring at "
		   TIME_T_FMT ": %s", sptr->user->server->name,
		   JupeIsLocal(jupe) ? "local " : "", jupe->ju_server,
		   jupe->ju_expire, jupe->ju_reason);
#ifdef JPATH
    write_log(JPATH, TIME_T_FMT, " %s!%s@%s deactivating %sJUPE for %s, "
	      "expiring at " TIME_T_FMT ": %s\n", TStime(), sptr->name,
	      sptr->user->username, sptr->user->host, JupeIsLocal(jupe) ?
	      "local " : "", jupe->ju_server, jupe->ju_expire,
	      jupe->ju_reason);
#endif /* JPATH */
  }

  propagate_jupe(cptr, sptr, jupe);

  return 0;
}

struct Jupe *
jupe_find(char *server)
{
  struct Jupe* jupe;
  struct Jupe* sjupe;

  for (jupe = GlobalJupeList; jupe; jupe = sjupe) { /* go through jupes */
    sjupe = jupe->ju_next;

    if (jupe->ju_expire <= TStime()) /* expire any that need expiring */
      jupe_free(jupe);
    else if (0 == ircd_strcmp(server, jupe->ju_server)) /* found it yet? */
      return jupe;
  }

  return 0;
}

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

void
jupe_burst(struct Client *cptr)
{
  struct Jupe *jupe;
  struct Jupe *sjupe;

  for (jupe = GlobalJupeList; jupe; jupe = sjupe) { /* go through jupes */
    sjupe = jupe->ju_next;

    if (jupe->ju_expire <= TStime()) /* expire any that need expiring */
      jupe_free(jupe);
    else if (!JupeIsLocal(jupe)) /* forward global jupes */
      sendto_one(cptr, "%s " TOK_JUPE " * %c%s "TIME_T_FMT" "TIME_T_FMT" :%s",
		 NumServ(&me), JupeIsActive(jupe) ? '+' : '-',
		 jupe->ju_server, jupe->ju_expire - TStime(),
		 jupe->ju_lastmod, jupe->ju_reason);
  }
}

int
jupe_resend(struct Client *cptr, struct Jupe *jupe)
{
  if (JupeIsLocal(jupe)) /* don't propagate local jupes */
    return 0;

  sendto_one(cptr, "%s " TOK_JUPE " * %c%s " TIME_T_FMT " " TIME_T_FMT " :%s",
	     NumServ(&me), JupeIsActive(jupe) ? '+' : '-', jupe->ju_server,
	     jupe->ju_expire - TStime(), jupe->ju_lastmod, jupe->ju_reason);

  return 0;
}

int
jupe_list(struct Client *sptr, char *server)
{
  struct Jupe *jupe;
  struct Jupe *sjupe;

  if (server) {
    if (!(jupe = jupe_find(server))) { /* no such jupe */
      sendto_one(sptr, err_str(ERR_NOSUCHJUPE), me.name, sptr->name, server);
      return 0;
    }

    /* send jupe information along */
    sendto_one(sptr, rpl_str(RPL_JUPELIST), me.name, sptr->name,
	       jupe->ju_server, jupe->ju_expire, JupeIsLocal(jupe) ?
	       me.name : "*", JupeIsActive(jupe) ? '+' : '-', jupe->ju_reason);
  } else {
    for (jupe = GlobalJupeList; jupe; jupe = sjupe) { /* go through jupes */
      sjupe = jupe->ju_next;

      if (jupe->ju_expire <= TStime()) /* expire any that need expiring */
	jupe_free(jupe);
      else /* send jupe information along */
	sendto_one(sptr, rpl_str(RPL_JUPELIST), me.name, sptr->name,
		   jupe->ju_server, jupe->ju_expire, JupeIsLocal(jupe) ?
		   me.name : "*", JupeIsActive(jupe) ? '+' : '-',
		   jupe->ju_reason);
    }
  }

  /* end of jupe information */
  sendto_one(sptr, rpl_str(RPL_ENDOFJUPELIST), me.name, sptr->name);
  return 0;
}
