/*
 * IRC - Internet Relay Chat, ircd/m_stats.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
/*
 * XXX - ack!!!
 */
#include "s_stats.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "userload.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


int report_klines(struct Client* sptr, char* mask, int limit_query)
{
  int   wilds = 0;
  int   count = 3;
  char* user  = 0;
  char* host;
  const struct DenyConf* conf;

  if (EmptyString(mask)) {
    if (limit_query)
      return need_more_params(sptr, "STATS K");
    else
      report_deny_list(sptr);
    return 1;
  }

  if (!limit_query) {
    wilds = string_has_wildcards(mask);
    count = 1000;
  }

  if ((host = strchr(mask, '@'))) {
    user = mask;
    *host++ = '\0';
  }
  else {
    host = mask;
  }

  for (conf = conf_get_deny_list(); conf; conf = conf->next) {
    if ((!wilds && ((user || conf->hostmask) &&
	!match(conf->hostmask, host) &&
	(!user || !match(conf->usermask, user)))) ||
	(wilds && !mmatch(host, conf->hostmask) &&
	(!user || !mmatch(user, conf->usermask))))
    {
      send_reply(sptr, RPL_STATSKLINE, (conf->ip_kill) ? 'k' : 'K',
                 conf->hostmask, conf->message, conf->usermask);
      if (--count == 0)
	return 1;
    }
  }
  /* send_reply(sptr, RPL_ENDOFSTATS, stat); */
  return 1;
}


/*
 * m_stats - generic message handler
 *
 *    parv[0] = sender prefix
 *    parv[1] = statistics selector (defaults to Message frequency)
 *    parv[2] = target server (current server defaulted, if omitted)
 * And 'stats l' and 'stats' L:
 *    parv[3] = server mask ("*" defaulted, if omitted)
 * Or for stats p,P:
 *    parv[3] = port mask (returns p-lines when its port is matched by this)
 * Or for stats k,K,i and I:
 *    parv[3] = [user@]host.name  (returns which K/I-lines match this)
 *           or [user@]host.mask  (returns which K/I-lines are mmatched by this)
 *              (defaults to old reply if ommitted, when local or Oper)
 *              A remote mask (something containing wildcards) is only
 *              allowed for IRC Operators.
 * Or for stats M:
 *    parv[3] = time param
 *    parv[4] = time param 
 *    (see report_memleak_stats() in runmalloc.c for details)
 *
 * This function is getting really ugly. -Ghostwolf
 */
int m_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Message *mptr;
  struct Client *acptr;
  struct ConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  const char **infotext = statsinfo;
  int i;

  if (hunt_stats(cptr, sptr, parc, parv, stat) != HUNTED_ISME)
    return 0;

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0;
      int wilds = 0;
      char *name = "*";

      if (parc > 3 && !EmptyString(parv[3])) {
        name = parv[3];
        wilds = string_has_wildcards(name);
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO, "Connection SendQ "
                 "SendM SendKBytes RcveM RcveKBytes :Open since");
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Don't show invisible people to non opers unless they know the nick */
        if (IsInvisible(acptr) && (doall || wilds) && !IsAnOper(acptr) && (acptr != sptr))
          continue;
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO,
                   "%s %u %u %u %u %u :%Tu", (*acptr->name) ? acptr->name : "<unregistered>",
                   (int)MsgQLength(&acptr->sendQ), (int)acptr->sendM,
                   (int)acptr->sendK, (int)acptr->receiveM,
                   (int)acptr->receiveK, CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_stats(sptr);
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'K':
    case 'k':    /* display CONF_IPKILL as well as CONF_KILL -Kev */
      if (0 == report_klines(sptr, (parc == 4) ? parv[3] : 0, 0))
        return 0;
      break;
    case 'F':
    case 'f':
      report_feature_list(sptr);
      break;
    case 'I':
    case 'i':
    {
      int wilds = 0;
      int count = 1000;
      char* host;

      if (parc < 4) {
        report_configured_links(sptr, CONF_CLIENT);
        break;
      }
      if (EmptyString(parv[3]))
        return need_more_params(sptr, "STATS I");

      host = parv[3];
      wilds = string_has_wildcards(host);

      for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
	if (CONF_CLIENT == aconf->status) {
	  if ((!wilds && (!match(aconf->host, host) ||
	      !match(aconf->name, host))) ||
	      (wilds && (!mmatch(host, aconf->host) ||
	      !mmatch(host, aconf->name))))
	  {
	    send_reply(sptr, RPL_STATSILINE, 'I', aconf->host, aconf->name,
		       aconf->port, get_conf_class(aconf));
	    if (--count == 0)
	      break;
	  }
	}
      }
      break;
    }
    case 'M':
#if !defined(NDEBUG)
      send_reply(sptr, RPL_STATMEMTOT, fda_get_byte_count(),
                 fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT), /* XXX DEAD */
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring " /* XXX DEAD */
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          send_reply(sptr, RPL_STATSCOMMANDS, mptr->cmd, mptr->count,
                     mptr->bytes);
      break;
    case 'o':
    case 'O':
      report_configured_links(sptr, CONF_OPS);
      break;
    case 'p':
    case 'P':
      /*
       * show listener ports
       * show hidden ports to opers, if there are more than 3 parameters,
       * interpret the fourth parameter as the port number.
       */ 
      show_ports(sptr, 0, (parc > 3) ? atoi(parv[3]) : 0, 100);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_crule_list(sptr, CRULE_ALL);
      break;
    case 'd':
      report_crule_list(sptr, CRULE_MASK);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      motd_report(sptr);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      send_reply(sptr, RPL_STATSUPTIME, nowr / 86400, (nowr / 3600) % 24,
                 (nowr / 60) % 60, nowr % 60);
      send_reply(sptr, RPL_STATSCONN, max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
      class_send_meminfo(sptr);
      send_listinfo(sptr, parv[0]);
#endif
      break;
    case 'Y':
    case 'y':
      report_classes(sptr);
      break;
    case 'Z':
    case 'z':
      count_memory(sptr, parv[0]);
      break;
    default:
      stat = '*';
      while (*infotext)
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, *infotext++);
      break;
  }
  send_reply(sptr, RPL_ENDOFSTATS, stat);
  return 0;
}

/*
 * ms_stats - server message handler
 *
 *    parv[0] = sender prefix
 *    parv[1] = statistics selector (defaults to Message frequency)
 *    parv[2] = target server (current server defaulted, if omitted)
 * And 'stats l' and 'stats' L:
 *    parv[3] = server mask ("*" defaulted, if omitted)
 * Or for stats p,P:
 *    parv[3] = port mask (returns p-lines when its port is matched by this)
 * Or for stats k,K,i and I:
 *    parv[3] = [user@]host.name  (returns which K/I-lines match this)
 *           or [user@]host.mask  (returns which K/I-lines are mmatched by this)
 *              (defaults to old reply if ommitted, when local or Oper)
 *              A remote mask (something containing wildcards) is only
 *              allowed for IRC Operators.
 * Or for stats M:
 *    parv[3] = time param
 *    parv[4] = time param 
 *    (see report_memleak_stats() in runmalloc.c for details)
 *
 * This function is getting really ugly. -Ghostwolf
 */
int ms_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Message *mptr;
  struct Client *acptr;
  struct ConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  int i;

  if (hunt_stats(cptr, sptr, parc, parv, stat) != HUNTED_ISME)
    return 0;

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0;
      int wilds = 0;
      char *name = "*";

      if (parc > 3 && !EmptyString(parv[3])) {
        name = parv[3];
        wilds = string_has_wildcards(name);
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO, "Connection SendQ "
                 "SendM SendKBytes RcveM RcveKBytes :Open since");
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Don't show invisible people to unauthorized people when using
         * wildcards  -- Is this still needed now /stats is oper only ? 
         * Not here, because ms_stats is specifically a remote command, 
         * thus the check was removed. -Ghostwolf */
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO,
                   "%s %u %u %u %u %u :%Tu", acptr->name,
                   (int)MsgQLength(&acptr->sendQ), (int)acptr->sendM,
                   (int)acptr->sendK, (int)acptr->receiveM,
                   (int)acptr->receiveK, CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_stats(sptr);
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'K':
    case 'k':    /* display CONF_IPKILL as well as CONF_KILL -Kev */
      if (0 == report_klines(sptr, (parc > 3) ? parv[3] : 0, !IsOper(sptr)))
        return 0;
      break;
    case 'F':
    case 'f':
      report_feature_list(sptr);
      break;
    case 'I':
    case 'i':
    {
      int   wilds = 0;
      int   count = 3;
      char* host;

      if (parc < 4 && IsOper(sptr)) {
        report_configured_links(sptr, CONF_CLIENT);
        break;
      }
      if (parc < 4 || EmptyString(parv[3]))
        return need_more_params(sptr, "STATS I");

      if (IsOper(sptr)) {
        wilds = string_has_wildcards(parv[3]);
        count = 1000;
      }

      host = parv[3];

      for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
	if (CONF_CLIENT == aconf->status) {
	  if ((!wilds && (!match(aconf->host, host) ||
	      !match(aconf->name, host))) ||
	      (wilds && (!mmatch(host, aconf->host) ||
	      !mmatch(host, aconf->name))))
	  {
	    send_reply(sptr, RPL_STATSILINE, 'I', aconf->host, aconf->name,
		       aconf->port, get_conf_class(aconf));
	    if (--count == 0)
	      break;
	  }
	}
      }
      break;
    }
    case 'M':
#if !defined(NDEBUG)
      send_reply(sptr, RPL_STATMEMTOT, fda_get_byte_count(),
                 fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT), /* XXX DEAD */
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring " /* XXX DEAD */
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          send_reply(sptr, RPL_STATSCOMMANDS, mptr->cmd, mptr->count,
                     mptr->bytes);
      break;
    case 'o':
    case 'O':
      report_configured_links(sptr, CONF_OPS);
      break;
    case 'p':
    case 'P':
      /*
       * show listener ports
       * show hidden ports to opers, if there are more than 3 parameters,
       * interpret the fourth parameter as the port number, limit non-local
       * or non-oper results to 8 ports.
       */ 
      show_ports(sptr, IsOper(sptr), (parc > 3) ? atoi(parv[3]) : 0, IsOper(sptr) ? 100 : 8);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_crule_list(sptr, CRULE_ALL);
      break;
    case 'd':
      report_crule_list(sptr, CRULE_MASK);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      motd_report(sptr);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      send_reply(sptr, RPL_STATSUPTIME, nowr / 86400, (nowr / 3600) % 24,
                 (nowr / 60) % 60, nowr % 60);
      send_reply(sptr, RPL_STATSCONN, max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
      class_send_meminfo(sptr);
      send_listinfo(sptr, parv[0]);
#endif
      break;
    case 'Y':
    case 'y':
      report_classes(sptr);
      break;
    case 'Z':
    case 'z':
      count_memory(sptr, parv[0]);
      break;
    default:
      stat = '*';
      break;
  }
  send_reply(sptr, RPL_ENDOFSTATS, stat);
  return 0;
}

/*
 * mo_stats - oper message handler
 *
 *    parv[0] = sender prefix
 *    parv[1] = statistics selector (defaults to Message frequency)
 *    parv[2] = target server (current server defaulted, if omitted)
 * And 'stats l' and 'stats' L:
 *    parv[3] = server mask ("*" defaulted, if omitted)
 * Or for stats p,P:
 *    parv[3] = port mask (returns p-lines when its port is matched by this)
 * Or for stats k,K,i and I:
 *    parv[3] = [user@]host.name  (returns which K/I-lines match this)
 *           or [user@]host.mask  (returns which K/I-lines are mmatched by this)
 *              (defaults to old reply if ommitted, when local or Oper)
 *              A remote mask (something containing wildcards) is only
 *              allowed for IRC Operators.
 * Or for stats M:
 *    parv[3] = time param
 *    parv[4] = time param 
 *    (see report_memleak_stats() in runmalloc.c for details)
 *
 * This function is getting really ugly. -Ghostwolf
 */
int mo_stats(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Message*  mptr;
  struct Client*   acptr;
  struct ConfItem* aconf;
  char             stat = parc > 1 ? parv[1][0] : '\0';
  const char**     infotext = statsinfo;
  int              i;

  if (hunt_stats(cptr, sptr, parc, parv, stat) != HUNTED_ISME)
    return 0;

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0, wilds = 0;
      char* name = "*";
      if (parc > 3 && !EmptyString(parv[3])) {
        name = parv[3];
        wilds = string_has_wildcards(name);
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO, "Connection SendQ "
                 "SendM SendKBytes RcveM RcveKBytes :Open since");
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO,
                   "%s %u %u %u %u %u :%Tu", acptr->name,
                   (int)MsgQLength(&acptr->sendQ), (int)acptr->sendM,
                   (int)acptr->sendK, (int)acptr->receiveM,
                   (int)acptr->receiveK, CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_stats(sptr);
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'K':
    case 'k':    /* display CONF_IPKILL as well as CONF_KILL -Kev */
      if (0 == report_klines(sptr, (parc > 3) ? parv[3] : 0, 0))
        return 0;
      break;
    case 'F':
    case 'f':
      report_feature_list(sptr);
      break;
    case 'I':
    case 'i':
      {
	int   wilds = 0;
	int   count = 1000;
	char* host;

	if (parc < 4) {
	  report_configured_links(sptr, CONF_CLIENT);
	  break;
	}
        if (EmptyString(parv[3]))
          return need_more_params(sptr, "STATS I");

	host = parv[3];
	wilds = string_has_wildcards(host);

	for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
	  if (CONF_CLIENT == aconf->status) {
	    if ((!wilds && (!match(aconf->host, host) ||
		!match(aconf->name, host))) ||
		(wilds && (!mmatch(host, aconf->host) ||
		!mmatch(host, aconf->name))))
	    {
	      send_reply(sptr, RPL_STATSILINE, 'I', aconf->host, aconf->name,
			 aconf->port, get_conf_class(aconf));
	      if (--count == 0)
		break;
	    }
	  }
	}
      }
      break;
    case 'M':
#if !defined(NDEBUG)
      send_reply(sptr, RPL_STATMEMTOT, fda_get_byte_count(),
                 fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT), /* XXX DEAD */
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring " /* XXX DEAD */
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          send_reply(sptr, RPL_STATSCOMMANDS, mptr->cmd, mptr->count,
                     mptr->bytes);
      break;
    case 'o':
    case 'O':
      report_configured_links(sptr, CONF_OPS);
      break;
    case 'p':
    case 'P':
      /*
       * show listener ports
       * show hidden ports to opers, if there are more than 3 parameters,
       * interpret the fourth parameter as the port number, limit non-local
       * or non-oper results to 8 ports.
       */ 
      show_ports(sptr, 1, (parc > 3) ? atoi(parv[3]) : 0, 100);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_crule_list(sptr, CRULE_ALL);
      break;
    case 'd':
      report_crule_list(sptr, CRULE_MASK);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      motd_report(sptr);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      send_reply(sptr, RPL_STATSUPTIME, nowr / 86400, (nowr / 3600) % 24,
                 (nowr / 60) % 60, nowr % 60);
      send_reply(sptr, RPL_STATSCONN, max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
      class_send_meminfo(sptr);
      send_listinfo(sptr, parv[0]);
#endif
      break;
    case 'Y':
    case 'y':
      report_classes(sptr);
      break;
    case 'Z':
    case 'z':
      count_memory(sptr, parv[0]);
      break;
    default:
      stat = '*';
      while (*infotext)
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, *infotext++);
      break;
  }
  send_reply(sptr, RPL_ENDOFSTATS, stat);
  return 0;
}

