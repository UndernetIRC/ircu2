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
  static char Sformat[] = ":%s %d %s Connection SendQ SendM SendKBytes "
      "RcveM RcveKBytes :Open since";
  static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :" TIME_T_FMT;
  struct Message *mptr;
  struct Client *acptr;
  struct Gline* gline;
  struct ConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  int i;

/* m_stats is so obnoxiously full of special cases that the different
 * hunt_server() possiblites were becoming very messy. It now uses a
 * switch() so as to be easier to read and update as params change. 
 * -Ghostwolf 
 */
  switch (stat)
  {
      /* open to all, standard # of params */
    case 'U':
    case 'u':
    {
      if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* open to all, varying # of params */
    case 'k':
    case 'K':
    case 'i':
    case 'I':
    case 'p':
    case 'P':
    {
      if (parc > 3)
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      break;
    }

      /* oper only, varying # of params */
    case 'l':
    case 'L':
    case 'M':
    {
      if (parc == 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else if (parc > 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s %s :%s", 2, parc,
            parv) != HUNTED_ISME)
          return 0;
      }
      else if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* oper only, standard # of params */
    default:
    {
      if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }
  }

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0, wilds = 0;
      char *name = "*";
      if (parc > 3 && *parv[3])
      {
        char *p;
        name = parv[3];
        wilds = (*name == '*' || *name == '?');
        for (p = name + 1; *p; ++p)
          if ((*p == '*' || *p == '?') && p[-1] != '\\')
          {
            wilds = 1;
            break;
          }
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      sendto_one(sptr, Sformat, me.name, RPL_STATSLINKINFO, parv[0]);
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Don't show invisible people to unauthorized people when using
         * wildcards  -- Is this still needed now /stats is oper only ? 
         * Yeah it is -- non opers can /stats l, just not remotely.
         */
        if (IsInvisible(acptr) && (doall || wilds) &&
            !(MyConnect(sptr) && IsOper(sptr)) &&
            !IsAnOper(acptr) && (acptr != sptr))
          continue;
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
                   acptr->name, (int)DBufLength(&acptr->sendQ), (int)acptr->sendM,
                   (int)acptr->sendK, (int)acptr->receiveM, (int)acptr->receiveK,
                   CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_remove_expired(TStime());
      for (gline = GlobalGlineList; gline; gline = gline->next) {
        sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name,
                   sptr->name, 'G', gline->name, gline->host,
                   gline->expire, gline->reason);
      }
      break;
    case 'H':
    case 'h':
      break;
    case 'I':
    case 'i':
    case 'K':
    case 'k':                   /* display CONF_IPKILL as well
                                   as CONF_KILL -Kev */
    {
      int wilds, count;
      char *user, *host, *p;
      int conf_status = (stat == 'k' || stat == 'K') ? CONF_KLINE : CONF_CLIENT;
      if ((MyUser(sptr) || IsOper(sptr)) && parc < 4)
      {
        report_configured_links(sptr, conf_status);
        break;
      }
      if (parc < 4 || *parv[3] == '\0')
        return need_more_params(sptr,
                        (conf_status & CONF_KLINE) ? "STATS K" : "STATS I");

      wilds = 0;
      for (p = parv[3]; *p; p++)
      {
        if (*p == '\\')
        {
          if (!*++p)
            break;
          continue;
        }
        if (*p == '?' || *p == '*')
        {
          wilds = 1;
          break;
        }
      }
      if (!(MyConnect(sptr) || IsOper(sptr)))
      {
        wilds = 0;
        count = 3;
      }
      else
        count = 1000;

      if (conf_status == CONF_CLIENT)
      {
        user = 0;            /* Not used, but to avoid compiler warning. */

        host = parv[3];
      }
      else
      {
        if ((host = strchr(parv[3], '@')))
        {
          user = parv[3];
          *host++ = 0;;
        }
        else
        {
          user = 0;
          host = parv[3];
        }
      }
      for (aconf = GlobalConfList; aconf; aconf = aconf->next)
      {
        if ((aconf->status & conf_status))
        {
          if (conf_status == CONF_KLINE)
          {
            if ((!wilds && ((user || aconf->host[1]) &&
                !match(aconf->host, host) &&
                (!user || !match(aconf->name, user)))) ||
                (wilds && !mmatch(host, aconf->host) &&
                (!user || !mmatch(user, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSKLINE), me.name,
                  sptr->name, 'K', aconf->host, aconf->passwd, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
          else if (conf_status == CONF_CLIENT)
          {
            if ((!wilds && (!match(aconf->host, host) ||
                !match(aconf->name, host))) ||
                (wilds && (!mmatch(host, aconf->host) ||
                !mmatch(host, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSILINE), me.name,
                  sptr->name, 'I', aconf->host, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
        }
      }
      break;
    }
    case 'M':
#if !defined(NDEBUG)
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], fda_get_byte_count(), fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring "
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          sendto_one(sptr, rpl_str(RPL_STATSCOMMANDS),
              me.name, parv[0], mptr->cmd, mptr->count, mptr->bytes);
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
      show_ports(sptr, IsOper(sptr), (parc > 3) ? atoi(parv[3]) : 0, 
                 (MyUser(sptr) || IsOper(sptr)) ? 100 : 8);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_configured_links(sptr, CONF_CRULEALL);
      break;
    case 'd':
      report_configured_links(sptr, CONF_CRULE);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      report_configured_links(sptr, CONF_TLINES);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      sendto_one(sptr, rpl_str(RPL_STATSUPTIME), me.name, parv[0],
          nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
      sendto_one(sptr, rpl_str(RPL_STATSCONN), me.name, parv[0],
          max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
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
  sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], stat);
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
  static char Sformat[] = ":%s %d %s Connection SendQ SendM SendKBytes "
      "RcveM RcveKBytes :Open since";
  static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :" TIME_T_FMT;
  struct Message *mptr;
  struct Client *acptr;
  struct Gline* gline;
  struct ConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  int i;

/* m_stats is so obnoxiously full of special cases that the different
 * hunt_server() possiblites were becoming very messy. It now uses a
 * switch() so as to be easier to read and update as params change. 
 * -Ghostwolf 
 */
  switch (stat)
  {
      /* open to all, standard # of params */
    case 'U':
    case 'u':
    {
      if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* open to all, varying # of params */
    case 'k':
    case 'K':
    case 'i':
    case 'I':
    case 'p':
    case 'P':
    {
      if (parc > 3)
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      break;
    }

      /* oper only, varying # of params */
    case 'l':
    case 'L':
    case 'M':
    {
      if (parc == 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else if (parc > 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s %s :%s", 2, parc,
            parv) != HUNTED_ISME)
          return 0;
      }
      else if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* oper only, standard # of params */
    default:
    {
      if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }
  }

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0, wilds = 0;
      char *name = "*";
      if (parc > 3 && *parv[3])
      {
        char *p;
        name = parv[3];
        wilds = (*name == '*' || *name == '?');
        for (p = name + 1; *p; ++p)
          if ((*p == '*' || *p == '?') && p[-1] != '\\')
          {
            wilds = 1;
            break;
          }
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      sendto_one(sptr, Sformat, me.name, RPL_STATSLINKINFO, parv[0]);
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Don't show invisible people to unauthorized people when using
         * wildcards  -- Is this still needed now /stats is oper only ? */
        if (IsInvisible(acptr) && (doall || wilds) &&
            !(MyConnect(sptr) && IsOper(sptr)) &&
            !IsAnOper(acptr) && (acptr != sptr))
          continue;
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
            acptr->name, (int)DBufLength(&acptr->sendQ), (int)acptr->sendM,
            (int)acptr->sendK, (int)acptr->receiveM, (int)acptr->receiveK,
            CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      if (IsAnOper(sptr))
        report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_remove_expired(TStime());
      for (gline = GlobalGlineList; gline; gline = gline->next) {
        sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name,
                   sptr->name, 'G', gline->name, gline->host,
                   gline->expire, gline->reason);
      }
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'I':
    case 'i':
    case 'K':
    case 'k':                   /* display CONF_IPKILL as well
                                   as CONF_KILL -Kev */
    {
      int wilds, count;
      char *user, *host, *p;
      int conf_status = (stat == 'k' || stat == 'K') ? CONF_KLINE : CONF_CLIENT;
      if ((MyUser(sptr) || IsOper(sptr)) && parc < 4)
      {
        report_configured_links(sptr, conf_status);
        break;
      }
      if (parc < 4 || *parv[3] == '\0')
        return need_more_params(sptr,
                        (conf_status & CONF_KLINE) ? "STATS K" : "STATS I");

      wilds = 0;
      for (p = parv[3]; *p; p++)
      {
        if (*p == '\\')
        {
          if (!*++p)
            break;
          continue;
        }
        if (*p == '?' || *p == '*')
        {
          wilds = 1;
          break;
        }
      }
      if (!(MyConnect(sptr) || IsOper(sptr)))
      {
        wilds = 0;
        count = 3;
      }
      else
        count = 1000;

      if (conf_status == CONF_CLIENT)
      {
        user = 0;            /* Not used, but to avoid compiler warning. */

        host = parv[3];
      }
      else
      {
        if ((host = strchr(parv[3], '@')))
        {
          user = parv[3];
          *host++ = 0;;
        }
        else
        {
          user = 0;
          host = parv[3];
        }
      }
      for (aconf = GlobalConfList; aconf; aconf = aconf->next)
      {
        if ((aconf->status & conf_status))
        {
          if (conf_status == CONF_KLINE)
          {
            if ((!wilds && ((user || aconf->host[1]) &&
                !match(aconf->host, host) &&
                (!user || !match(aconf->name, user)))) ||
                (wilds && !mmatch(host, aconf->host) &&
                (!user || !mmatch(user, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSKLINE), me.name,
                  sptr->name, 'K', aconf->host, aconf->passwd, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
          else if (conf_status == CONF_CLIENT)
          {
            if ((!wilds && (!match(aconf->host, host) ||
                !match(aconf->name, host))) ||
                (wilds && (!mmatch(host, aconf->host) ||
                !mmatch(host, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSILINE), me.name,
                  sptr->name, 'I', aconf->host, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
        }
      }
      break;
    }
    case 'M':
#if !defined(NDEBUG)
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], fda_get_byte_count(), fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring "
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          sendto_one(sptr, rpl_str(RPL_STATSCOMMANDS),
              me.name, parv[0], mptr->cmd, mptr->count, mptr->bytes);
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
      show_ports(sptr, IsOper(sptr), (parc > 3) ? atoi(parv[3]) : 0, 
                 (MyUser(sptr) || IsOper(sptr)) ? 100 : 8);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_configured_links(sptr, CONF_CRULEALL);
      break;
    case 'd':
      report_configured_links(sptr, CONF_CRULE);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      report_configured_links(sptr, CONF_TLINES);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      sendto_one(sptr, rpl_str(RPL_STATSUPTIME), me.name, parv[0],
          nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
      sendto_one(sptr, rpl_str(RPL_STATSCONN), me.name, parv[0],
          max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
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
  sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], stat);
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
  static char Sformat[] = ":%s %d %s Connection SendQ SendM SendKBytes "
      "RcveM RcveKBytes :Open since";
  static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :" TIME_T_FMT;
  struct Message *mptr;
  struct Client *acptr;
  struct Gline* gline;
  struct ConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  int i;

/* m_stats is so obnoxiously full of special cases that the different
 * hunt_server() possiblites were becoming very messy. It now uses a
 * switch() so as to be easier to read and update as params change. 
 * -Ghostwolf 
 */
  switch (stat)
  {
      /* open to all, standard # of params */
    case 'U':
    case 'u':
    {
      if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* open to all, varying # of params */
    case 'k':
    case 'K':
    case 'i':
    case 'I':
    case 'p':
    case 'P':
    {
      if (parc > 3)
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      break;
    }

      /* oper only, varying # of params */
    case 'l':
    case 'L':
    case 'M':
    {
      if (parc == 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else if (parc > 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s %s :%s", 2, parc,
            parv) != HUNTED_ISME)
          return 0;
      }
      else if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* oper only, standard # of params */
    default:
    {
      if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }
  }

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0, wilds = 0;
      char *name = "*";
      if (parc > 3 && *parv[3])
      {
        char *p;
        name = parv[3];
        wilds = (*name == '*' || *name == '?');
        for (p = name + 1; *p; ++p)
          if ((*p == '*' || *p == '?') && p[-1] != '\\')
          {
            wilds = 1;
            break;
          }
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      sendto_one(sptr, Sformat, me.name, RPL_STATSLINKINFO, parv[0]);
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Don't show invisible people to unauthorized people when using
         * wildcards  -- Is this still needed now /stats is oper only ? */
        if (IsInvisible(acptr) && (doall || wilds) &&
            !(MyConnect(sptr) && IsOper(sptr)) &&
            !IsAnOper(acptr) && (acptr != sptr))
          continue;
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
            acptr->name, (int)DBufLength(&acptr->sendQ), (int)acptr->sendM,
            (int)acptr->sendK, (int)acptr->receiveM, (int)acptr->receiveK,
            CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_remove_expired(TStime());
      for (gline = GlobalGlineList; gline; gline = gline->next) {
        sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name,
                   sptr->name, 'G', gline->name, gline->host,
                   gline->expire, gline->reason);
      }
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'I':
    case 'i':
    case 'K':
    case 'k':                   /* display CONF_IPKILL as well
                                   as CONF_KILL -Kev */
    {
      int wilds, count;
      char *user, *host, *p;
      int conf_status = (stat == 'k' || stat == 'K') ? CONF_KLINE : CONF_CLIENT;
      if ((MyUser(sptr) || IsOper(sptr)) && parc < 4)
      {
        report_configured_links(sptr, conf_status);
        break;
      }
      if (parc < 4 || *parv[3] == '\0')
        return need_more_params(sptr,
                        (conf_status & CONF_KLINE) ? "STATS K" : "STATS I");

      wilds = 0;
      for (p = parv[3]; *p; p++)
      {
        if (*p == '\\')
        {
          if (!*++p)
            break;
          continue;
        }
        if (*p == '?' || *p == '*')
        {
          wilds = 1;
          break;
        }
      }
      if (!(MyConnect(sptr) || IsOper(sptr)))
      {
        wilds = 0;
        count = 3;
      }
      else
        count = 1000;

      if (conf_status == CONF_CLIENT)
      {
        user = 0;            /* Not used, but to avoid compiler warning. */

        host = parv[3];
      }
      else
      {
        if ((host = strchr(parv[3], '@')))
        {
          user = parv[3];
          *host++ = 0;;
        }
        else
        {
          user = 0;
          host = parv[3];
        }
      }
      for (aconf = GlobalConfList; aconf; aconf = aconf->next)
      {
        if ((aconf->status & conf_status))
        {
          if (conf_status == CONF_KLINE)
          {
            if ((!wilds && ((user || aconf->host[1]) &&
                !match(aconf->host, host) &&
                (!user || !match(aconf->name, user)))) ||
                (wilds && !mmatch(host, aconf->host) &&
                (!user || !mmatch(user, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSKLINE), me.name,
                  sptr->name, 'K', aconf->host, aconf->passwd, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
          else if (conf_status == CONF_CLIENT)
          {
            if ((!wilds && (!match(aconf->host, host) ||
                !match(aconf->name, host))) ||
                (wilds && (!mmatch(host, aconf->host) ||
                !mmatch(host, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSILINE), me.name,
                  sptr->name, 'I', aconf->host, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
        }
      }
      break;
    }
    case 'M':
#if !defined(NDEBUG)
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], fda_get_byte_count(), fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring "
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          sendto_one(sptr, rpl_str(RPL_STATSCOMMANDS),
              me.name, parv[0], mptr->cmd, mptr->count, mptr->bytes);
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
      show_ports(sptr, IsOper(sptr), (parc > 3) ? atoi(parv[3]) : 0, 
                 (MyUser(sptr) || IsOper(sptr)) ? 100 : 8);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_configured_links(sptr, CONF_CRULEALL);
      break;
    case 'd':
      report_configured_links(sptr, CONF_CRULE);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      report_configured_links(sptr, CONF_TLINES);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      sendto_one(sptr, rpl_str(RPL_STATSUPTIME), me.name, parv[0],
          nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
      sendto_one(sptr, rpl_str(RPL_STATSCONN), me.name, parv[0],
          max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
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
  sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], stat);
  return 0;
}

#if 0
/*
 * m_stats
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
int m_stats(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  static char Sformat[] = ":%s %d %s Connection SendQ SendM SendKBytes "
      "RcveM RcveKBytes :Open since";
  static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :" TIME_T_FMT;
  struct Message *mptr;
  struct Client *acptr;
  struct Gline* gline;
  struct ConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  int i;

/* m_stats is so obnoxiously full of special cases that the different
 * hunt_server() possiblites were becoming very messy. It now uses a
 * switch() so as to be easier to read and update as params change. 
 * -Ghostwolf 
 */
  switch (stat)
  {
      /* open to all, standard # of params */
    case 'U':
    case 'u':
    {
      if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* open to all, varying # of params */
    case 'k':
    case 'K':
    case 'i':
    case 'I':
    case 'p':
    case 'P':
    {
      if (parc > 3)
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else
      {
        if (hunt_server(0, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      break;
    }

      /* oper only, varying # of params */
    case 'l':
    case 'L':
    case 'M':
    {
      if (parc == 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s :%s", 2, parc, parv)
            != HUNTED_ISME)
          return 0;
      }
      else if (parc > 4)
      {
        if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s %s %s :%s", 2, parc,
            parv) != HUNTED_ISME)
          return 0;
      }
      else if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }

      /* oper only, standard # of params */
    default:
    {
      if (hunt_server(1, cptr, sptr, "%s%s " TOK_STATS " %s :%s", 2, parc, parv)
          != HUNTED_ISME)
        return 0;
      break;
    }
  }

  switch (stat)
  {
    case 'L':
    case 'l':
    {
      int doall = 0, wilds = 0;
      char *name = "*";
      if (parc > 3 && *parv[3])
      {
        char *p;
        name = parv[3];
        wilds = (*name == '*' || *name == '?');
        for (p = name + 1; *p; ++p)
          if ((*p == '*' || *p == '?') && p[-1] != '\\')
          {
            wilds = 1;
            break;
          }
      }
      else
        doall = 1;
      /*
       * Send info about connections which match, or all if the
       * mask matches me.name.  Only restrictions are on those who
       * are invisible not being visible to 'foreigners' who use
       * a wild card based search to list it.
       */
      sendto_one(sptr, Sformat, me.name, RPL_STATSLINKINFO, parv[0]);
      for (i = 0; i <= HighestFd; i++)
      {
        if (!(acptr = LocalClientArray[i]))
          continue;
        /* Don't return clients when this is a request for `all' */
        if (doall && IsUser(acptr))
          continue;
        /* Don't show invisible people to unauthorized people when using
         * wildcards  -- Is this still needed now /stats is oper only ? */
        if (IsInvisible(acptr) && (doall || wilds) &&
            !(MyConnect(sptr) && IsOper(sptr)) &&
            !IsAnOper(acptr) && (acptr != sptr))
          continue;
        /* Only show the ones that match the given mask - if any */
        if (!doall && wilds && match(name, acptr->name))
          continue;
        /* Skip all that do not match the specific query */
        if (!(doall || wilds) && 0 != ircd_strcmp(name, acptr->name))
          continue;
        sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
                   acptr->name,
                   (int)DBufLength(&acptr->sendQ), (int)acptr->sendM,
                   (int)acptr->sendK, (int)acptr->receiveM, (int)acptr->receiveK,
                   CurrentTime - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr, CONF_SERVER);
      break;
    case 'G':
    case 'g': /* send glines */
      gline_remove_expired(TStime());
      for (gline = GlobalGlineList; gline; gline = gline->next) {
        sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name,
                   sptr->name, 'G', gline->name, gline->host,
                   gline->expire, gline->reason);
      }
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'I':
    case 'i':
    case 'K':
    case 'k':                   /* display CONF_IPKILL as well
                                   as CONF_KILL -Kev */
    {
      int wilds, count;
      char *user, *host, *p;
      int conf_status = (stat == 'k' || stat == 'K') ? CONF_KLINE : CONF_CLIENT;
      if ((MyUser(sptr) || IsOper(sptr)) && parc < 4)
      {
        report_configured_links(sptr, conf_status);
        break;
      }
      if (parc < 4 || *parv[3] == '\0')
        return need_more_params(sptr,
                        (conf_status & CONF_KLINE) ? "STATS K" : "STATS I");

      wilds = 0;
      for (p = parv[3]; *p; p++)
      {
        if (*p == '\\')
        {
          if (!*++p)
            break;
          continue;
        }
        if (*p == '?' || *p == '*')
        {
          wilds = 1;
          break;
        }
      }
      if (!(MyConnect(sptr) || IsOper(sptr)))
      {
        wilds = 0;
        count = 3;
      }
      else
        count = 1000;

      if (conf_status == CONF_CLIENT)
      {
        user = 0;            /* Not used, but to avoid compiler warning. */

        host = parv[3];
      }
      else
      {
        if ((host = strchr(parv[3], '@')))
        {
          user = parv[3];
          *host++ = 0;;
        }
        else
        {
          user = 0;
          host = parv[3];
        }
      }
      for (aconf = GlobalConfList; aconf; aconf = aconf->next)
      {
        if ((aconf->status & conf_status))
        {
          if (conf_status == CONF_KLINE)
          {
            if ((!wilds && ((user || aconf->host[1]) &&
                !match(aconf->host, host) &&
                (!user || !match(aconf->name, user)))) ||
                (wilds && !mmatch(host, aconf->host) &&
                (!user || !mmatch(user, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSKLINE), me.name,
                  sptr->name, 'K', aconf->host, aconf->passwd, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
          else if (conf_status == CONF_CLIENT)
          {
            if ((!wilds && (!match(aconf->host, host) ||
                !match(aconf->name, host))) ||
                (wilds && (!mmatch(host, aconf->host) ||
                !mmatch(host, aconf->name))))
            {
              sendto_one(sptr, rpl_str(RPL_STATSILINE), me.name,
                  sptr->name, 'I', aconf->host, aconf->name,
                  aconf->port, get_conf_class(aconf));
              if (--count == 0)
                break;
            }
          }
        }
      }
      break;
    }
    case 'M':
#if !defined(NDEBUG)
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], fda_get_byte_count(), fda_get_block_count());
#endif

#if 0
#ifdef MEMSIZESTATS
      sendto_one(sptr, rpl_str(RPL_STATMEMTOT),
          me.name, parv[0], get_mem_size(), get_alloc_cnt());
#endif
#ifdef MEMLEAKSTATS
      report_memleak_stats(sptr, parc, parv);
#endif
#if !defined(MEMSIZESTATS) && !defined(MEMLEAKSTATS)
      sendto_one(sptr, ":%s NOTICE %s :stats M : Memory allocation monitoring "
          "is not enabled on this server", me.name, parv[0]);
#endif
#endif /* 0 */
      break;
    case 'm':
      for (mptr = msgtab; mptr->cmd; mptr++)
        if (mptr->count)
          sendto_one(sptr, rpl_str(RPL_STATSCOMMANDS),
              me.name, parv[0], mptr->cmd, mptr->count, mptr->bytes);
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
      show_ports(sptr, IsOper(sptr), (parc > 3) ? atoi(parv[3]) : 0, 
                 (MyUser(sptr) || IsOper(sptr)) ? 100 : 8);
      break;
    case 'R':
    case 'r':
#ifdef DEBUGMODE
      send_usage(sptr, parv[0]);
#endif
      break;
    case 'D':
      report_configured_links(sptr, CONF_CRULEALL);
      break;
    case 'd':
      report_configured_links(sptr, CONF_CRULE);
      break;
    case 't':
      tstats(sptr, parv[0]);
      break;
    case 'T':
      report_configured_links(sptr, CONF_TLINES);
      break;
    case 'U':
      report_configured_links(sptr, CONF_UWORLD);
      break;
    case 'u':
    {
      time_t nowr;

      nowr = CurrentTime - me.since;
      sendto_one(sptr, rpl_str(RPL_STATSUPTIME), me.name, parv[0],
                 nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
      sendto_one(sptr, rpl_str(RPL_STATSCONN), me.name, parv[0],
                 max_connection_count, max_client_count);
      break;
    }
    case 'W':
    case 'w':
      calc_load(sptr);
      break;
    case 'X':
    case 'x':
#ifdef  DEBUGMODE
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
  sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], stat);
  return 0;
}
#endif /* 0 */
