/*
 * IRC - Internet Relay Chat, ircd/opercmds.c (formerly ircd/s_serv.c)
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
 */

#include "sys.h"
#include <sys/stat.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdlib.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include "h.h"
#include "opercmds.h"
#include "struct.h"
#include "ircd.h"
#include "s_bsd.h"
#include "send.h"
#include "s_err.h"
#include "numeric.h"
#include "match.h"
#include "s_misc.h"
#include "s_conf.h"
#include "class.h"
#include "s_user.h"
#include "common.h"
#include "msg.h"
#include "sprintf_irc.h"
#include "userload.h"
#include "parse.h"
#include "numnicks.h"
#include "crule.h"
#include "version.h"
#include "support.h"
#include "s_serv.h"
#include "hash.h"

RCSTAG_CC("$Id$");

/*
 *  m_squit
 *
 *    parv[0] = sender prefix
 *    parv[1] = server name
 *    parv[2] = timestamp
 *    parv[parc-1] = comment
 */
int m_squit(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 aConfItem *aconf;
  char *server;
  Reg2 aClient *acptr;
  char *comment = (parc > ((!IsServer(cptr)) ? 2 : 3) &&
      !BadPtr(parv[parc - 1])) ? parv[parc - 1] : cptr->name;

  if (!IsPrivileged(sptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }

  if (parc > (IsServer(cptr) ? 2 : 1))
  {
    server = parv[1];
    /*
     * To accomodate host masking, a squit for a masked server
     * name is expanded if the incoming mask is the same as
     * the server name for that link to the name of link.
     */
    if ((*server == '*') && IsServer(cptr) && (aconf = cptr->serv->nline) &&
	!strCasediff(server, my_name_for_link(me.name, aconf)))
    {
      server = cptr->name;
      acptr = cptr;
    }
    else
    {
      /*
       * The following allows wild cards in SQUIT. Only usefull
       * when the command is issued by an oper.
       */
      for (acptr = client; (acptr = next_client(acptr, server));
	  acptr = acptr->next)
	if (IsServer(acptr) || IsMe(acptr))
	  break;

      if (acptr)
      {
	if (IsMe(acptr))
	{
	  if (IsServer(cptr))
	  {
	    acptr = cptr;
	    server = cptr->sockhost;
	  }
	  else
	    acptr = NULL;
	}
	else
	{
	  /*
	   * Look for a matching server that is closer,
	   * that way we won't accidently squit two close
	   * servers like davis.* and davis-r.* when typing
	   * /SQUIT davis*
	   */
	  aClient *acptr2;
	  for (acptr2 = acptr->serv->up; acptr2 != &me;
	      acptr2 = acptr2->serv->up)
	    if (!match(server, acptr2->name))
	      acptr = acptr2;
	}
      }
    }
    /* If atoi(parv[2]) == 0 we must indeed squit !
     * It wil be our neighbour.
     */
    if (acptr && IsServer(cptr) &&
	atoi(parv[2]) && atoi(parv[2]) != acptr->serv->timestamp)
    {
      Debug((DEBUG_NOTICE, "Ignoring SQUIT with wrong timestamp"));
      return 0;
    }
  }
  else
  {
    sendto_one(cptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "SQUIT");
    if (IsServer(cptr))
    {
      /*
       * This is actually protocol error. But, well, closing
       * the link is very proper answer to that...
       */
      server = cptr->sockhost;
      acptr = cptr;
    }
    else
      return 0;
  }
  if (!acptr)
  {
    if (IsUser(sptr))
      sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], server);
    return 0;
  }
  if (IsLocOp(sptr) && !MyConnect(acptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }

  return exit_client(cptr, acptr, sptr, comment);
}

/*
 * m_stats/stats_conf
 *
 * Report N/C-configuration lines from this server. This could
 * report other configuration lines too, but converting the
 * status back to "char" is a bit akward--not worth the code
 * it needs...
 *
 * Note: The info is reported in the order the server uses
 *       it--not reversed as in ircd.conf!
 */

static unsigned int report_array[17][3] = {
  {CONF_CONNECT_SERVER, RPL_STATSCLINE, 'C'},
  {CONF_NOCONNECT_SERVER, RPL_STATSNLINE, 'N'},
  {CONF_CLIENT, RPL_STATSILINE, 'I'},
  {CONF_KILL, RPL_STATSKLINE, 'K'},
  {CONF_IPKILL, RPL_STATSKLINE, 'k'},
  {CONF_LEAF, RPL_STATSLLINE, 'L'},
  {CONF_OPERATOR, RPL_STATSOLINE, 'O'},
  {CONF_HUB, RPL_STATSHLINE, 'H'},
  {CONF_LOCOP, RPL_STATSOLINE, 'o'},
  {CONF_CRULEALL, RPL_STATSDLINE, 'D'},
  {CONF_CRULEAUTO, RPL_STATSDLINE, 'd'},
  {CONF_UWORLD, RPL_STATSULINE, 'U'},
  {CONF_TLINES, RPL_STATSTLINE, 'T'},
  {CONF_LISTEN_PORT, RPL_STATSPLINE, 'P'},
  {0, 0}
};

static void report_configured_links(aClient *sptr, int mask)
{
  static char null[] = "<NULL>";
  aConfItem *tmp;
  unsigned int *p;
  unsigned short int port;
  char c, *host, *pass, *name;

  for (tmp = conf; tmp; tmp = tmp->next)
    if ((tmp->status & mask))
    {
      for (p = &report_array[0][0]; *p; p += 3)
	if (*p == tmp->status)
	  break;
      if (!*p)
	continue;
      c = (char)*(p + 2);
      host = BadPtr(tmp->host) ? null : tmp->host;
      pass = BadPtr(tmp->passwd) ? null : tmp->passwd;
      name = BadPtr(tmp->name) ? null : tmp->name;
      port = tmp->port;
      /*
       * On K line the passwd contents can be
       * displayed on STATS reply.    -Vesa
       */
      /* Special-case 'k' or 'K' lines as appropriate... -Kev */
      if ((tmp->status & CONF_KLINE))
	sendto_one(sptr, rpl_str(p[1]), me.name,
	    sptr->name, c, host, pass, name, port, get_conf_class(tmp));
      /* connect rules are classless */
      else if ((tmp->status & CONF_CRULE))
	sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, host, name);
      else if ((tmp->status & CONF_TLINES))
	sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, host, pass);
      else if ((tmp->status & CONF_LISTEN_PORT))
	sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, port,
	    tmp->clients, tmp->status);
      else if ((tmp->status & CONF_UWORLD))
	sendto_one(sptr, rpl_str(p[1]),
	    me.name, sptr->name, c, host, pass, name, port,
	    get_conf_class(tmp));
      else
	sendto_one(sptr, rpl_str(p[1]), me.name, sptr->name, c, host, name,
	    port, get_conf_class(tmp));
    }
  return;
}

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
int m_stats(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  static char Sformat[] = ":%s %d %s Connection SendQ SendM SendKBytes "
      "RcveM RcveKBytes :Open since";
  static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :" TIME_T_FMT;
  aMessage *mptr;
  aClient *acptr;
  aGline *agline, *a2gline;
  aConfItem *aconf;
  char stat = parc > 1 ? parv[1][0] : '\0';
  Reg1 int i;

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
      if (hunt_server(0, cptr, sptr, ":%s STATS %s :%s", 2, parc, parv)
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
	if (hunt_server(0, cptr, sptr, ":%s STATS %s %s :%s", 2, parc, parv)
	    != HUNTED_ISME)
	  return 0;
      }
      else
      {
	if (hunt_server(0, cptr, sptr, ":%s STATS %s :%s", 2, parc, parv)
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
	if (hunt_server(1, cptr, sptr, ":%s STATS %s %s :%s", 2, parc, parv)
	    != HUNTED_ISME)
	  return 0;
      }
      else if (parc > 4)
      {
	if (hunt_server(1, cptr, sptr, ":%s STATS %s %s %s :%s", 2, parc,
	    parv) != HUNTED_ISME)
	  return 0;
      }
      else if (hunt_server(1, cptr, sptr, ":%s STATS %s :%s", 2, parc, parv)
	  != HUNTED_ISME)
	return 0;
      break;
    }

      /* oper only, standard # of params */
    default:
    {
      if (hunt_server(1, cptr, sptr, ":%s STATS %s :%s", 2, parc, parv)
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
      for (i = 0; i <= highest_fd; i++)
      {
	if (!(acptr = loc_clients[i]))
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
	if (!(doall || wilds) && strCasediff(name, acptr->name))
	  continue;
	sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
	    (isUpper(stat)) ?
	    get_client_name(acptr, TRUE) : get_client_name(acptr, FALSE),
	    (int)DBufLength(&acptr->sendQ), (int)acptr->sendM,
	    (int)acptr->sendK, (int)acptr->receiveM, (int)acptr->receiveK,
	    time(NULL) - acptr->firsttime);
      }
      break;
    }
    case 'C':
    case 'c':
      report_configured_links(sptr,
	  CONF_CONNECT_SERVER | CONF_NOCONNECT_SERVER);
      break;
    case 'G':
    case 'g':
      /* send glines */
      for (agline = gline, a2gline = NULL; agline; agline = agline->next)
      {
	if (agline->expire <= TStime())
	{			/* handle expired glines */
	  free_gline(agline, a2gline);
	  agline = a2gline ? a2gline : gline;	/* make sure to splice
						   list together */
	  if (!agline)
	    break;		/* last gline; break out of loop */
	  continue;		/* continue! */
	}
	sendto_one(sptr, rpl_str(RPL_STATSGLINE), me.name,
	    sptr->name, 'G', agline->name, agline->host,
	    agline->expire, agline->reason);
	a2gline = agline;
      }
      break;
    case 'H':
    case 'h':
      report_configured_links(sptr, CONF_HUB | CONF_LEAF);
      break;
    case 'I':
    case 'i':
    case 'K':
    case 'k':			/* display CONF_IPKILL as well
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
      {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
	    (conf_status & CONF_KLINE) ? "STATS K" : "STATS I");
	return 0;
      }
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
	user = NULL;		/* Not used, but to avoid compiler warning. */

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
	  user = NULL;
	  host = parv[3];
	}
      }
      for (aconf = conf; aconf; aconf = aconf->next)
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
    {
      int count = 100;
      char port[6];
      if ((MyUser(sptr) || IsOper(sptr)) && parc < 4)
      {
	report_configured_links(sptr, CONF_LISTEN_PORT);
	break;
      }
      if (!(MyConnect(sptr) || IsOper(sptr)))
	count = 3;
      for (aconf = conf; aconf; aconf = aconf->next)
	if (aconf->status == CONF_LISTEN_PORT)
	{
	  if (parc >= 4 && *parv[3] != '\0')
	  {
	    sprintf_irc(port, "%u", aconf->port);
	    if (match(parv[3], port))
	      continue;
	  }
	  sendto_one(sptr, rpl_str(RPL_STATSPLINE), me.name, sptr->name, 'P',
	      aconf->port, aconf->clients, aconf->status);
	  if (--count == 0)
	    break;
	}
      break;
    }
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
      register time_t nowr;

      nowr = now - me.since;
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
#ifdef	DEBUGMODE
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
 *  m_connect                           - Added by Jto 11 Feb 1989
 *
 *    parv[0] = sender prefix
 *    parv[1] = servername
 *    parv[2] = port number
 *    parv[3] = remote server
 */
int m_connect(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  int retval;
  unsigned short int port, tmpport;
  aConfItem *aconf, *cconf;
  aClient *acptr;

  if (!IsPrivileged(sptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return -1;
  }

  if (IsLocOp(sptr) && parc > 3)	/* Only allow LocOps to make */
    return 0;			/* local CONNECTS --SRB      */

  if (parc > 3 && MyUser(sptr))
  {
    aClient *acptr2, *acptr3;
    if (!(acptr3 = find_match_server(parv[3])))
    {
      sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], parv[3]);
      return 0;
    }

    /* Look for closest matching server */
    for (acptr2 = acptr3; acptr2 != &me; acptr2 = acptr2->serv->up)
      if (!match(parv[3], acptr2->name))
	acptr3 = acptr2;

    parv[3] = acptr3->name;
  }

  if (hunt_server(1, cptr, sptr, ":%s CONNECT %s %s :%s", 3, parc, parv) !=
      HUNTED_ISME)
    return 0;

  if (parc < 2 || *parv[1] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "CONNECT");
    return -1;
  }

  if ((acptr = FindServer(parv[1])))
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :Connect: Server %s %s %s.",
	  me.name, parv[0], parv[1], "already exists from", acptr->from->name);
    else
      sendto_one(sptr, "%s NOTICE %s%s :Connect: Server %s %s %s.",
	  NumServ(&me), NumNick(sptr), parv[1], "already exists from",
	  acptr->from->name);
    return 0;
  }

  for (aconf = conf; aconf; aconf = aconf->next)
    if (aconf->status == CONF_CONNECT_SERVER &&
	match(parv[1], aconf->name) == 0)
      break;
  /* Checked first servernames, then try hostnames. */
  if (!aconf)
    for (aconf = conf; aconf; aconf = aconf->next)
      if (aconf->status == CONF_CONNECT_SERVER &&
	  (match(parv[1], aconf->host) == 0 ||
	  match(parv[1], strchr(aconf->host, '@') + 1) == 0))
	break;

  if (!aconf)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr,
	  ":%s NOTICE %s :Connect: Host %s not listed in ircd.conf",
	  me.name, parv[0], parv[1]);
    else
      sendto_one(sptr,
	  "%s NOTICE %s%s :Connect: Host %s not listed in ircd.conf",
	  NumServ(&me), NumNick(sptr), parv[1]);
    return 0;
  }
  /*
   *  Get port number from user, if given. If not specified,
   *  use the default from configuration structure. If missing
   *  from there, then use the precompiled default.
   */
  tmpport = port = aconf->port;
  if (parc > 2 && !BadPtr(parv[2]))
  {
    if ((port = atoi(parv[2])) == 0)
    {
      if (MyUser(sptr) || Protocol(cptr) < 10)
	sendto_one(sptr,
	    ":%s NOTICE %s :Connect: Invalid port number", me.name, parv[0]);
      else
	sendto_one(sptr, "%s NOTICE %s%s :Connect: Invalid port number",
	    NumServ(&me), NumNick(sptr));
      return 0;
    }
  }
  else if (port == 0 && (port = PORTNUM) == 0)
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :Connect: missing port number",
	  me.name, parv[0]);
    else
      sendto_one(sptr, "%s NOTICE %s%s :Connect: missing port number",
	  NumServ(&me), NumNick(sptr));
    return 0;
  }

  /*
   * Evaluate connection rules...  If no rules found, allow the
   * connect.   Otherwise stop with the first true rule (ie: rules
   * are ored together.  Oper connects are effected only by D
   * lines (CRULEALL) not d lines (CRULEAUTO).
   */
  for (cconf = conf; cconf; cconf = cconf->next)
    if ((cconf->status == CONF_CRULEALL) &&
	(match(cconf->host, aconf->name) == 0))
      if (crule_eval(cconf->passwd))
      {
	if (MyUser(sptr) || Protocol(cptr) < 10)
	  sendto_one(sptr, ":%s NOTICE %s :Connect: Disallowed by rule: %s",
	      me.name, parv[0], cconf->name);
	else
	  sendto_one(sptr, "%s NOTICE %s%s :Connect: Disallowed by rule: %s",
	      NumServ(&me), NumNick(sptr), cconf->name);
	return 0;
      }

  /*
   * Notify all operators about remote connect requests
   */
  if (!IsAnOper(cptr))
  {
    sendto_ops_butone(NULL, &me, ":%s WALLOPS :Remote CONNECT %s %s from %s",
	me.name, parv[1], parv[2] ? parv[2] : "", get_client_name(sptr, FALSE));
#if defined(USE_SYSLOG) && defined(SYSLOG_CONNECT)
    syslog(LOG_DEBUG,
	"CONNECT From %s : %s %d", parv[0], parv[1], parv[2] ? parv[2] : "");
#endif
  }
  aconf->port = port;
  switch (retval = connect_server(aconf, sptr, NULL))
  {
    case 0:
      if (MyUser(sptr) || Protocol(cptr) < 10)
	sendto_one(sptr,
	    ":%s NOTICE %s :*** Connecting to %s[%s].",
	    me.name, parv[0], aconf->host, aconf->name);
      else
	sendto_one(sptr,
	    "%s NOTICE %s%s :*** Connecting to %s[%s].",
	    NumServ(&me), NumNick(sptr), aconf->host, aconf->name);
      break;
    case -1:
      /* Comments already sent */
      break;
    case -2:
      if (MyUser(sptr) || Protocol(cptr) < 10)
	sendto_one(sptr, ":%s NOTICE %s :*** Host %s is unknown.",
	    me.name, parv[0], aconf->host);
      else
	sendto_one(sptr, "%s NOTICE %s%s :*** Host %s is unknown.",
	    NumServ(&me), NumNick(sptr), aconf->host);
      break;
    default:
      if (MyUser(sptr) || Protocol(cptr) < 10)
	sendto_one(sptr,
	    ":%s NOTICE %s :*** Connection to %s failed: %s",
	    me.name, parv[0], aconf->host, strerror(retval));
      else
	sendto_one(sptr,
	    "%s NOTICE %s%s :*** Connection to %s failed: %s",
	    NumServ(&me), NumNick(sptr), aconf->host, strerror(retval));
  }
  aconf->port = tmpport;
  return 0;
}

/*
 * m_wallops
 *
 * Writes to all +w users currently online
 *
 * parv[0] = sender prefix
 * parv[1] = message text
 */
int m_wallops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  char *message;

  message = parc > 1 ? parv[1] : NULL;

  if (BadPtr(message))
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "WALLOPS");
    return 0;
  }

  if (!IsServer(sptr) && MyConnect(sptr) && !IsAnOper(sptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }
  sendto_ops_butone(IsServer(cptr) ? cptr : NULL, sptr,
      ":%s WALLOPS :%s", parv[0], message);
  return 0;
}

/*
 * m_time
 *
 * parv[0] = sender prefix
 * parv[1] = servername
 */
int m_time(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  if (hunt_server(0, cptr, sptr, ":%s TIME :%s", 1, parc, parv) == HUNTED_ISME)
    sendto_one(sptr, rpl_str(RPL_TIME), me.name,
	parv[0], me.name, TStime(), TSoffset, date((long)0));
  return 0;
}

/*
 * m_settime
 *
 * parv[0] = sender prefix
 * parv[1] = new time
 * parv[2] = servername (Only used when sptr is an Oper).
 */
int m_settime(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  time_t t;
  long int dt;
  static char tbuf[11];
  Dlink *lp;

  if (!IsPrivileged(sptr))
    return 0;

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "SETTIME");
    return 0;
  }

  if (parc == 2 && MyUser(sptr))
    parv[parc++] = me.name;

  t = atoi(parv[1]);
  dt = TStime() - t;

  if (t < 779557906 || dt < -9000000)
  {
    sendto_one(sptr, ":%s NOTICE %s :SETTIME: Bad value", me.name, parv[0]);
    return 0;
  }

  if (IsServer(sptr))		/* send to unlagged servers */
  {
#ifdef RELIABLE_CLOCK
    sprintf_irc(tbuf, TIME_T_FMT, TStime());
    parv[1] = tbuf;
#endif
    for (lp = me.serv->down; lp; lp = lp->next)
      if (cptr != lp->value.cptr && DBufLength(&lp->value.cptr->sendQ) < 8000)
	sendto_one(lp->value.cptr, ":%s SETTIME %s", parv[0], parv[1]);
  }
  else
  {
    sprintf_irc(tbuf, TIME_T_FMT, TStime());
    parv[1] = tbuf;
    if (hunt_server(1, cptr, sptr, ":%s SETTIME %s %s", 2, parc, parv) !=
	HUNTED_ISME)
      return 0;
  }

#ifdef RELIABLE_CLOCK
  if ((dt > 600) || (dt < -600))
    sendto_serv_butone((aClient *)NULL,
	":%s WALLOPS :Bad SETTIME from %s: " TIME_T_FMT, me.name, sptr->name,
	t);
  if (IsUser(sptr))
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :clock is not set %ld seconds %s : "
	  "RELIABLE_CLOCK is defined", me.name, parv[0],
	  (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
    else
      sendto_one(sptr, "%s NOTICE %s%s :clock is not set %ld seconds %s : "
	  "RELIABLE_CLOCK is defined", NumServ(&me), NumNick(sptr),
	  (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
  }
#else
  sendto_ops("SETTIME from %s, clock is set %ld seconds %s",
      get_client_name(sptr, FALSE), (dt < 0) ? -dt : dt,
      (dt < 0) ? "forwards" : "backwards");
  TSoffset -= dt;
  if (IsUser(sptr))
  {
    if (MyUser(sptr) || Protocol(cptr) < 10)
      sendto_one(sptr, ":%s NOTICE %s :clock is set %ld seconds %s", me.name,
	  parv[0], (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
    else
      sendto_one(sptr, "%s NOTICE %s%s :clock is set %ld seconds %s",
	  NumServ(&me), NumNick(sptr),
	  (dt < 0) ? -dt : dt, (dt < 0) ? "forwards" : "backwards");
  }
#endif
  return 0;
}

static char *militime(char *sec, char *usec)
{
  struct timeval tv;
  static char timebuf[18];

  gettimeofday(&tv, NULL);
  if (sec && usec)
#if defined(__sun__) || defined(__bsdi__) || (__GLIBC__ >= 2) || defined(__NetBSD__)
    sprintf(timebuf, "%ld",
	(tv.tv_sec - atoi(sec)) * 1000 + (tv.tv_usec - atoi(usec)) / 1000);
#else
    sprintf_irc(timebuf, "%d",
	(tv.tv_sec - atoi(sec)) * 1000 + (tv.tv_usec - atoi(usec)) / 1000);
#endif
  else
#if defined(__sun__) || defined(__bsdi__) || (__GLIBC__ >= 2) || defined(__NetBSD__)
    sprintf(timebuf, "%ld %ld", tv.tv_sec, tv.tv_usec);
#else
    sprintf_irc(timebuf, "%d %d", tv.tv_sec, tv.tv_usec);
#endif
  return timebuf;
}

/*
 * m_rping  -- by Run
 *
 *    parv[0] = sender (sptr->name thus)
 * if sender is a person: (traveling towards start server)
 *    parv[1] = pinged server[mask]
 *    parv[2] = start server (current target)
 *    parv[3] = optional remark
 * if sender is a server: (traveling towards pinged server)
 *    parv[1] = pinged server (current target)
 *    parv[2] = original sender (person)
 *    parv[3] = start time in s
 *    parv[4] = start time in us
 *    parv[5] = the optional remark
 */
int m_rping(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  aClient *acptr;

  if (!IsPrivileged(sptr))
    return 0;

  if (parc < (IsAnOper(sptr) ? (MyConnect(sptr) ? 2 : 3) : 6))
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "RPING");
    return 0;
  }
  if (MyUser(sptr))
  {
    if (parc == 2)
      parv[parc++] = me.name;
    else if (!(acptr = find_match_server(parv[2])))
    {
      parv[3] = parv[2];
      parv[2] = me.name;
      parc++;
    }
    else
      parv[2] = acptr->name;
    if (parc == 3)
      parv[parc++] = "<No client start time>";
  }

  if (IsAnOper(sptr))
  {
    if (hunt_server(1, cptr, sptr, ":%s RPING %s %s :%s", 2, parc, parv) !=
	HUNTED_ISME)
      return 0;
    if (!(acptr = find_match_server(parv[1])) || !IsServer(acptr))
    {
      sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], parv[1]);
      return 0;
    }
    if (Protocol(acptr->from) < 10)
      sendto_one(acptr, ":%s RPING %s %s %s :%s",
	  me.name, acptr->name, sptr->name, militime(NULL, NULL), parv[3]);
    else
      sendto_one(acptr, ":%s RPING %s %s %s :%s",
	  me.name, NumServ(acptr), sptr->name, militime(NULL, NULL), parv[3]);
  }
  else
  {
    if (hunt_server(1, cptr, sptr, ":%s RPING %s %s %s %s :%s", 1, parc, parv)
	!= HUNTED_ISME)
      return 0;
    sendto_one(cptr, ":%s RPONG %s %s %s %s :%s", me.name, parv[0],
	parv[2], parv[3], parv[4], parv[5]);
  }
  return 0;
}

/*
 * m_rpong  -- by Run too :)
 *
 * parv[0] = sender prefix
 * parv[1] = from pinged server: start server; from start server: sender
 * parv[2] = from pinged server: sender; from start server: pinged server
 * parv[3] = pingtime in ms
 * parv[4] = client info (for instance start time)
 */
int m_rpong(aClient *UNUSED(cptr), aClient *sptr, int parc, char *parv[])
{
  aClient *acptr;

  if (!IsServer(sptr))
    return 0;

  if (parc < 5)
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "RPING");
    return 0;
  }

  if (!(acptr = FindClient(parv[1])))
    return 0;

  if (!IsMe(acptr))
  {
    if (IsServer(acptr) && parc > 5)
    {
      sendto_one(acptr, ":%s RPONG %s %s %s %s :%s",
	  parv[0], parv[1], parv[2], parv[3], parv[4], parv[5]);
      return 0;
    }
  }
  else
  {
    parv[1] = parv[2];
    parv[2] = sptr->name;
    parv[0] = me.name;
    parv[3] = militime(parv[3], parv[4]);
    parv[4] = parv[5];
    if (!(acptr = FindUser(parv[1])))
      return 0;			/* No bouncing between servers ! */
  }

  sendto_one(acptr, ":%s RPONG %s %s %s :%s",
      parv[0], parv[1], parv[2], parv[3], parv[4]);
  return 0;
}

#if defined(OPER_REHASH) || defined(LOCOP_REHASH)
/*
 * m_rehash
 */
int m_rehash(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
#ifndef LOCOP_REHASH
  if (!MyUser(sptr) || !IsOper(sptr))
#else
#ifdef	OPER_REHASH
  if (!MyUser(sptr) || !IsAnOper(sptr))
#else
  if (!MyUser(sptr) || !IsLocOp(sptr))
#endif
#endif
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }
  sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0], configfile);
  sendto_ops("%s is rehashing Server config file", parv[0]);
#ifdef USE_SYSLOG
  syslog(LOG_INFO, "REHASH From %s\n", get_client_name(sptr, FALSE));
#endif
  return rehash(cptr, (parc > 1) ? ((*parv[1] == 'q') ? 2 : 0) : 0);
}
#endif

#if defined(OPER_RESTART) || defined(LOCOP_RESTART)
/*
 * m_restart
 */
int m_restart(aClient *UNUSED(cptr), aClient *sptr, int UNUSED(parc),
    char *parv[])
{
#ifndef LOCOP_RESTART
  if (!MyUser(sptr) || !IsOper(sptr))
#else
#ifdef	OPER_RESTART
  if (!MyUser(sptr) || !IsAnOper(sptr))
#else
  if (!MyUser(sptr) || !IsLocOp(sptr))
#endif
#endif
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }
#ifdef USE_SYSLOG
  syslog(LOG_WARNING, "Server RESTART by %s\n", get_client_name(sptr, FALSE));
#endif
  server_reboot();
  return 0;
}
#endif

/*
 * m_trace
 *
 * parv[0] = sender prefix
 * parv[1] = nick or servername
 * parv[2] = 'target' servername
 */
int m_trace(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 int i;
  Reg2 aClient *acptr;
  aConfClass *cltmp;
  char *tname;
  int doall, link_s[MAXCONNECTIONS], link_u[MAXCONNECTIONS];
  int cnt = 0, wilds, dow;

  if (parc < 2 || BadPtr(parv[1]))
  {
    /* just "TRACE" without parameters. Must be from local client */
    parc = 1;
    acptr = &me;
    tname = me.name;
    i = HUNTED_ISME;
  }
  else if (parc < 3 || BadPtr(parv[2]))
  {
    /* No target specified. Make one before propagating. */
    parc = 2;
    tname = parv[1];
    if ((acptr = find_match_server(parv[1])) ||
	((acptr = FindClient(parv[1])) && !MyUser(acptr)))
    {
      if (IsUser(acptr))
	parv[2] = acptr->user->server->name;
      else
	parv[2] = acptr->name;
      parc = 3;
      parv[3] = NULL;
      if ((i = hunt_server(IsServer(acptr), cptr, sptr,
	  ":%s TRACE %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
	return 0;
    }
    else
      i = HUNTED_ISME;
  }
  else
  {
    /* Got "TRACE <tname> :<target>" */
    parc = 3;
    if (MyUser(sptr) || Protocol(cptr) < 10)
      acptr = find_match_server(parv[2]);
    else
      acptr = FindNServer(parv[2]);
    if ((i = hunt_server(0, cptr, sptr,
	":%s TRACE %s :%s", 2, parc, parv)) == HUNTED_NOSUCH)
      return 0;
    tname = parv[1];
  }

  if (i == HUNTED_PASS)
  {
    if (!acptr)
      acptr = next_client(client, tname);
    else
      acptr = acptr->from;
    sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
#ifndef GODMODE
	version, debugmode, tname, acptr ? acptr->from->name : "<No_match>");
#else /* GODMODE */
	version, debugmode, tname, acptr ? acptr->from->name : "<No_match>",
	(acptr && acptr->from->serv) ? acptr->from->serv->timestamp : 0);
#endif /* GODMODE */
    return 0;
  }

  doall = (parv[1] && (parc > 1)) ? !match(tname, me.name) : TRUE;
  wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
  dow = wilds || doall;

  /* Don't give (long) remote listings to lusers */
  if (dow && !MyConnect(sptr) && !IsAnOper(sptr))
    return 0;

  for (i = 0; i < MAXCONNECTIONS; i++)
    link_s[i] = 0, link_u[i] = 0;

  if (doall)
  {
    for (acptr = client; acptr; acptr = acptr->next)
      if (IsUser(acptr))
	link_u[acptr->from->fd]++;
      else if (IsServer(acptr))
	link_s[acptr->from->fd]++;
  }

  /* report all direct connections */

  for (i = 0; i <= highest_fd; i++)
  {
    char *name;
    unsigned int conClass;

    if (!(acptr = loc_clients[i]))	/* Local Connection? */
      continue;
    if (IsInvisible(acptr) && dow && !(MyConnect(sptr) && IsOper(sptr)) &&
	!IsAnOper(acptr) && (acptr != sptr))
      continue;
    if (!doall && wilds && match(tname, acptr->name))
      continue;
    if (!dow && strCasediff(tname, acptr->name))
      continue;
    name = get_client_name(acptr, FALSE);
    conClass = get_client_class(acptr);

    switch (acptr->status)
    {
      case STAT_CONNECTING:
	sendto_one(sptr, rpl_str(RPL_TRACECONNECTING),
	    me.name, parv[0], conClass, name);
	cnt++;
	break;
      case STAT_HANDSHAKE:
	sendto_one(sptr, rpl_str(RPL_TRACEHANDSHAKE),
	    me.name, parv[0], conClass, name);
	cnt++;
	break;
      case STAT_ME:
	break;
      case STAT_UNKNOWN:
      case STAT_UNKNOWN_USER:
      case STAT_UNKNOWN_SERVER:
	sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
	    me.name, parv[0], conClass, name);
	cnt++;
	break;
      case STAT_USER:
	/* Only opers see users if there is a wildcard
	   but anyone can see all the opers. */
	if ((IsAnOper(sptr) && (MyUser(sptr) ||
	    !(dow && IsInvisible(acptr)))) || !dow || IsAnOper(acptr))
	{
	  if (IsAnOper(acptr))
	    sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
		me.name, parv[0], conClass, name, now - acptr->lasttime);
	  else
	    sendto_one(sptr, rpl_str(RPL_TRACEUSER),
		me.name, parv[0], conClass, name, now - acptr->lasttime);
	  cnt++;
	}
	break;
	/*
	 * Connection is a server
	 *
	 * Serv <class> <nS> <nC> <name> <ConnBy> <last> <age>
	 *
	 * class        Class the server is in
	 * nS           Number of servers reached via this link
	 * nC           Number of clients reached via this link
	 * name         Name of the server linked
	 * ConnBy       Who established this link
	 * last         Seconds since we got something from this link
	 * age          Seconds this link has been alive
	 *
	 * Additional comments etc......        -Cym-<cym@acrux.net>
	 */

      case STAT_SERVER:
	if (acptr->serv->user)
	  sendto_one(sptr, rpl_str(RPL_TRACESERVER),
	      me.name, parv[0], conClass, link_s[i],
	      link_u[i], name, acptr->serv->by,
	      acptr->serv->user->username,
	      acptr->serv->user->host,
	      now - acptr->lasttime, now - acptr->serv->timestamp);
	else
	  sendto_one(sptr, rpl_str(RPL_TRACESERVER),
	      me.name, parv[0], conClass, link_s[i],
	      link_u[i], name, *(acptr->serv->by) ?
	      acptr->serv->by : "*", "*", me.name,
	      now - acptr->lasttime, now - acptr->serv->timestamp);
	cnt++;
	break;
      case STAT_LOG:
	sendto_one(sptr, rpl_str(RPL_TRACELOG),
	    me.name, parv[0], LOGFILE, acptr->port);
	cnt++;
	break;
      case STAT_PING:
	sendto_one(sptr, rpl_str(RPL_TRACEPING), me.name,
	    parv[0], name, (acptr->acpt) ? acptr->acpt->name : "<null>");
	break;
      default:			/* We actually shouldn't come here, -msa */
	sendto_one(sptr, rpl_str(RPL_TRACENEWTYPE), me.name, parv[0], name);
	cnt++;
	break;
    }
  }
  /*
   * Add these lines to summarize the above which can get rather long
   * and messy when done remotely - Avalon
   */
  if (!IsAnOper(sptr) || !cnt)
  {
    if (!cnt)
      /* let the user have some idea that its at the end of the trace */
      sendto_one(sptr, rpl_str(RPL_TRACESERVER),
	  me.name, parv[0], 0, link_s[me.fd],
	  link_u[me.fd], "<No_match>", *(me.serv->by) ?
	  me.serv->by : "*", "*", me.name, 0, 0);
    return 0;
  }
  for (cltmp = FirstClass(); doall && cltmp; cltmp = NextClass(cltmp))
    if (Links(cltmp) > 0)
      sendto_one(sptr, rpl_str(RPL_TRACECLASS), me.name,
	  parv[0], ConClass(cltmp), Links(cltmp));
  return 0;
}

/*
 *  m_close                              - added by Darren Reed Jul 13 1992.
 */
int m_close(aClient *cptr, aClient *sptr, int UNUSED(parc), char *parv[])
{
  Reg1 aClient *acptr;
  Reg2 int i;
  int closed = 0;

  if (!MyOper(sptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }

  for (i = highest_fd; i; i--)
  {
    if (!(acptr = loc_clients[i]))
      continue;
    if (!IsUnknown(acptr) && !IsConnecting(acptr) && !IsHandshake(acptr))
      continue;
    sendto_one(sptr, rpl_str(RPL_CLOSING), me.name, parv[0],
	get_client_name(acptr, TRUE), acptr->status);
    exit_client(cptr, acptr, &me, "Oper Closing");
    closed++;
  }
  sendto_one(sptr, rpl_str(RPL_CLOSEEND), me.name, parv[0], closed);
  return 0;
}

#if defined(OPER_DIE) || defined(LOCOP_DIE)
/*
 * m_die
 */
int m_die(aClient *UNUSED(cptr), aClient *sptr, int UNUSED(parc), char *parv[])
{
  Reg1 aClient *acptr;
  Reg2 int i;

#ifndef LOCOP_DIE
  if (!MyUser(sptr) || !IsOper(sptr))
#else
#ifdef	OPER_DIE
  if (!MyUser(sptr) || !IsAnOper(sptr))
#else
  if (!MyUser(sptr) || !IsLocOp(sptr))
#endif
#endif
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
  }

  for (i = 0; i <= highest_fd; i++)
  {
    if (!(acptr = loc_clients[i]))
      continue;
    if (IsUser(acptr))
      sendto_one(acptr, ":%s NOTICE %s :Server Terminating. %s",
	  me.name, acptr->name, get_client_name(sptr, TRUE));
    else if (IsServer(acptr))
      sendto_one(acptr, ":%s ERROR :Terminated by %s",
	  me.name, get_client_name(sptr, TRUE));
  }
#ifdef __cplusplus
  s_die(0);
#else
  s_die();
#endif
  return 0;
}
#endif

static void add_gline(aClient *sptr, int ip_mask, char *host, char *comment,
    char *user, time_t expire, int local)
{
  aClient *acptr;
  aGline *agline;
  int fd,gtype=0;

#ifdef WT_BADCHAN
  if(*host=='#')
    gtype=1;	/* BAD CHANNEL */
#endif
  /* Inform ops */
  sendto_op_mask(SNO_GLINE,
      "%s adding %s%s for %s@%s, expiring at " TIME_T_FMT ": %s", sptr->name,
      local ? "local " : "",
      gtype ? "BADCHAN":"GLINE", user, host, expire, comment);

#ifdef GPATH
  write_log(GPATH,
      "# " TIME_T_FMT " %s adding %s %s for %s@%s, expiring at " TIME_T_FMT
      ": %s\n", TStime(), sptr->name, local ? "local" : "global",
      gtype ? "BADCHAN" : "GLINE", user, host, expire, comment);

  /* this can be inserted into the conf */
  if(!gtype)
    write_log(GPATH, "%c:%s:%s:%s\n", ip_mask ? 'k' : 'K', host, comment, 
      user);
#endif /* GPATH */

  agline = make_gline(ip_mask, host, comment, user, expire);
  if (local)
    SetGlineIsLocal(agline);

#ifdef WT_BADCHAN
  if(gtype) return;
#endif

  for (fd = highest_fd; fd >= 0; --fd)	/* get the users! */
    if ((acptr = loc_clients[fd]) && !IsMe(acptr))
    {

      if (!acptr->user || strlen(acptr->sockhost) > (size_t)HOSTLEN ||
	  (acptr->user->username ? strlen(acptr->user->username) : 0) >
	  (size_t)HOSTLEN)
	continue;		/* these tests right out of
				   find_kill for safety's sake */

      if ((GlineIsIpMask(agline) ?
	  match(agline->host, inetntoa(acptr->ip)) :
	  match(agline->host, acptr->sockhost)) == 0 &&
	  (!acptr->user->username ||
	  match(agline->name, acptr->user->username) == 0))
      {

	/* ok, he was the one that got G-lined */
	sendto_one(acptr, ":%s %d %s :*** %s.", me.name,
	    ERR_YOUREBANNEDCREEP, acptr->name, agline->reason);

	/* let the ops know about my first kill */
	sendto_op_mask(SNO_GLINE, "G-line active for %s",
	    get_client_name(acptr, FALSE));

	/* and get rid of him */
	if (sptr != acptr)
	  exit_client(sptr->from, acptr, &me, "G-lined");
      }
    }
}

/*
 * m_gline
 *
 * parv[0] = Send prefix
 *
 * From server:
 *
 * parv[1] = Target: server numeric
 * parv[2] = [+|-]<G-line mask>
 * parv[3] = Expiration offset
 * parv[4] = Comment
 *
 * From client:
 *
 * parv[1] = [+|-]<G-line mask>
 * parv[2] = Expiration offset
 * parv[3] = Comment
 *
 */
int m_gline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  aClient *acptr = NULL;	/* Init. to avoid compiler warning. */

  aGline *agline, *a2gline;
  char *user, *host;
  int active, ip_mask,gtype = 0;
  time_t expire = 0;

  /* Remove expired G-lines */
  for (agline = gline, a2gline = NULL; agline; agline = agline->next)
  {
    if (agline->expire <= TStime())
    {
      free_gline(agline, a2gline);
      agline = a2gline ? a2gline : gline;
      if (!agline)
	break;
      continue;
    }
    a2gline = agline;
  }

#ifdef WT_BADCHAN
  /* Remove expired bad channels */
  for (agline = badchan, a2gline = NULL; agline; agline = agline->next)
  {
    if (agline->expire <= TStime())
    {
      free_gline(agline, a2gline);
      agline = a2gline ? a2gline : badchan;
      if (!agline)
        break;
      continue;
    }
    a2gline = agline;
  }
#endif


  if (IsServer(cptr))
  {
    if (find_conf_host(cptr->confs, sptr->name, CONF_UWORLD))
    {
      if (parc < 3 || (*parv[2] != '-' && (parc < 5 || *parv[4] == '\0')))
      {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
	    "GLINE");
	return 0;
      }

      if (*parv[2] == '-')	/* add mode or delete mode? */
	active = 0;
      else
	active = 1;

      if (*parv[2] == '+' || *parv[2] == '-')
	parv[2]++;		/* step past mode indicator */

      /* forward the message appropriately */
      if (!strCasediff(parv[1], "*"))	/* global! */
	sendto_serv_butone(cptr, active ? ":%s GLINE %s +%s %s :%s" :
	    ":%s GLINE %s -%s", parv[0], parv[1], parv[2], parv[3], parv[4]);
      else if ((
#if 1
	  /*
	   * REMOVE THIS after all servers upgraded to 2.10.01 and
	   * Uworld uses a numeric too
	   */
	  (strlen(parv[1]) != 1 && !(acptr = FindClient(parv[1])))) ||
	  (strlen(parv[1]) == 1 &&
#endif
	  !(acptr = FindNServer(parv[1]))))
	return 0;		/* no such server/user exists; forget it */
      else
#if 1
/*
 * REMOVE THIS after all servers upgraded to 2.10.01 and
 * Uworld uses a numeric too
 */
      if (IsServer(acptr) || !MyConnect(acptr))
#endif
      {
	sendto_one(acptr, active ? ":%s GLINE %s +%s %s :%s" :
	    ":%s GLINE %s -%s", parv[0], parv[1], parv[2], parv[3], parv[4]);	/* single destination */
	return 0;		/* only the intended  destination
				   should add this gline */
      }

      if (!(host = strchr(parv[2], '@')))
      {				/* convert user@host */
	user = "*";		/* no @'s; assume username is '*' */
	host = parv[2];
      }
      else
      {
	user = parv[2];
	*(host++) = '\0';	/* break up string at the '@' */
      }
      ip_mask = check_if_ipmask(host);	/* Store this boolean */
#ifdef WT_BADCHAN
      if(*host == '#') gtype=1;		/* BAD CHANNEL GLINE */
#endif

      for (agline = (gtype)?badchan:gline, a2gline = NULL; agline; 
           agline = agline->next)
      {
	if (!strCasediff(agline->name, user)
	    && !strCasediff(agline->host, host))
	  break;
	a2gline = agline;
      }

      if (!active && agline)
      {				/* removing the gline */
	/* notify opers */
	sendto_op_mask(SNO_GLINE, "%s removing %s for %s@%s", parv[0],
	    gtype?"BADCHAN":"GLINE",agline->name, agline->host);

#ifdef GPATH
	write_log(GPATH, "# " TIME_T_FMT " %s removing %s for %s@%s\n",
	    TStime(), parv[0], gtype?"BADCHAN":"GLINE",agline->name, 
            agline->host);
#endif /* GPATH */

	free_gline(agline, a2gline);	/* remove the gline */
      }
      else if (active)
      {				/* must be adding a gline */
	expire = atoi(parv[3]) + TStime();	/* expire time? */
	if (agline && agline->expire < expire)
	{			/* new expire time? */
	  /* yes, notify the opers */
	  sendto_op_mask(SNO_GLINE,
	      "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
	      parv[0], gtype?"BADCHAN":"GLINE",agline->name, agline->host, 
              expire);

#ifdef GPATH
	  write_log(GPATH, "# " TIME_T_FMT " %s resetting expiration time "
	      "on %s for %s@%s to " TIME_T_FMT "\n",
	      TStime(), parv[0], gtype?"BADCHAN":"GLINE",
               agline->name, agline->host, expire);
#endif /* GPATH */

	  agline->expire = expire;	/* reset the expire time */
	}
	else if (!agline)
	{			/* create gline */
	  for (agline = gtype?badchan:gline; agline; agline = agline->next)
	    if (!mmatch(agline->name, user) &&
		(ip_mask ? GlineIsIpMask(agline) : !GlineIsIpMask(agline)) &&
		!mmatch(agline->host, host))
	      return 0;		/* found an existing G-line that matches */

	  /* add the line: */
	  add_gline(sptr, ip_mask, host, parv[4], user, expire, 0);
	}
      }
    }
  }
  else if (parc < 2 || *parv[1] == '\0')
  {
    /* Not enough args and a user; list glines */
    for (agline = gline; agline; agline = agline->next)
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0],
	  agline->name, agline->host, agline->expire, agline->reason,
	  GlineIsActive(agline) ? (GlineIsLocal(agline) ? " (local)" : "") :
	  " (Inactive)");
    sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
  }
  else
  {
    int priv;

#ifdef LOCOP_LGLINE
    priv = IsAnOper(cptr);
#else
    priv = IsOper(cptr);
#endif

    if (priv)
    {				/* non-oper not permitted to change things */
      if (*parv[1] == '-')
      {				/* oper wants to deactivate the gline */
	active = 0;
	parv[1]++;
      }
      else if (*parv[1] == '+')
      {				/* oper wants to activate inactive gline */
	active = 1;
	parv[1]++;
      }
      else
	active = -1;

      if (parc > 2)
	expire = atoi(parv[2]) + TStime();	/* oper wants to reset
						   expire TS */
    }
    else
      active = -1;

    if (!(host = strchr(parv[1], '@')))
    {
      user = "*";		/* no @'s; assume username is '*' */
      host = parv[1];
    }
    else
    {
      user = parv[1];
      *(host++) = '\0';		/* break up string at the '@' */
    }
    ip_mask = check_if_ipmask(host);	/* Store this boolean */
#ifdef WT_BADCHAN
    if(*host == '#')
#ifndef WT_LOCAL_BADCHAN
     return 0;
#else
     gtype=1;	/* BAD CHANNEL */
#endif
#endif

    for (agline = gtype?badchan:gline, a2gline = NULL; agline; 
      agline = agline->next)
    {
      if (!mmatch(agline->name, user) &&
	  (ip_mask ? GlineIsIpMask(agline) : !GlineIsIpMask(agline)) &&
	  !mmatch(agline->host, host))
	break;
      a2gline = agline;
    }

    if (!agline)
    {
#ifdef OPER_LGLINE
      if (priv && active && expire > now)
      {
	/* Add local G-line */
	if (parc < 4 || !strchr(parv[3], ' '))
	{
	  sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
	      me.name, parv[0], "GLINE");
	  return 0;
	}
	add_gline(sptr, ip_mask, host, parv[3], user, expire, 1);
      }
      else
#endif
	sendto_one(cptr, err_str(ERR_NOSUCHGLINE), me.name, parv[0], user,
	    host);

      return 0;
    }

    if (expire <= agline->expire)
      expire = 0;

    if ((active == -1 ||
	(active ? GlineIsActive(agline) : !GlineIsActive(agline))) &&
	expire == 0)
    {
      /* oper wants a list of one gline only */
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0], agline->name,
	  agline->host, agline->expire, agline->reason,
	  GlineIsActive(agline) ? "" : " (Inactive)");
      sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
      return 0;
    }

    if (active != -1 &&
	(active ? !GlineIsActive(agline) : GlineIsActive(agline)))
    {
      if (active)		/* reset activation on gline */
	SetActive(agline);
#ifdef OPER_LGLINE
      else if (GlineIsLocal(agline))
      {
	/* Remove local G-line */
	sendto_op_mask(SNO_GLINE, "%s removed local %s for %s@%s",
	    parv[0], gtype?"BADCHAN":"GLINE",agline->name, agline->host);
#ifdef GPATH
	write_log(GPATH, "# " TIME_T_FMT
	    " %s!%s@%s removed local %s for %s@%s\n",
	    TStime(), parv[0], cptr->user->username, cptr->user->host,
	    gtype?"BADCHAN":"GLINE",
	    agline->name, agline->host);
#endif /* GPATH */
	free_gline(agline, a2gline);	/* remove the gline */
	return 0;
      }
#endif
      else
	ClearActive(agline);
    }
    else
      active = -1;		/* for later sendto_ops and logging functions */

    if (expire)
      agline->expire = expire;	/* reset expiration time */

    /* inform the operators what's up */
    if (active != -1)
    {				/* changing the activation */
      sendto_op_mask(SNO_GLINE, !expire ? "%s %sactivating %s for %s@%s" :
	  "%s %sactivating %s for %s@%s and "
	  "resetting expiration time to " TIME_T_FMT,
	  parv[0], active ? "re" : "de", gtype?"BADCHAN":"GLINE",agline->name,
	  agline->host, agline->expire);
#ifdef GPATH
      write_log(GPATH, !expire ? "# " TIME_T_FMT " %s!%s@%s %sactivating "
	  "%s for %s@%s\n" : "# " TIME_T_FMT " %s!%s@%s %sactivating %s "
	  "for %s@%s and resetting expiration time to " TIME_T_FMT "\n",
	  TStime(), parv[0], cptr->user->username, cptr->user->host,
	  active ? "re" : "de", gtype?"BADCHAN":"GLINE",agline->name, 
          agline->host, agline->expire);
#endif /* GPATH */

    }
    else if (expire)
    {				/* changing only the expiration */
      sendto_op_mask(SNO_GLINE,
	  "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
	  parv[0], gtype?"BADCHAN":"GLINE",agline->name, agline->host, 
          agline->expire);
#ifdef GPATH
      write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s resetting expiration "
	  "time on %s for %s@%s to " TIME_T_FMT "\n", TStime(), parv[0],
	  cptr->user->username, cptr->user->host,gtype?"BADCHAN":"GLINE",
	  agline->name, agline->host, agline->expire);
#endif /* GPATH */
    }
  }

  return 0;
}
