/*
 * IRC - Internet Relay Chat, ircd/s_stats.c
 * Copyright (C) 2000 Joseph Bongaarts
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
#include "config.h"

#include "s_stats.h"
#include "class.h"
#include "client.h"
#include "gline.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "listener.h"
#include "list.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "userload.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


/*
 * m_stats/s_stats
 *
 * Report configuration lines and other statistics from this
 * server. 
 *
 * Note: The info is reported in the order the server uses
 *       it--not reversed as in ircd.conf!
 */

static unsigned int report_array[17][3] = {
  {CONF_SERVER, RPL_STATSCLINE, 'C'},
  {CONF_CLIENT, RPL_STATSILINE, 'I'},
  {CONF_LEAF, RPL_STATSLLINE, 'L'},
  {CONF_OPERATOR, RPL_STATSOLINE, 'O'},
  {CONF_HUB, RPL_STATSHLINE, 'H'},
  {CONF_LOCOP, RPL_STATSOLINE, 'o'},
  {CONF_UWORLD, RPL_STATSULINE, 'U'},
  {0, 0}
};

static void
stats_configured_links(struct Client* sptr, struct StatDesc* sd, int stat,
			char* param)
{
  static char null[] = "<NULL>";
  struct ConfItem *tmp;
  int mask;
  unsigned int *p;
  unsigned short int port;
  char c, *host, *pass, *name;

  mask = sd->sd_funcdata;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if ((tmp->status & mask)) {
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
      if ((tmp->status & CONF_UWORLD))
	send_reply(sptr, p[1], c, host, pass, name, port, get_conf_class(tmp));
      else if ((tmp->status & (CONF_SERVER | CONF_HUB)))
	send_reply(sptr, p[1], c, "*", name, port, get_conf_class(tmp));
      else
	send_reply(sptr, p[1], c, host, name, port, get_conf_class(tmp));
    }
  }
}

/*
 * {CONF_CRULEALL, RPL_STATSDLINE, 'D'},
 * {CONF_CRULEAUTO, RPL_STATSDLINE, 'd'},
 */
static void
stats_crule_list(struct Client* to, struct StatDesc* sd, int stat,
		  char* param)
{
  const struct CRuleConf* p = conf_get_crule_list();
  int mask;

  mask = (stat == 'D' ? CRULE_ALL : CRULE_MASK);

  for ( ; p; p = p->next) {
    if (0 != (p->type & mask))
      send_reply(to, RPL_STATSDLINE, stat, p->hostmask, p->rule);
  }
}

static void
stats_engine(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  send_reply(to, RPL_STATSENGINE, engine_name());
}

static void
stats_access(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  struct ConfItem *aconf;
  int wilds = 0;
  int count = 1000;

  if (!param) {
    stats_configured_links(to, sd, stat, param);
    return;
  }

  wilds = string_has_wildcards(param);

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (CONF_CLIENT == aconf->status) {
      if ((!wilds && (!match(aconf->host, param) ||
		      !match(aconf->name, param))) ||
	  (wilds && (!mmatch(param, aconf->host) ||
		     !mmatch(param, aconf->name)))) {
	send_reply(to, RPL_STATSILINE, 'I', aconf->host, aconf->name,
		   aconf->port, get_conf_class(aconf));
	if (--count == 0)
	  break;
      }
    }
  }
}

/*
 * {CONF_KILL, RPL_STATSKLINE, 'K'},
 * {CONF_IPKILL, RPL_STATSKLINE, 'k'},
 */
static void
report_deny_list(struct Client* to)
{
  const struct DenyConf* p = conf_get_deny_list();
  for ( ; p; p = p->next)
    send_reply(to, RPL_STATSKLINE, (p->flags & DENY_FLAGS_IP) ? 'k' : 'K',
               p->hostmask, p->message, p->usermask);
}

static void
stats_klines(struct Client* sptr, struct StatDesc* sd, int stat, char* mask)
{
  int   wilds = 0;
  int   count = 3;
  int   limit_query = 0;
  char* user  = 0;
  char* host;
  const struct DenyConf* conf;

  if (!IsAnOper(sptr))
    limit_query = 1;

  if (!mask) {
    if (limit_query)
      need_more_params(sptr, "STATS K");
    else
      report_deny_list(sptr);
    return;
  }

  if (!limit_query) {
    wilds = string_has_wildcards(mask);
    count = 1000;
  }

  if ((host = strchr(mask, '@'))) {
    user = mask;
    *host++ = '\0';
  } else {
    host = mask;
  }

  for (conf = conf_get_deny_list(); conf; conf = conf->next) {
    if ((!wilds && ((user || conf->hostmask) &&
		    !match(conf->hostmask, host) &&
		    (!user || !match(conf->usermask, user)))) ||
	(wilds && !mmatch(host, conf->hostmask) &&
	 (!user || !mmatch(user, conf->usermask)))) {
      send_reply(sptr, RPL_STATSKLINE,
		 (conf->flags & DENY_FLAGS_IP) ? 'k' : 'K',
                 conf->hostmask, conf->message, conf->usermask);
      if (--count == 0)
	return;
    }
  }
}

static void
stats_links(struct Client* sptr, struct StatDesc* sd, int stat, char* name)
{
  struct Client *acptr;
  int i;
  int wilds = 0;

  if (name)
    wilds = string_has_wildcards(name);

  /*
   * Send info about connections which match, or all if the
   * mask matches me.name.  Only restrictions are on those who
   * are invisible not being visible to 'foreigners' who use
   * a wild card based search to list it.
   */
  send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO, "Connection SendQ "
	     "SendM SendKBytes RcveM RcveKBytes :Open since");
  for (i = 0; i <= HighestFd; i++) {
    if (!(acptr = LocalClientArray[i]))
      continue;
    /* Don't return clients when this is a request for `all' */
    if (!name && IsUser(acptr))
      continue;
    /* Don't show invisible people to non opers unless they know the nick */
    if (IsInvisible(acptr) && (!name || wilds) && !IsAnOper(acptr) &&
	(acptr != sptr))
      continue;
    /* Only show the ones that match the given mask - if any */
    if (name && wilds && match(name, cli_name(acptr)))
      continue;
    /* Skip all that do not match the specific query */
    if (!(!name || wilds) && 0 != ircd_strcmp(name, cli_name(acptr)))
      continue;
    send_reply(sptr, SND_EXPLICIT | RPL_STATSLINKINFO,
	       "%s %u %u %u %u %u :%Tu",
	       (*(cli_name(acptr))) ? cli_name(acptr) : "<unregistered>",
	       (int)MsgQLength(&(cli_sendQ(acptr))), (int)cli_sendM(acptr),
	       (int)cli_sendK(acptr), (int)cli_receiveM(acptr),
	       (int)cli_receiveK(acptr), CurrentTime - cli_firsttime(acptr));
  }
}

static void
stats_commands(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  struct Message *mptr;

  for (mptr = msgtab; mptr->cmd; mptr++)
    if (mptr->count)
      send_reply(to, RPL_STATSCOMMANDS, mptr->cmd, mptr->count, mptr->bytes);
}

static void
stats_quarantine(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  struct qline *qline;

  for (qline = GlobalQuarantineList; qline; qline = qline->next) {
    if (param && match(param, qline->chname)) /* narrow search */
      continue;
    send_reply(to, RPL_STATSQLINE, qline->chname, qline->reason);
  }
}

static void
stats_uptime(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  time_t nowr;

  nowr = CurrentTime - cli_since(&me);
  send_reply(to, RPL_STATSUPTIME, nowr / 86400, (nowr / 3600) % 24,
	     (nowr / 60) % 60, nowr % 60);
  send_reply(to, RPL_STATSCONN, max_connection_count, max_client_count);
}

static void
stats_servers_verbose(struct Client* sptr, struct StatDesc* sd, int stat,
		      char* param)
{
  struct Client *acptr;

  /* lowercase 'v' is for human-readable,
   * uppercase 'V' is for machine-readable */
  if (stat == 'v')
    send_reply(sptr, SND_EXPLICIT | RPL_STATSVERBOSE,
	       "%-20s %-20s Flags Hops Numeric   Lag  RTT   Up Down "
	       "Clients/Max Proto %-10s :Info", "Servername", "Uplink",
	       "LinkTS");

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsServer(acptr) && !IsMe(acptr))
      continue;
    if (param && match(param, cli_name(acptr))) /* narrow search */
      continue;
    send_reply(sptr, SND_EXPLICIT | RPL_STATSVERBOSE, stat == 'v' ?
	       "%-20s %-20s %c%c%c%c  %4i %s %-4i %5i %4i %4i %4i %5i %5i "
	       "P%-2i   %Tu :%s" :
	       "%s %s %c%c%c%c %i %s %i %i %i %i %i %i %i P%i %Tu :%s",
	       cli_name(acptr),
	       cli_name(cli_serv(acptr)->up),
	       IsBurst(acptr) ? 'B' : '-',
	       IsBurstAck(acptr) ? 'A' : '-',
	       IsHub(acptr) ? 'H' : '-',
	       IsService(acptr) ? 'S' : '-',
	       cli_hopcount(acptr),
	       NumServ(acptr),
	       base64toint(cli_yxx(acptr)),
	       cli_serv(acptr)->lag,
	       cli_serv(acptr)->asll_rtt,
	       cli_serv(acptr)->asll_to,
	       cli_serv(acptr)->asll_from,
	       cli_serv(acptr)->clients,
	       cli_serv(acptr)->nn_mask,
	       cli_serv(acptr)->prot,
	       cli_serv(acptr)->timestamp,
	       cli_info(acptr));
  }
}

#ifdef DEBUGMODE
static void
stats_meminfo(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  class_send_meminfo(to);
  send_listinfo(to, 0);
}
#endif

static void
stats_help(struct Client* to, struct StatDesc* sd, int stat, char* param)
{
  struct StatDesc *asd;

  if (MyUser(to)) /* only if it's my user */
    for (asd = statsinfo; asd->sd_c; asd++)
      if (asd->sd_c != sd->sd_c) /* don't send the help for us */
	sendcmdto_one(&me, CMD_NOTICE, to, "%C :%c - %s", to, asd->sd_c,
		      asd->sd_desc);
}

/* This array of structures contains information about all single-character
 * stats.  Struct StatDesc is defined in s_stats.h.
 */
struct StatDesc statsinfo[] = {
  { 'c', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_c,
    stats_configured_links, CONF_SERVER,
    "Remote server connection lines." },
  { 'd', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_d,
    stats_crule_list, 0,
    "Dynamic routing configuration." },
  { 'e', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_e,
    stats_engine, 0,
    "Report server event loop engine." },
  { 'f', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_f,
    feature_report, 0,
    "Feature settings." },
  { 'g', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_g,
    gline_stats, 0,
    "Global bans (G-lines)." },
  { 'h', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_h,
    stats_configured_links, (CONF_HUB | CONF_LEAF),
    "Hubs information." },
  { 'i', (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_i,
    stats_access, CONF_CLIENT,
    "Connection authorization lines." },
  { 'j', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_j,
    msgq_histogram, 0,
    "Message length histogram." },
  { 'k', (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_k,
    stats_klines, 0,
    "Local bans (K-Lines)." },
  { 'l', (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_l,
    stats_links, 0,
    "Current connections information." },
#if 0
  { 'M', (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_M,
    stats_memtotal, 0,
    "Memory allocation & leak monitoring." },
#endif
  { 'm', (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_m,
    stats_commands, 0,
    "Message usage information." },
  { 'o', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_o,
    stats_configured_links, CONF_OPS,
    "Operator information." },
  { 'p', (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_p,
    show_ports, 0,
    "Listening ports." },
  { 'q', (STAT_FLAG_OPERONLY | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_q,
    stats_quarantine, 0,
    "Quarantined channels list." },
#ifdef DEBUGMODE
  { 'r', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_r,
    send_usage, 0,
    "System resource usage (Debug only)." },
#endif
  { 'T', (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_T,
    motd_report, 0,
    "Configured Message Of The Day files." },
  { 't', (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_t,
    tstats, 0,
    "Local connection statistics (Total SND/RCV, etc)." },
  { 'U', (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_U,
    stats_configured_links, CONF_UWORLD,
    "Service server & nick jupes information." },
  { 'u', (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_u,
    stats_uptime, 0,
    "Current uptime & highest connection count." },
  { 'v', (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_v,
    stats_servers_verbose, 0,
    "Verbose server information." },
  { 'w', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_w,
    calc_load, 0,
    "Userload statistics." },
#ifdef DEBUGMODE
  { 'x', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_x,
    stats_meminfo, 0,
    "List usage information (Debug only)." },
#endif
  { 'y', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_y,
    report_classes, 0,
    "Connection classes." },
  { 'z', STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_z,
    count_memory, 0,
    "Memory/Structure allocation information." },
  { '*', (STAT_FLAG_CASESENS | STAT_FLAG_VARPARAM), FEAT_LAST_F,
    stats_help, 0,
    "Send help for stats." },
  { '\0', 0, FEAT_LAST_F, 0, 0, 0 }
};

/* This array is for mapping from characters to statistics descriptors */
struct StatDesc *statsmap[256];

/* Function to build the statsmap from the statsinfo array */
void
stats_init(void)
{
  struct StatDesc *sd;
  int i;

  /* Make darn sure the statsmap array is initialized to all zeros */
  for (i = 0; i < 256; i++)
    statsmap[i] = 0;

  /* Build the mapping */
  for (sd = statsinfo; sd->sd_c; sd++) {
    if (sd->sd_flags & STAT_FLAG_CASESENS)
      /* case sensitive character... */
      statsmap[(int)sd->sd_c] = sd;
    else {
      /* case insensitive--make sure to put in two entries */
      statsmap[(int)ToLower((int)sd->sd_c)] = sd;
      statsmap[(int)ToUpper((int)sd->sd_c)] = sd;
    }
  }
}
