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
 */
#include "config.h"

#include "class.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_crypt.h"
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
#include "querycmds.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "userload.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/** @file
 * @brief Report configuration lines and other statistics from this
 * server.
 * @version $Id$
 *
 * Note: The info is reported in the order the server uses
 *       it--not reversed as in ircd.conf!
 */

/* The statsinfo array should only be used in this file, but just TRY
 * telling the compiler that you want to forward declare a static
 * array without specifying a length, and see how it responds.  So we
 * forward declare it "extern".
 */
extern struct StatDesc statsinfo[];

/** Report items from #GlobalConfList.
 * Uses sd->sd_funcdata as a filter for ConfItem::status.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request.
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_configured_links(struct Client *sptr, const struct StatDesc* sd,
                       char* param)
{
  static char null[] = "";
  struct ConfItem *tmp;
  unsigned short int port;
  int maximum;
  char *host, *name, *username, *hub_limit;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next)
  {
    if ((tmp->status & sd->sd_funcdata))
    {
      host = tmp->host ? tmp->host : null;
      name = tmp->name ? tmp->name : null;
      username = tmp->username ? tmp->username : null;
      hub_limit = tmp->hub_limit ? tmp->hub_limit : null;
      maximum = tmp->maximum;
      port = tmp->address.port;

      if (tmp->status & CONF_UWORLD)
      {
        const char *oper = (tmp->flags & CONF_UWORLD_OPER) ? "+" : "";
        send_reply(sptr, RPL_STATSULINE, oper, host);
      }
      else if (tmp->status & CONF_SERVER)
	send_reply(sptr, RPL_STATSCLINE, name, port, maximum, hub_limit, get_conf_class(tmp));
      else if (tmp->status & CONF_CLIENT)
        send_reply(sptr, RPL_STATSILINE,
                   (tmp->username ? tmp->username : ""), (tmp->username ? "@" : ""),
                   (tmp->host ? tmp->host : "*"), maximum,
                   (name[0] == ':' ? "0" : ""), (tmp->name ? tmp->name : "*"),
                   port, get_conf_class(tmp));
      else if (tmp->status & CONF_OPERATOR)
      {
        int global = FlagHas(&tmp->privs_dirty, PRIV_PROPAGATE)
            ? FlagHas(&tmp->privs, PRIV_PROPAGATE)
            : FlagHas(&tmp->conn_class->privs, PRIV_PROPAGATE);
        send_reply(sptr, RPL_STATSOLINE, global ? 'O' : 'o',
                   username, host, name, get_conf_class(tmp));
      }
    }
  }
}

/** Report connection rules from conf_get_crule_list().
 * Uses sd->sd_funcdata as a filter for CRuleConf::type.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request.
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_crule_list(struct Client* to, const struct StatDesc *sd,
                 char *param)
{
  const struct CRuleConf* p = conf_get_crule_list();

  for ( ; p; p = p->next)
  {
    if (p->type & sd->sd_funcdata)
      send_reply(to, RPL_STATSDLINE, (p->type & CRULE_ALL ? 'D' : 'd'), p->hostmask, p->rule);
  }
}

/** Report active event engine name.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_engine(struct Client *to, const struct StatDesc *sd, char *param)
{
  send_reply(to, RPL_STATSENGINE, engine_name());
}

/** Report client access lists.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request.
 * @param[in] param Filter for hostname or IP (NULL to show all).
 */
static void
stats_access(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct ConfItem *aconf;
  int wilds = 0;
  int count = 1000;

  if (!param)
  {
    stats_configured_links(to, sd, param);
    return;
  }

  wilds = string_has_wildcards(param);

  for (aconf = GlobalConfList; aconf; aconf = aconf->next)
  {
    if (aconf->status != CONF_CLIENT)
      continue;
    if (wilds ? ((aconf->host && !mmatch(aconf->host, param))
                 || (aconf->name && !mmatch(aconf->name, param)))
        : ((aconf->host && !match(param, aconf->host))
           || (aconf->name && !match(param, aconf->name))))
    {
      send_reply(to, RPL_STATSILINE,
                 (aconf->username ? aconf->username : ""), (aconf->username ? "@" : ""), 
                 (aconf->host ? aconf->host : "*"), aconf->maximum,
                 (aconf->name && aconf->name[0] == ':' ? "0":""),
                 aconf->name ? aconf->name : "*",
                 aconf->address.port, get_conf_class(aconf));
      if (--count == 0)
        break;
    }
  }
}


/** Report DenyConf entries.
 * @param[in] to Client requesting list.
 */
static void
report_deny_list(struct Client* to)
{
  const struct DenyConf* p = conf_get_deny_list();
  for ( ; p; p = p->next)
    send_reply(to, RPL_STATSKLINE, p->bits > 0 ? 'k' : 'K',
               p->usermask ? p->usermask : "*",
               p->hostmask ? p->hostmask : "*",
               p->message ? p->message : "(none)",
               p->realmask ? p->realmask : "*");
}

/** Report K/k-lines to a user.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] mask Filter for hostmasks to show.
 */
static void
stats_klines(struct Client *sptr, const struct StatDesc *sd, char *mask)
{
  int wilds = 0;
  int count = 3;
  int limit_query = 0;
  char *user  = 0;
  char *host;
  const struct DenyConf* conf;

  if (!IsAnOper(sptr))
    limit_query = 1;

  if (!mask)
  {
    if (limit_query)
      need_more_params(sptr, "STATS K");
    else
      report_deny_list(sptr);
    return;
  }

  if (!limit_query)
  {
    wilds = string_has_wildcards(mask);
    count = 1000;
  }
  if ((host = strchr(mask, '@')))
  {
    user = mask;
    *host++ = '\0';
  }
  else
    host = mask;

  for (conf = conf_get_deny_list(); conf; conf = conf->next)
  {
    /* Skip this block if the user is searching for a user-matching
     * mask but the current Kill doesn't have a usermask, or if user
     * is searching for a host-matching mask but the Kill has no
     * hostmask, or if the user mask is specified and doesn't match,
     * or if the host mask is specified and doesn't match.
     */
    if ((user && !conf->usermask)
        || (host && !conf->hostmask)
        || (user && conf->usermask
            && (wilds
                ? mmatch(user, conf->usermask)
                : match(conf->usermask, user)))
        || (host && conf->hostmask
            && (wilds
                ? mmatch(host, conf->hostmask)
                : match(conf->hostmask, host))))
      continue;
    send_reply(sptr, RPL_STATSKLINE, conf->bits > 0 ? 'k' : 'K',
               conf->usermask ? conf->usermask : "*",
               conf->hostmask ? conf->hostmask : "*",
               conf->message ? conf->message : "(none)",
               conf->realmask ? conf->realmask : "*");
    if (--count == 0)
      return;
  }
}

/** Report on servers and/or clients connected to the network.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] name Filter for client names to show.
 */
static void
stats_links(struct Client* sptr, const struct StatDesc* sd, char* name)
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
    for (i = 0; i <= HighestFd; i++)
    {
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
                 "%s %u %u %Lu %u %Lu :%Tu",
                 (*(cli_name(acptr))) ? cli_name(acptr) : "<unregistered>",
                 (int)MsgQLength(&(cli_sendQ(acptr))), (int)cli_sendM(acptr),
                 (cli_sendB(acptr) >> 10), (int)cli_receiveM(acptr),
                 (cli_receiveB(acptr) >> 10), CurrentTime - cli_firsttime(acptr));
    }
}

/** Report on loaded modules.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_modules(struct Client* to, const struct StatDesc* sd, char* param)
{
crypt_mechs_t* mechs;

  send_reply(to, SND_EXPLICIT | RPL_STATSLLINE, 
   "Module  Description      Entry Point");

 /* atm the only "modules" we have are the crypto mechanisms,
    eventualy they'll be part of a global dl module list, for now
    i'll just output data about them -- hikari */

 if(crypt_mechs_root == NULL)
  return;

 mechs = crypt_mechs_root->next;

 for(;;)
 {
  if(mechs == NULL)
   return;

  send_reply(to, SND_EXPLICIT | RPL_STATSLLINE, 
   "%s  %s     0x%X", 
   mechs->mech->shortname, mechs->mech->description, 
   mechs->mech->crypt_function);

  mechs = mechs->next;
 }

}

/** Report how many times each command has been used.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_commands(struct Client* to, const struct StatDesc* sd, char* param)
{
  struct Message *mptr;

  for (mptr = msgtab; mptr->cmd; mptr++)
    if (mptr->count)
      send_reply(to, RPL_STATSCOMMANDS, mptr->cmd, mptr->count, mptr->bytes);
}

/** List channel quarantines.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Filter for quarantined channel names.
 */
static void
stats_quarantine(struct Client* to, const struct StatDesc* sd, char* param)
{
  struct qline *qline;

  for (qline = GlobalQuarantineList; qline; qline = qline->next)
  {
    if (param && match(param, qline->chname)) /* narrow search */
      continue;
    send_reply(to, RPL_STATSQLINE, qline->chname, qline->reason);
  }
}

/** List service pseudo-command mappings.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_mapping(struct Client *to, const struct StatDesc* sd, char* param)
{
  struct s_map *map;

  send_reply(to, RPL_STATSRLINE, "Command", "Name", "Prepend", "Target");
  for (map = GlobalServiceMapList; map; map = map->next) {
    struct nick_host *nh;
    for (nh = map->services; nh; nh = nh->next) {
      send_reply(to, RPL_STATSRLINE, map->command, map->name,
                 (map->prepend ? map->prepend : "*"), nh->nick);
    }
  }
}

/** Report server uptime and maximum connection/client counts.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_uptime(struct Client* to, const struct StatDesc* sd, char* param)
{
  time_t nowr;

  nowr = CurrentTime - cli_since(&me);
  send_reply(to, RPL_STATSUPTIME, nowr / 86400, (nowr / 3600) % 24,
             (nowr / 60) % 60, nowr % 60);
  send_reply(to, RPL_STATSCONN, max_connection_count, max_client_count);
}

/** Verbosely report on servers connected to the network.
 * If sd->sd_funcdata != 0, then display in a more human-friendly format.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request.
 * @param[in] param Filter for server names to display.
 */
static void
stats_servers_verbose(struct Client* sptr, const struct StatDesc* sd,
		      char* param)
{
  struct Client *acptr;
  const char *fmt;

  /*
   * lowercase 'v' is for human-readable,
   * uppercase 'V' is for machine-readable
   */
  if (sd->sd_funcdata) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSVERBOSE,
               "%-20s %-20s Flags Hops Numeric   Lag  RTT   Up Down "
               "Clients/Max Proto %-10s :Info", "Servername", "Uplink",
               "LinkTS");
    fmt = "%-20s %-20s %c%c%c%c%c  %4i %s %-4i %5i %4i %4i %4i %5i %5i P%-2i   %Tu :%s";
  } else {
    fmt = "%s %s %c%c%c%c%c %i %s %i %i %i %i %i %i %i P%i %Tu :%s";
  }

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    if (!IsServer(acptr) && !IsMe(acptr))
      continue;
    /* narrow search */
    if (param && match(param, cli_name(acptr)))
      continue;
    send_reply(sptr, SND_EXPLICIT | RPL_STATSVERBOSE, fmt,
               cli_name(acptr),
               cli_name(cli_serv(acptr)->up),
               IsBurst(acptr) ? 'B' : '-',
               IsBurstAck(acptr) ? 'A' : '-',
               IsHub(acptr) ? 'H' : '-',
               IsService(acptr) ? 'S' : '-',
               IsIPv6(acptr) ? '6' : '-',
               cli_hopcount(acptr),
               NumServ(acptr),
               base64toint(cli_yxx(acptr)),
               cli_serv(acptr)->lag,
               cli_serv(acptr)->asll_rtt,
               cli_serv(acptr)->asll_to,
               cli_serv(acptr)->asll_from,
               (acptr == &me ? UserStats.local_clients : cli_serv(acptr)->clients),
               cli_serv(acptr)->nn_mask,
               cli_serv(acptr)->prot,
               cli_serv(acptr)->timestamp,
               cli_info(acptr));
  }
}

/** Lists WebIRC authorizations.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_webirc(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct wline *wline;
  char ip_text[SOCKIPLEN + 1];

  for (wline = GlobalWebircList; wline; wline = wline->next) {
    const char *desc = wline->description;
    if (!desc)
      desc = "(no description provided)";
    if (wline->hidden)
      strcpy(ip_text, "*");
    else
      ircd_ntoa_r(ip_text, &wline->ip);
    send_reply(to, RPL_STATSWLINE, ip_text, wline->bits, desc);
  }
}

/** Display objects allocated (and total memory used by them) for
 * several types of structures.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_meminfo(struct Client* to, const struct StatDesc* sd, char* param)
{
  extern void bans_send_meminfo(struct Client *cptr);

  class_send_meminfo(to);
  bans_send_meminfo(to);
  send_listinfo(to, 0);
}

/** Send a list of available statistics.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request.
 * @param[in] param Extra parameter from user (ignored).
 */
static void
stats_help(struct Client* to, const struct StatDesc* sd, char* param)
{
  struct StatDesc *asd;

  /* only if it's my user */
  if (MyUser(to))
    for (asd = statsinfo; asd->sd_name; asd++)
      if (asd != sd) /* don't send the help for us */
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :%c (%s) - %s", to, asd->sd_c,
                      asd->sd_name, asd->sd_desc);
}

/** Contains information about all statistics. */
struct StatDesc statsinfo[] = {
  { 'a', "nameservers", STAT_FLAG_OPERFEAT|STAT_FLAG_LOCONLY, FEAT_HIS_STATS_a,
    report_dns_servers, 0,
    "DNS servers." },
  { 'c', "connect", STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_c,
    stats_configured_links, CONF_SERVER,
    "Remote server connection lines." },
  { 'd', "maskrules", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_d,
    stats_crule_list, CRULE_MASK,
    "Dynamic routing configuration." },
  { 'D', "crules", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_d,
    stats_crule_list, CRULE_ALL,
    "Dynamic routing configuration." },
  { 'e', "engine", STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_e,
    stats_engine, 0,
    "Report server event loop engine." },
  { 'f', "features", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_f,
    feature_report, 0,
    "Feature settings." },
  { 'F', "featuresall", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_f,
    feature_report, 1,
    "All feature settings, including defaulted values." },
  { 'g', "glines", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_g,
    gline_stats, 0,
    "Global bans (G-lines)." },
  { 'i', "access", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_i,
    stats_access, CONF_CLIENT,
    "Connection authorization lines." },
  { 'j', "histogram", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_j,
    msgq_histogram, 0,
    "Message length histogram." },
  { 'J', "jupes", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_J,
    stats_nickjupes, 0,
    "Nickname jupes." },
  { 'k', "klines", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_k,
    stats_klines, 0,
    "Local bans (K-Lines)." },
  { 'l', "links", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM | STAT_FLAG_CASESENS),
    FEAT_HIS_STATS_l,
    stats_links, 0,
    "Current connections information." },
  { 'L', "modules", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS),
    FEAT_HIS_STATS_L,
    stats_modules, 0,
    "Dynamically loaded modules." },
  { 'm', "commands", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_m,
    stats_commands, 0,
    "Message usage information." },
  { 'o', "operators", STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_o,
    stats_configured_links, CONF_OPERATOR,
    "Operator information." },
  { 'p', "ports", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_p,
    show_ports, 0,
    "Listening ports." },
  { 'q', "quarantines", (STAT_FLAG_OPERONLY | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_q,
    stats_quarantine, 0,
    "Quarantined channels list." },
  { 'R', "mappings", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_R,
    stats_mapping, 0,
    "Service mappings." },
#ifdef DEBUGMODE
  { 'r', "usage", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_r,
    send_usage, 0,
    "System resource usage (Debug only)." },
#endif
  { 'T', "motds", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_T,
    motd_report, 0,
    "Configured Message Of The Day files." },
  { 't', "locals", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_t,
    tstats, 0,
    "Local connection statistics (Total SND/RCV, etc)." },
  { 'U', "uworld", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_U,
    stats_configured_links, CONF_UWORLD,
    "Service server information." },
  { 'u', "uptime", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_u,
    stats_uptime, 0,
    "Current uptime & highest connection count." },
  { 'v', "vservers", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM | STAT_FLAG_CASESENS), FEAT_HIS_STATS_v,
    stats_servers_verbose, 1,
    "Verbose server information." },
  { 'V', "vserversmach", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM | STAT_FLAG_CASESENS), FEAT_HIS_STATS_v,
    stats_servers_verbose, 0,
    "Verbose server information." },
  { 'w', "userload", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_w,
    calc_load, 0,
    "Userload statistics." },
  { 'W', "webirc", (STAT_FLAG_OPERFEAT | STAT_FLAG_CASESENS), FEAT_HIS_STATS_W,
    stats_webirc, 0,
    "WebIRC authorizations." },
  { 'x', "memusage", STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_x,
    stats_meminfo, 0,
    "List usage information." },
  { 'y', "classes", STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_y,
    report_classes, 0,
    "Connection classes." },
  { 'z', "memory", STAT_FLAG_OPERFEAT, FEAT_HIS_STATS_z,
    count_memory, 0,
    "Memory/Structure allocation information." },
  { ' ', "iauth", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_IAUTH,
    report_iauth_stats, 0,
    "IAuth statistics." },
  { ' ', "iauthconf", (STAT_FLAG_OPERFEAT | STAT_FLAG_VARPARAM), FEAT_HIS_STATS_IAUTH,
    report_iauth_conf, 0,
    "IAuth configuration." },
  { '*', "help", STAT_FLAG_CASESENS, FEAT_LAST_F,
    stats_help, 0,
    "Send help for stats." },
  { '\0', 0, FEAT_LAST_F, 0, 0, 0 }
};

/** Maps from characters to statistics descriptors.
 * Statistics descriptors with no single-character alias are not included.
 */
static struct StatDesc *statsmap[256];
/** Number of statistics descriptors. */
static int statscount;

/** Compare two StatDesc structures by long name (StatDesc::sd_name).
 * @param[in] a_ Pointer to a StatDesc.
 * @param[in] b_ Pointer to a StatDesc.
 * @return Less than, equal to, or greater than zero if \a a_ is
 * lexicographically less than, equal to, or greater than \a b_.
 */
static int
stats_cmp(const void *a_, const void *b_)
{
  const struct StatDesc *a = a_;
  const struct StatDesc *b = b_;
  return ircd_strcmp(a->sd_name, b->sd_name);
}

/** Compare a StatDesc's name against a string.
 * @param[in] key Pointer to a null-terminated string.
 * @param[in] sd_ Pointer to a StatDesc.
 * @return Less than, equal to, or greater than zero if \a key is
 * lexicographically less than, equal to, or greater than \a
 * sd_->sd_name.
 */
static int
stats_search(const void *key, const void *sd_)
{
  const struct StatDesc *sd = sd_;
  return ircd_strcmp(key, sd->sd_name);
}

/** Look up a stats handler.  If name_or_char is just one character
 * long, use that as a character index; otherwise, look it up by name
 * in #statsinfo.
 * @param[in] name_or_char Null-terminated string to look up.
 * @return The statistics descriptor for \a name_or_char (NULL if none).
 */
const struct StatDesc *
stats_find(const char *name_or_char)
{
  if (!name_or_char[1])
    return statsmap[name_or_char[0] - CHAR_MIN];
  else
    return bsearch(name_or_char, statsinfo, statscount, sizeof(statsinfo[0]), stats_search);
}

/** Build statsmap from the statsinfo array. */
void
stats_init(void)
{
  struct StatDesc *sd;

  /* Count number of stats entries and sort them. */
  for (statscount = 0, sd = statsinfo; sd->sd_name; sd++, statscount++) {}
  qsort(statsinfo, statscount, sizeof(statsinfo[0]), stats_cmp);

  /* Build the mapping */
  for (sd = statsinfo; sd->sd_name; sd++)
  {
    if (!sd->sd_c)
      continue;
    else if (sd->sd_flags & STAT_FLAG_CASESENS)
      /* case sensitive character... */
      statsmap[sd->sd_c - CHAR_MIN] = sd;
    else
    {
      /* case insensitive--make sure to put in two entries */
      statsmap[ToLower(sd->sd_c) - CHAR_MIN] = sd;
      statsmap[ToUpper(sd->sd_c) - CHAR_MIN] = sd;
    }
  }
}
