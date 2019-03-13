/*
 * IRC - Internet Relay Chat, ircd/s_conf.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief ircd configuration file driver
 * @version $Id$
 */
#include "config.h"

#include "s_conf.h"
#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd_features.h"
#include "fileio.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/** Global list of all ConfItem structures. */
struct ConfItem  *GlobalConfList;
/** Count of items in #GlobalConfList. */
int              GlobalConfCount;
/** Global list of service mappings. */
struct s_map     *GlobalServiceMapList;
/** Global list of channel quarantines. */
struct qline     *GlobalQuarantineList;
/** Global list of webirc authorizations. */
struct wline*      GlobalWebircList;

/** Current line number in scanner input. */
int lineno;

/** Flag for whether to perform ident lookups. */
int DoIdentLookups;

/** Configuration information for #me. */
struct LocalConf   localConf;
/** Global list of connection rules. */
struct CRuleConf*  cruleConfList;
/** Global list of K-lines. */
struct DenyConf*   denyConfList;

/** Tell a user that they are banned, dumping the message from a file.
 * @param sptr Client being rejected
 * @param filename Send this file's contents to \a sptr
 */
static void killcomment(struct Client* sptr, const char* filename)
{
  FBFILE*     file = 0;
  char        line[80];
  struct stat sb;

  if (NULL == (file = fbopen(filename, "r"))) {
    send_reply(sptr, ERR_NOMOTD);
    send_reply(sptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
               ":Connection from your host is refused on this server.");
    return;
  }
  fbstat(&sb, file);
  while (fbgets(line, sizeof(line) - 1, file)) {
    char* end = line + strlen(line);
    while (end > line) {
      --end;
      if ('\n' == *end || '\r' == *end)
        *end = '\0';
      else
        break;
    }
    send_reply(sptr, RPL_MOTD, line);
  }
  send_reply(sptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
             ":Connection from your host is refused on this server.");
  fbclose(file);
}

/** Allocate a new struct ConfItem and link it to #GlobalConfList.
 * @return Newly allocated structure.
 */
struct ConfItem* make_conf(int type)
{
  struct ConfItem* aconf;

  aconf = (struct ConfItem*) MyMalloc(sizeof(struct ConfItem));
  assert(0 != aconf);
  ++GlobalConfCount;
  memset(aconf, 0, sizeof(struct ConfItem));
  aconf->status  = type;
  aconf->next    = GlobalConfList;
  GlobalConfList = aconf;
  return aconf;
}

/** Free a struct ConfItem and any resources it owns.
 * @param aconf Item to free.
 */
void free_conf(struct ConfItem *aconf)
{
  Debug((DEBUG_DEBUG, "free_conf: %s %s %d",
         aconf->host ? aconf->host : "*",
         aconf->name ? aconf->name : "*",
         aconf->address.port));
  if (aconf->dns_pending)
    delete_resolver_queries(aconf);
  MyFree(aconf->username);
  MyFree(aconf->host);
  MyFree(aconf->origin_name);
  if (aconf->passwd)
    memset(aconf->passwd, 0, strlen(aconf->passwd));
  MyFree(aconf->passwd);
  MyFree(aconf->name);
  MyFree(aconf->hub_limit);
  MyFree(aconf);
  --GlobalConfCount;
}

/** Disassociate configuration from the client.
 * @param cptr Client to operate on.
 * @param aconf ConfItem to detach.
 */
static void detach_conf(struct Client* cptr, struct ConfItem* aconf)
{
  struct SLink** lp;
  struct SLink*  tmp;

  assert(0 != aconf);
  assert(0 != cptr);
  assert(0 < aconf->clients);

  lp = &(cli_confs(cptr));

  while (*lp) {
    if ((*lp)->value.aconf == aconf) {
      if (aconf->conn_class && (aconf->status & CONF_CLIENT_MASK) && ConfLinks(aconf) > 0)
        --ConfLinks(aconf);

      assert(0 < aconf->clients);
      if (0 == --aconf->clients && IsIllegal(aconf))
        free_conf(aconf);
      tmp = *lp;
      *lp = tmp->next;
      free_link(tmp);
      return;
    }
    lp = &((*lp)->next);
  }
}

/** Parse a user\@host mask into username and host or IP parts.
 * If \a host contains no username part, set \a aconf->username to
 * NULL.  If the host part of \a host looks like an IP mask, set \a
 * aconf->addrbits and \a aconf->address to match.  Otherwise, set
 * \a aconf->host, and set \a aconf->addrbits to -1.
 * @param[in,out] aconf Configuration item to set.
 * @param[in] host user\@host mask to parse.
 */
void conf_parse_userhost(struct ConfItem *aconf, char *host)
{
  char *host_part;
  unsigned char addrbits;

  MyFree(aconf->username);
  MyFree(aconf->host);
  host_part = strchr(host, '@');
  if (host_part) {
    *host_part = '\0';
    DupString(aconf->username, host);
    host_part++;
  } else {
    aconf->username = NULL;
    host_part = host;
  }
  DupString(aconf->host, host_part);
  if (ipmask_parse(aconf->host, &aconf->address.addr, &addrbits))
    aconf->addrbits = addrbits;
  else
    aconf->addrbits = -1;
}

/** Copies a completed DNS query into its ConfItem.
 * @param vptr Pointer to struct ConfItem for the block.
 * @param hp DNS reply, or NULL if the lookup failed.
 */
static void conf_dns_callback(void* vptr, const struct irc_in_addr *addr, const char *h_name)
{
  struct ConfItem* aconf = (struct ConfItem*) vptr;
  assert(aconf);
  aconf->dns_pending = 0;
  if (addr)
    memcpy(&aconf->address.addr, addr, sizeof(aconf->address.addr));
}

/** Start a nameserver lookup of the conf host.  If the conf entry is
 * currently doing a lookup, do nothing.
 * @param aconf ConfItem for which to start a request.
 */
static void conf_dns_lookup(struct ConfItem* aconf)
{
  if (!aconf->dns_pending) {
    char            buf[HOSTLEN + 1];

    host_from_uh(buf, aconf->host, HOSTLEN);
    gethost_byname(buf, conf_dns_callback, aconf);
    aconf->dns_pending = 1;
  }
}


/** Start lookups of all addresses in the conf line.  The origin must
 * be a numeric IP address.  If the remote host field is not an IP
 * address, start a DNS lookup for it.
 * @param aconf Connection to do lookups for.
 */
void
lookup_confhost(struct ConfItem *aconf)
{
  if (EmptyString(aconf->host) || EmptyString(aconf->name)) {
    Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
           aconf->host, aconf->name));
    return;
  }
  if (aconf->origin_name
      && !ircd_aton(&aconf->origin.addr, aconf->origin_name)) {
    Debug((DEBUG_ERROR, "Origin name error: (%s) (%s)",
        aconf->origin_name, aconf->name));
  }
  /*
   * Do name lookup now on hostnames given and store the
   * ip numbers in conf structure.
   */
  if (IsIP6Char(*aconf->host)) {
    if (!ircd_aton(&aconf->address.addr, aconf->host)) {
      Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
          aconf->host, aconf->name));
    }
  }
  else
    conf_dns_lookup(aconf);
}

/** Find a server by name or hostname.
 * @param name Server name to find.
 * @return Pointer to the corresponding ConfItem, or NULL if none exists.
 */
struct ConfItem* conf_find_server(const char* name)
{
  struct ConfItem* conf;
  assert(0 != name);

  for (conf = GlobalConfList; conf; conf = conf->next) {
    if (CONF_SERVER == conf->status) {
      /*
       * Check first servernames, then try hostnames.
       * XXX - match returns 0 if there _is_ a match... guess they
       * haven't decided what true is yet
       */
      if (0 == match(name, conf->name))
        return conf;
    }
  }
  return 0;
}

/** Evaluate connection rules.
 * @param name Name of server to check
 * @param mask Filter for CRule types (only consider if type & \a mask != 0).
 * @return Name of rule that forbids the connection; NULL if no prohibitions.
 */
const char* conf_eval_crule(const char* name, int mask)
{
  struct CRuleConf* p = cruleConfList;
  assert(0 != name);

  for ( ; p; p = p->next) {
    if (0 != (p->type & mask) && 0 == match(p->hostmask, name)) {
      if (crule_eval(p->node))
        return p->rule;
    }
  }
  return 0;
}

/** Remove all conf entries from the client except those which match
 * the status field mask.
 * @param cptr Client to operate on.
 * @param mask ConfItem types to keep.
 */
void det_confs_butmask(struct Client* cptr, int mask)
{
  struct SLink* link;
  struct SLink* next;
  assert(0 != cptr);

  for (link = cli_confs(cptr); link; link = next) {
    next = link->next;
    if ((link->value.aconf->status & mask) == 0)
      detach_conf(cptr, link->value.aconf);
  }
}

/** Find the first (best) Client block to attach.
 * @param cptr Client for whom to check rules.
 * @return Authorization check result.
 */
enum AuthorizationCheckResult attach_iline(struct Client* cptr)
{
  struct ConfItem* aconf;

  assert(0 != cptr);

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (aconf->status != CONF_CLIENT)
      continue;
    /* If you change any of this logic, please make corresponding
     * changes in conf_debug_iline() below.
     */
    if (aconf->address.port && aconf->address.port != cli_listener(cptr)->addr.port)
      continue;
    if (aconf->username && match(aconf->username, cli_username(cptr)))
      continue;
    if (aconf->host && match(aconf->host, cli_sockhost(cptr)))
      continue;
    if ((aconf->addrbits >= 0)
        && !ipmask_check(&cli_ip(cptr), &aconf->address.addr, aconf->addrbits))
      continue;
    if (IPcheck_nr(cptr) > aconf->maximum)
      return ACR_TOO_MANY_FROM_IP;
    return attach_conf(cptr, aconf);
  }
  return ACR_NO_AUTHORIZATION;
}

/** Interpret \a client as a client specifier and show which Client
 * block(s) match that client.
 *
 * The client specifier may contain an IP address, hostname, listener
 * port, or a combination of those separated by commas.  IP addresses
 * and hostnamese may be preceded by "username@"; the last given
 * username will be used for the match.
 *
 * @param[in] client Client specifier.
 * @return Matching Client block structure.
 */
struct ConfItem *conf_debug_iline(const char *client)
{
  struct irc_in_addr address;
  struct ConfItem *aconf;
  struct DenyConf *deny;
  char *sep;
  unsigned short listener;
  char username[USERLEN+1], hostname[HOSTLEN+1], realname[REALLEN+1];

  /* Initialize variables. */
  listener = 0;
  memset(&address, 0, sizeof(address));
  memset(&username, 0, sizeof(username));
  memset(&hostname, 0, sizeof(hostname));
  memset(&realname, 0, sizeof(realname));

  /* Parse client specifier. */
  while (*client) {
    struct irc_in_addr tmpaddr;
    long tmp;

    /* Try to parse as listener port number first. */
    tmp = strtol(client, &sep, 10);
    if (tmp && (*sep == '\0' || *sep == ',')) {
      listener = tmp;
      client = sep + (*sep != '\0');
      continue;
    }

    /* Maybe username@ before an IP address or hostname? */
    tmp = strcspn(client, ",@");
    if (client[tmp] == '@') {
      if (tmp > USERLEN)
        tmp = USERLEN;
      ircd_strncpy(username, client, tmp);
      /* and fall through */
      client += tmp + 1;
    }

    /* Looks like an IP address? */
    tmp = ircd_aton(&tmpaddr, client);
    if (tmp && (client[tmp] == '\0' || client[tmp] == ',')) {
        memcpy(&address, &tmpaddr, sizeof(address));
        client += tmp + (client[tmp] != '\0');
        continue;
    }

    /* Realname? */
    if (client[0] == '$' && client[1] == 'R') {
      client += 2;
      for (tmp = 0; *client != '\0' && *client != ',' && tmp < REALLEN; ++client, ++tmp) {
        if (*client == '\\')
          realname[tmp] = *++client;
        else
          realname[tmp] = *client;
      }
      continue;
    }

    /* Else must be a hostname. */
    tmp = strcspn(client, ",");
    if (tmp > HOSTLEN)
      tmp = HOSTLEN;
    ircd_strncpy(hostname, client, tmp);
    client += tmp + (client[tmp] != '\0');
  }

  /* Walk configuration to find matching Client block. */
  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (aconf->status != CONF_CLIENT)
      continue;
    if (aconf->address.port && aconf->address.port != listener) {
      fprintf(stdout, "Listener port mismatch: %u != %u\n", aconf->address.port, listener);
      continue;
    }
    if (aconf->username && match(aconf->username, username)) {
      fprintf(stdout, "Username mismatch: %s != %s\n", aconf->username, username);
      continue;
    }
    if (aconf->host && match(aconf->host, hostname)) {
      fprintf(stdout, "Hostname mismatch: %s != %s\n", aconf->host, hostname);
      continue;
    }
    if ((aconf->addrbits >= 0)
        && !ipmask_check(&address, &aconf->address.addr, aconf->addrbits)) {
      fprintf(stdout, "IP address mismatch: %s != %s\n", aconf->name, ircd_ntoa(&address));
      continue;
    }
    fprintf(stdout, "Match! username=%s host=%s ip=%s class=%s maxlinks=%u password=%s\n",
            (aconf->username ? aconf->username : "(null)"),
            (aconf->host ? aconf->host : "(null)"),
            (aconf->name ? aconf->name : "(null)"),
            ConfClass(aconf), aconf->maximum,
            (aconf->passwd ? aconf->passwd : "(null)"));
    break;
  }

  /* If no authorization, say so and exit. */
  if (!aconf)
  {
    fprintf(stdout, "No authorization found.\n");
    return NULL;
  }

  /* Look for a Kill block with the user's name on it. */
  for (deny = denyConfList; deny; deny = deny->next) {
    if (deny->usermask && match(deny->usermask, username))
      continue;
    if (deny->realmask && match(deny->realmask, realname))
      continue;
    if (deny->bits > 0) {
      if (!ipmask_check(&address, &deny->address, deny->bits))
        continue;
    } else if (deny->hostmask && match(deny->hostmask, hostname))
      continue;

    /* Looks like a match; report it. */
    fprintf(stdout, "Denied! usermask=%s realmask=\"%s\" hostmask=%s (bits=%u)\n",
            deny->usermask ? deny->usermask : "(null)",
            deny->realmask ? deny->realmask : "(null)",
            deny->hostmask ? deny->hostmask : "(null)",
            deny->bits);
  }

  return aconf;
}

/** Check whether a particular ConfItem is already attached to a
 * Client.
 * @param aconf ConfItem to search for
 * @param cptr Client to check
 * @return Non-zero if \a aconf is attached to \a cptr, zero if not.
 */
static int is_attached(struct ConfItem *aconf, struct Client *cptr)
{
  struct SLink *lp;

  for (lp = cli_confs(cptr); lp; lp = lp->next) {
    if (lp->value.aconf == aconf)
      return 1;
  }
  return 0;
}

/** Associate a specific configuration entry to a *local* client (this
 * is the one which used in accepting the connection). Note, that this
 * automatically changes the attachment if there was an old one...
 * @param cptr Client to attach \a aconf to
 * @param aconf ConfItem to attach
 * @return Authorization check result.
 */
enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf)
{
  struct SLink *lp;

  if (is_attached(aconf, cptr))
    return ACR_ALREADY_AUTHORIZED;
  if (IsIllegal(aconf))
    return ACR_NO_AUTHORIZATION;
  if ((aconf->status & (CONF_OPERATOR | CONF_CLIENT)) &&
      ConfLinks(aconf) >= ConfMaxLinks(aconf) && ConfMaxLinks(aconf) > 0)
    return ACR_TOO_MANY_IN_CLASS;  /* Use this for printing error message */
  lp = make_link();
  lp->next = cli_confs(cptr);
  lp->value.aconf = aconf;
  cli_confs(cptr) = lp;
  ++aconf->clients;
  if (aconf->status & CONF_CLIENT_MASK)
    ConfLinks(aconf)++;
  return ACR_OK;
}

/** Return our LocalConf configuration structure.
 * @return A pointer to #localConf.
 */
const struct LocalConf* conf_get_local(void)
{
  return &localConf;
}

/** Attach ConfItems to a client if the name passed matches that for
 * the ConfItems or is an exact match for them.
 * @param cptr Client getting the ConfItem attachments.
 * @param name Filter to match ConfItem::name.
 * @param statmask Filter to limit ConfItem::status.
 * @return First ConfItem attached to \a cptr.
 */
struct ConfItem* attach_confs_byname(struct Client* cptr, const char* name,
                                     int statmask)
{
  struct ConfItem* tmp;
  struct ConfItem* first = NULL;

  assert(0 != name);

  if (HOSTLEN < strlen(name))
    return 0;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (0 != (tmp->status & statmask) && !IsIllegal(tmp)) {
      assert(0 != tmp->name);
      if (0 == match(tmp->name, name) || 0 == ircd_strcmp(tmp->name, name)) { 
        if (ACR_OK == attach_conf(cptr, tmp) && !first)
          first = tmp;
      }
    }
  }
  return first;
}

/** Attach ConfItems to a client if the host passed matches that for
 * the ConfItems or is an exact match for them.
 * @param cptr Client getting the ConfItem attachments.
 * @param host Filter to match ConfItem::host.
 * @param statmask Filter to limit ConfItem::status.
 * @return First ConfItem attached to \a cptr.
 */
struct ConfItem* attach_confs_byhost(struct Client* cptr, const char* host,
                                     int statmask)
{
  struct ConfItem* tmp;
  struct ConfItem* first = 0;

  assert(0 != host);
  if (HOSTLEN < strlen(host))
    return 0;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (0 != (tmp->status & statmask) && !IsIllegal(tmp)) {
      assert(0 != tmp->host);
      if (0 == match(tmp->host, host) || 0 == ircd_strcmp(tmp->host, host)) { 
        if (ACR_OK == attach_conf(cptr, tmp) && !first)
          first = tmp;
      }
    }
  }
  return first;
}

/** Find a ConfItem that has the same name and user+host fields as
 * specified.  Requires an exact match for \a name.
 * @param name Name to match
 * @param cptr Client to match against
 * @param statmask Filter for ConfItem::status
 * @return First found matching ConfItem.
 */
struct ConfItem* find_conf_exact(const char* name, struct Client *cptr, int statmask)
{
  struct ConfItem *tmp;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (!(tmp->status & statmask) || !tmp->name || !tmp->host ||
        0 != ircd_strcmp(tmp->name, name))
      continue;
    if (tmp->username && match(tmp->username, cli_username(cptr)))
      continue;
    if (tmp->addrbits < 0)
    {
      if (match(tmp->host, cli_sockhost(cptr)))
        continue;
    }
    else if (!ipmask_check(&cli_ip(cptr), &tmp->address.addr, tmp->addrbits))
      continue;
    if ((tmp->status & CONF_OPERATOR)
        && (MaxLinks(tmp->conn_class) > 0)
        && (tmp->clients >= MaxLinks(tmp->conn_class)))
      continue;
    return tmp;
  }
  return 0;
}

/** Find a ConfItem from a list that has a name that matches \a name.
 * @param lp List to search in.
 * @param name Filter for ConfItem::name field; matches either exactly
 * or as a glob.
 * @param statmask Filter for ConfItem::status.
 * @return First matching ConfItem from \a lp.
 */
struct ConfItem* find_conf_byname(struct SLink* lp, const char* name,
                                  int statmask)
{
  struct ConfItem* tmp;
  assert(0 != name);

  if (HOSTLEN < strlen(name))
    return 0;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)) {
      assert(0 != tmp->name);
      if (0 == ircd_strcmp(tmp->name, name) || 0 == match(tmp->name, name))
        return tmp;
    }
  }
  return 0;
}

/** Find a ConfItem from a list that has a host that matches \a host.
 * @param lp List to search in.
 * @param host Filter for ConfItem::host field; matches as a glob.
 * @param statmask Filter for ConfItem::status.
 * @return First matching ConfItem from \a lp.
 */
struct ConfItem* find_conf_byhost(struct SLink* lp, const char* host,
                                  int statmask)
{
  struct ConfItem* tmp = NULL;
  assert(0 != host);

  if (HOSTLEN < strlen(host))
    return 0;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)) {
      assert(0 != tmp->host);
      if (0 == match(tmp->host, host))
        return tmp;
    }
  }
  return 0;
}

/** Find a ConfItem from a list that has an address equal to \a ip.
 * @param lp List to search in.
 * @param ip Filter for ConfItem::address field; matches exactly.
 * @param statmask Filter for ConfItem::status.
 * @return First matching ConfItem from \a lp.
 */
struct ConfItem* find_conf_byip(struct SLink* lp, const struct irc_in_addr* ip,
                                int statmask)
{
  struct ConfItem* tmp;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)
        && !irc_in_addr_cmp(&tmp->address.addr, ip))
      return tmp;
  }
  return 0;
}

/** Free all CRules from #cruleConfList. */
void conf_erase_crule_list(void)
{
  struct CRuleConf* next;
  struct CRuleConf* p = cruleConfList;

  for ( ; p; p = next) {
    next = p->next;
    crule_free(&p->node);
    MyFree(p->hostmask);
    MyFree(p->rule);
    MyFree(p);
  }
  cruleConfList = 0;
}

/** Return #cruleConfList.
 * @return #cruleConfList
 */
const struct CRuleConf* conf_get_crule_list(void)
{
  return cruleConfList;
}

/** Free all deny rules from #denyConfList. */
void conf_erase_deny_list(void)
{
  struct DenyConf* next;
  struct DenyConf* p = denyConfList;
  for ( ; p; p = next) {
    next = p->next;
    MyFree(p->hostmask);
    MyFree(p->usermask);
    MyFree(p->message);
    MyFree(p->realmask);
    MyFree(p);
  }
  denyConfList = 0;
}

/** Return #denyConfList.
 * @return #denyConfList
 */
const struct DenyConf* conf_get_deny_list(void)
{
  return denyConfList;
}

/** Find any existing quarantine for the named channel.
 * @param chname Channel name to search for.
 * @return Reason for channel's quarantine, or NULL if none exists.
 */
const char*
find_quarantine(const char *chname)
{
  struct qline *qline;

  for (qline = GlobalQuarantineList; qline; qline = qline->next)
    if (!ircd_strcmp(qline->chname, chname))
      return qline->reason;
  return NULL;
}

/** Find a WebIRC authorization for the given client address.
 * @param addr IP address to search for.
 * @param passwd Client-provided password for block.
 * @return WebIRC authorization block, or NULL if none exists.
 */
const struct wline *
find_webirc(const struct irc_in_addr *addr, const char *passwd)
{
  struct wline *wline;

  for (wline = GlobalWebircList; wline; wline = wline->next)
    if (ipmask_check(addr, &wline->ip, wline->bits)
        && (0 == strcmp(wline->passwd, passwd)))
      return wline;
  return NULL;
}

/** Free all qline structs from #GlobalQuarantineList. */
void clear_quarantines(void)
{
  struct qline *qline;
  while ((qline = GlobalQuarantineList))
  {
    GlobalQuarantineList = qline->next;
    MyFree(qline->reason);
    MyFree(qline->chname);
    MyFree(qline);
  }
}

/** Mark everything in #GlobalWebircList stale. */
static void webirc_mark_stale(void)
{
  struct wline *wline;
  for (wline = GlobalWebircList; wline; wline = wline->next)
    wline->stale = 1;
}

/** Remove any still-stale entries in #GlobalWebircList. */
static void webirc_remove_stale(void)
{
  struct wline *wline, **pp_w;

  for (pp_w = &GlobalWebircList; (wline = *pp_w) != NULL; ) {
    if (wline->stale) {
      *pp_w = wline->next;
      MyFree(wline->passwd);
      MyFree(wline->description);
      MyFree(wline);
    } else {
      pp_w = &wline->next;
    }
  }
}

/** When non-zero, indicates that a configuration error has been seen in this pass. */
static int conf_error;
/** When non-zero, indicates that the configuration file was loaded at least once. */
static int conf_already_read;
extern void yyparse(void);
extern int init_lexer(void);
extern void deinit_lexer(void);

/** Read configuration file.
 * @return Zero on failure, non-zero on success. */
int read_configuration_file(void)
{
  conf_error = 0;
  feature_unmark(); /* unmark all features for resetting later */
  clear_nameservers(); /* clear previous list of DNS servers */
  if (!init_lexer())
    return 0;
  yyparse();
  deinit_lexer();
  feature_mark(); /* reset unmarked features */
  conf_already_read = 1;
  return 1;
}

/** Report an error message about the configuration file.
 * @param msg The error to report.
 */
void
yyerror(const char *msg)
{
 sendto_opmask_butone(0, SNO_ALL, "Config file parse error line %d: %s",
                      lineno, msg);
 log_write(LS_CONFIG, L_ERROR, 0, "Config file parse error line %d: %s",
           lineno, msg);
 if (!conf_already_read)
   fprintf(stderr, "Config file parse error line %d: %s\n", lineno, msg);
 conf_error = 1;
}

/** Attach CONF_UWORLD items to a server and everything attached to it. */
static void
attach_conf_uworld(struct Client *cptr)
{
  struct DLink *lp;

  attach_confs_byhost(cptr, cli_name(cptr), CONF_UWORLD);
  for (lp = cli_serv(cptr)->down; lp; lp = lp->next)
    attach_conf_uworld(lp->value.cptr);
}

/** Free all memory associated with service mapping \a smap.
 * @param smap[in] The mapping to free.
 */
void free_mapping(struct s_map *smap)
{
  struct nick_host *nh, *next;
  for (nh = smap->services; nh; nh = next)
  {
    next = nh->next;
    MyFree(nh);
  }
  MyFree(smap->name);
  MyFree(smap->command);
  MyFree(smap->prepend);
  MyFree(smap);
}

/** Unregister and free all current service mappings. */
static void close_mappings(void)
{
  struct s_map *map, *next;

  for (map = GlobalServiceMapList; map; map = next) {
    next = map->next;
    unregister_mapping(map);
    free_mapping(map);
  }
  GlobalServiceMapList = NULL;
}

/** Reload the configuration file.
 * @param cptr Client that requested rehash (if a signal, &me).
 * @param sig Type of rehash (0 = oper-requested, 1 = signal, 2 =
 *   oper-requested but do not restart resolver)
 * @return CPTR_KILLED if any client was K/G-lined because of the
 * rehash; otherwise 0.
 */
int rehash(struct Client *cptr, int sig)
{
  struct ConfItem** tmp = &GlobalConfList;
  struct ConfItem*  tmp2;
  struct Client*    acptr;
  int               i;
  int               ret = 0;
  int               found_g = 0;

  if (1 == sig)
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Got signal SIGHUP, reloading ircd conf. file");

  while ((tmp2 = *tmp)) {
    if (tmp2->clients) {
      /*
       * Configuration entry is still in use by some
       * local clients, cannot delete it--mark it so
       * that it will be deleted when the last client
       * exits...
       */
      if (CONF_CLIENT == (tmp2->status & CONF_CLIENT))
        tmp = &tmp2->next;
      else {
        *tmp = tmp2->next;
        tmp2->next = 0;
      }
      tmp2->status |= CONF_ILLEGAL;
    }
    else {
      *tmp = tmp2->next;
      free_conf(tmp2);
    }
  }
  conf_erase_crule_list();
  conf_erase_deny_list();
  motd_clear();

  /*
   * delete the juped nicks list
   */
  clearNickJupes();

  clear_quarantines();

  class_mark_delete();
  mark_listeners_closing();
  auth_mark_closing();
  webirc_mark_stale();
  close_mappings();
  DoIdentLookups = 0;

  read_configuration_file();

  if (sig != 2)
    restart_resolver();

  log_reopen(); /* reopen log files */

  auth_close_unused();
  close_listeners();
  class_delete_marked();         /* unless it fails */

  /*
   * Flush out deleted I and P lines although still in use.
   */
  for (tmp = &GlobalConfList; (tmp2 = *tmp);) {
    if (CONF_ILLEGAL == (tmp2->status & CONF_ILLEGAL)) {
      *tmp = tmp2->next;
      tmp2->next = NULL;
      if (!tmp2->clients)
        free_conf(tmp2);
    }
    else
      tmp = &tmp2->next;
  }

  for (i = 0; i <= HighestFd; i++) {
    if ((acptr = LocalClientArray[i])) {
      const struct wline *wline;
      assert(!IsMe(acptr));
      if (IsServer(acptr))
        det_confs_butmask(acptr, ~(CONF_UWORLD | CONF_ILLEGAL));
      /* Because admin's are getting so uppity about people managing to
       * get past K/G's etc, we'll "fix" the bug by actually explaining
       * whats going on.
       */
      if ((found_g = find_kill(acptr))) {
        sendto_opmask_butone(0, found_g == -2 ? SNO_GLINE : SNO_OPERKILL,
                             found_g == -2 ? "G-line active for %s%s" :
                             "K-line active for %s%s",
                             IsUnknown(acptr) ? "Unregistered Client ":"",
                             get_client_name(acptr, SHOW_IP));
        if (exit_client(cptr, acptr, &me, found_g == -2 ? "G-lined" :
            "K-lined") == CPTR_KILLED)
          ret = CPTR_KILLED;
      } else if ((wline = cli_wline(acptr)) && wline->stale) {
        if (exit_client(cptr, acptr, &me, "WebIRC authorization removed")
            == CPTR_KILLED)
          ret = CPTR_KILLED;
      }
    }
  }

  attach_conf_uworld(&me);
  webirc_remove_stale();

  return ret;
}

/** Read configuration file for the very first time.
 * @return Non-zero on success, zero on failure.
 */

int init_conf(void)
{
  if (read_configuration_file()) {
    /*
     * make sure we're sane to start if the config
     * file read didn't get everything we need.
     * XXX - should any of these abort the server?
     * TODO: add warning messages
     */
    if (0 == localConf.name || 0 == localConf.numeric)
      return 0;
    if (conf_error)
      return 0;

    if (0 == localConf.location1)
      DupString(localConf.location1, "");
    if (0 == localConf.location2)
      DupString(localConf.location2, "");
    if (0 == localConf.contact)
      DupString(localConf.contact, "");

    return 1;
  }
  return 0;
}

/** Searches for a K/G-line for a client.  If one is found, notify the
 * user and disconnect them.
 * @param cptr Client to search for.
 * @return 0 if client is accepted; -1 if client was locally denied
 * (K-line); -2 if client was globally denied (G-line).
 */
int find_kill(struct Client *cptr)
{
  const char*      host;
  const char*      name;
  const char*      realname;
  struct DenyConf* deny;
  struct Gline*    agline = NULL;

  assert(0 != cptr);

  if (!cli_user(cptr))
    return 0;

  host = cli_sockhost(cptr);
  name = cli_user(cptr)->username;
  realname = cli_info(cptr);

  assert(strlen(host) <= HOSTLEN);
  assert((name ? strlen(name) : 0) <= HOSTLEN);
  assert((realname ? strlen(realname) : 0) <= REALLEN);

  /* 2000-07-14: Rewrote this loop for massive speed increases.
   *             -- Isomer
   */
  for (deny = denyConfList; deny; deny = deny->next) {
    if (deny->usermask && match(deny->usermask, name))
      continue;
    if (deny->realmask && match(deny->realmask, realname))
      continue;
    if (deny->bits > 0) {
      if (!ipmask_check(&cli_ip(cptr), &deny->address, deny->bits))
        continue;
    } else if (deny->hostmask && match(deny->hostmask, host))
      continue;

    if (EmptyString(deny->message))
      send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
                 ":Connection from your host is refused on this server.");
    else {
      if (deny->flags & DENY_FLAGS_FILE)
        killcomment(cptr, deny->message);
      else
        send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s.", deny->message);
    }
    return -1;
  }

  if (!feature_bool(FEAT_DISABLE_GLINES) && (agline = gline_lookup(cptr, 0))) {
    /*
     * find active glines
     * added a check against the user's IP address to find_gline() -Kev
     */
    send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s.", GlineReason(agline));
    return -2;
  }

  return 0;
}

/** Attempt to attach Client blocks to \a cptr.  If attach_iline()
 * fails for the client, emit a debugging message.
 * @param cptr Client to check for access.
 * @return Access check result.
 */
enum AuthorizationCheckResult conf_check_client(struct Client *cptr)
{
  enum AuthorizationCheckResult acr = ACR_OK;

  if ((acr = attach_iline(cptr))) {
    Debug((DEBUG_DNS, "ch_cl: access denied: %s[%s]", 
          cli_name(cptr), cli_sockhost(cptr)));
    return acr;
  }
  return ACR_OK;
}

/** Check access for a server given its name (passed in cptr struct).
 * Must check for all C/N lines which have a name which matches the
 * name given and a host which matches. A host alias which is the
 * same as the server name is also acceptable in the host field of a
 * C/N line.
 * @param cptr Peer server to check.
 * @return 0 if accepted, -1 if access denied.
 */
int conf_check_server(struct Client *cptr)
{
  struct ConfItem* c_conf = NULL;
  struct SLink*    lp;

  Debug((DEBUG_DNS, "sv_cl: check access for %s[%s]", 
        cli_name(cptr), cli_sockhost(cptr)));

  if (IsUnknown(cptr) && !attach_confs_byname(cptr, cli_name(cptr), CONF_SERVER)) {
    Debug((DEBUG_DNS, "No C/N lines for %s", cli_sockhost(cptr)));
    return -1;
  }
  lp = cli_confs(cptr);
  /*
   * We initiated this connection so the client should have a C and N
   * line already attached after passing through the connect_server()
   * function earlier.
   */
  if (IsConnecting(cptr) || IsHandshake(cptr)) {
    c_conf = find_conf_byname(lp, cli_name(cptr), CONF_SERVER);
    if (!c_conf) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Connect Error: lost Connect block for %s",
                           cli_name(cptr));
      det_confs_butmask(cptr, 0);
      return -1;
    }
  }

  /* Try finding the Connect block by DNS name and IP next. */
  if (!c_conf && !(c_conf = find_conf_byhost(lp, cli_sockhost(cptr), CONF_SERVER)))
        c_conf = find_conf_byip(lp, &cli_ip(cptr), CONF_SERVER);

  /*
   * Attach by IP# only if all other checks have failed.
   * It is quite possible to get here with the strange things that can
   * happen when using DNS in the way the irc server does. -avalon
   */
  if (!c_conf)
    c_conf = find_conf_byip(lp, &cli_ip(cptr), CONF_SERVER);
  /*
   * detach all conf lines that got attached by attach_confs()
   */
  det_confs_butmask(cptr, 0);
  /*
   * if no Connect block, then deny access
   */
  if (!c_conf) {
    Debug((DEBUG_DNS, "sv_cl: access denied: %s[%s@%s]",
          cli_name(cptr), cli_username(cptr), cli_sockhost(cptr)));
    return -1;
  }
  /*
   * attach the Connect block to the client structure for later use.
   */
  attach_conf(cptr, c_conf);

  if (!irc_in_addr_valid(&c_conf->address.addr))
    memcpy(&c_conf->address.addr, &cli_ip(cptr), sizeof(c_conf->address.addr));

  Debug((DEBUG_DNS, "sv_cl: access ok: %s[%s]",
         cli_name(cptr), cli_sockhost(cptr)));
  return 0;
}

