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
 *
 * $Id$
 */
#include "s_conf.h"

#include "IPcheck.h"
#include "class.h"
#include "client.h"
#include "crule.h"
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
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "sprintf_irc.h"
#include "struct.h"
#include "support.h"
#include "sys.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

struct ConfItem* GlobalConfList  = 0;
int              GlobalConfCount = 0;
struct MotdItem* motd = NULL;
struct MotdItem* rmotd = NULL;
struct TRecord*  tdata = NULL;
struct tm        motd_tm;


/*
 * output the reason for being k lined from a file  - Mmmm
 * sptr is server
 * parv is the sender prefix
 * filename is the file that is to be output to the K lined client
 */
static void killcomment(struct Client *sptr, char *parv, char *filename)
{
  FBFILE*     file = NULL;
  char        line[80];
  char*       tmp = NULL;
  struct stat sb;
  struct tm*  tm;

  if (NULL == (file = fbopen(filename, "r"))) {
    send_reply(sptr, ERR_NOMOTD);
    send_reply(sptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
	       ":Connection from your host is refused on this server.");
    return;
  }
  fbstat(&sb, file);
  tm = localtime((time_t*) &sb.st_mtime);        /* NetBSD needs cast */
  while (fbgets(line, sizeof(line) - 1, file)) {
    if ((tmp = strchr(line, '\n')))
      *tmp = '\0';
    if ((tmp = strchr(line, '\r')))
      *tmp = '\0';
    send_reply(sptr, RPL_MOTD, line);
  }
  send_reply(sptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
	     ":Connection from your host is refused on this server.");
  fbclose(file);
}

struct ConfItem* make_conf(void)
{
  struct ConfItem* aconf;

  aconf = (struct ConfItem*) MyMalloc(sizeof(struct ConfItem));
  assert(0 != aconf);
#ifdef        DEBUGMODE
  ++GlobalConfCount;
#endif
  aconf->status       = CONF_ILLEGAL;
  aconf->clients      = 0;
  aconf->ipnum.s_addr = INADDR_NONE;
  aconf->host         = 0;
  aconf->passwd       = 0;
  aconf->name         = 0;
  aconf->port         = 0;
  aconf->hold         = 0;
  aconf->dns_pending  = 0;
  aconf->confClass    = 0;
  aconf->next         = 0;
  return aconf;
}

void delist_conf(struct ConfItem *aconf)
{
  if (aconf == GlobalConfList)
    GlobalConfList = GlobalConfList->next;
  else {
    struct ConfItem *bconf;

    for (bconf = GlobalConfList; aconf != bconf->next; bconf = bconf->next)
      ;
    bconf->next = aconf->next;
  }
  aconf->next = NULL;
}

void free_conf(struct ConfItem *aconf)
{
  Debug((DEBUG_DEBUG, "free_conf: %s %s %d",
         aconf->host ? aconf->host : "*",
         aconf->name ? aconf->name : "*",
         aconf->port));
  if (aconf->dns_pending)
    delete_resolver_queries(aconf);
  MyFree(aconf->host);
  if (aconf->passwd)
    memset(aconf->passwd, 0, strlen(aconf->passwd));
  MyFree(aconf->passwd);
  MyFree(aconf->name);
  MyFree(aconf);
#ifdef        DEBUGMODE
  --GlobalConfCount;
#endif
}

/*
 * conf_dns_callback - called when resolver query finishes
 * if the query resulted in a successful search, hp will contain
 * a non-null pointer, otherwise hp will be null.
 * if successful save hp in the conf item it was called with
 */
static void conf_dns_callback(void* vptr, struct DNSReply* reply)
{
  struct ConfItem* aconf = (struct ConfItem*) vptr;
  aconf->dns_pending = 0;
  if (reply)
    memcpy(&aconf->ipnum, reply->hp->h_addr, sizeof(struct in_addr));
}

/*
 * conf_dns_lookup - do a nameserver lookup of the conf host
 * if the conf entry is currently doing a ns lookup do nothing, otherwise
 * if the lookup returns a null pointer, set the conf dns_pending flag
 */
static struct DNSReply* conf_dns_lookup(struct ConfItem* aconf)
{
  struct DNSReply* dns_reply = 0;
  if (!aconf->dns_pending) {
    char            buf[HOSTLEN + 1];
    struct DNSQuery query;
    query.vptr     = aconf;
    query.callback = conf_dns_callback;
    host_from_uh(buf, aconf->host, HOSTLEN);
    buf[HOSTLEN] = '\0';

    if (0 == (dns_reply = gethost_byname(buf, &query)))
      aconf->dns_pending = 1;
  }
  return dns_reply;
}


/*
 * lookup_confhost
 *
 * Do (start) DNS lookups of all hostnames in the conf line and convert
 * an IP addresses in a.b.c.d number for to IP#s.
 */
static void lookup_confhost(struct ConfItem *aconf)
{
  struct DNSReply* reply;

  if (EmptyString(aconf->host) || EmptyString(aconf->name)) {
    Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
           aconf->host, aconf->name));
    return;
  }
  /*
   * Do name lookup now on hostnames given and store the
   * ip numbers in conf structure.
   */
  if (IsDigit(*aconf->host)) {
    /*
     * rfc 1035 sez host names may not start with a digit
     * XXX - this has changed code needs to be updated
     */
    aconf->ipnum.s_addr = inet_addr(aconf->host);
    if (INADDR_NONE == aconf->ipnum.s_addr) {
      Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
            aconf->host, aconf->name));
    }
  }
  else if ((reply = conf_dns_lookup(aconf)))
    memcpy(&aconf->ipnum, reply->hp->h_addr, sizeof(struct in_addr));
}

/*
 * conf_find_server - find a server by name or hostname
 * returns a server conf item pointer if found, 0 otherwise
 *
 * NOTE: at some point when we don't have to scan the entire
 * list it may be cheaper to look for server names and host
 * names in separate loops (original code did it that way)
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

/*
 * conf_eval_crule - evaluate connection rules
 * returns the name of the rule triggered if found, 0 otherwise
 *
 * Evaluate connection rules...  If no rules found, allow the
 * connect.   Otherwise stop with the first true rule (ie: rules
 * are ored together.  Oper connects are effected only by D
 * lines (CRULEALL) not d lines (CRULEAUTO).
 */
const char* conf_eval_crule(struct ConfItem* conf)
{
  struct ConfItem* rule;
  assert(0 != conf);

  for (rule = GlobalConfList; rule; rule = rule->next) {
    if ((CONF_CRULEALL == rule->status) && (0 == match(rule->host, conf->name))) {
      if (crule_eval(rule->passwd))
        return rule->name;
    }
  }
  return 0;
}


/*
 * field breakup for ircd.conf file.
 */
static char* getfield(char* newline, char fs)
{
  static char* gfline = NULL;
  char*        end;
  char*        field;

  if (newline)
    gfline = newline;

  if (gfline == NULL)
    return NULL;

  end = field = gfline;

  if (fs != ':') {
    if (*end == fs)
      ++end;
    else
      fs = ':';
  }
  do {
    while (*end != fs) {
      if (!*end) {
        end = NULL;
        break;
      }
      ++end;
    }
  } while (end && fs != ':' && *++end != ':' && *end != '\n') ;

  if (end == NULL) {
    gfline = NULL;
    if ((end = strchr(field, '\n')) == NULL)
      end = field + strlen(field);
  }
  else
    gfline = end + 1;

  *end = '\0';

  return field;
}

/*
 * Remove all conf entries from the client except those which match
 * the status field mask.
 */
void det_confs_butmask(struct Client *cptr, int mask)
{
  struct SLink *tmp, *tmp2;

  for (tmp = cptr->confs; tmp; tmp = tmp2) {
    tmp2 = tmp->next;
    if ((tmp->value.aconf->status & mask) == 0)
      detach_conf(cptr, tmp->value.aconf);
  }
}

/*
 * validate_hostent - make sure hostnames are valid in a hostent struct
 * XXX - this is terrible, what's worse is it used to be in the inner
 * loop of scanning all the I:lines --Bleep
 */
static int validate_hostent(struct hostent* hp)
{
  char        fullname[HOSTLEN + 1];
  int         i     = 0;
  int         error = 0;
  const char* hname;

  for (hname = hp->h_name; hname; hname = hp->h_aliases[i++]) {
    unsigned int fullnamelen = 0;
    unsigned int label_count = 0;

    ircd_strncpy(fullname, hname, HOSTLEN);
    fullname[HOSTLEN] = '\0';
    /*
     * Disallow a hostname label to contain anything but a [-a-zA-Z0-9].
     * It may not start or end on a '.'.
     * A label may not end on a '-', the maximum length of a label is
     * 63 characters.
     * On top of that (which seems to be the RFC) we demand that the
     * top domain does not contain any digits.
     */
    error = (*hname == '.') ? 1 : 0;        /* May not start with a '.' */
    if (!error) {
      char *p;
      for (p = fullname; *p; ++p, ++fullnamelen) {
        if (*p == '.') { 
          /* Label may not end on '-' and May not end on a '.' */
          if (p[-1] == '-' || p[1] == 0) {
            error = 1;
            break;
          }
          label_count = 0;
          error = 0;        /* Was not top domain */
          continue;
        }
        if (++label_count > 63) {
          /* Label not longer then 63 */
          error = 1;
          break;
        }
        if (*p >= '0' && *p <= '9') {
          /* In case this is top domain */
          error = 1;
          continue;
        }
        if (!(*p >= 'a' && *p <= 'z')
            && !(*p >= 'A' && *p <= 'Z') && *p != '-') {
          error = 1;
          break;
        }
      }
    }
    if (error)
      break;
  }
  return (0 == error);
}

/*
 * check_limit_and_attach - check client limits and attach I:line
 *
 * Made it accept 1 charactor, and 2 charactor limits (0->99 now), 
 * and dislallow more than 255 people here as well as in ipcheck.
 * removed the old "ONE" scheme too.
 *  -- Isomer 2000-06-22
 */
static enum AuthorizationCheckResult
check_limit_and_attach(struct Client* cptr, struct ConfItem* aconf)
{
  int number = 255;
  
  if (aconf->passwd) {
    if (IsDigit(*aconf->passwd) && !aconf->passwd[1])
      number = *aconf->passwd-'0';
    else if (IsDigit(*aconf->passwd) && IsDigit(aconf->passwd[1]) && 
             !aconf->passwd[2])
      number = (*aconf->passwd-'0')*10+(aconf->passwd[1]-'0');
  }
  if (ip_registry_count(cptr->ip.s_addr) > number)
    return ACR_TOO_MANY_FROM_IP;
  return attach_conf(cptr, aconf);
}

/*
 * Find the first (best) I line to attach.
 */
enum AuthorizationCheckResult attach_iline(struct Client*  cptr)
{
  struct ConfItem* aconf;
  const char*      hname;
  int              i;
  static char      uhost[HOSTLEN + USERLEN + 3];
  static char      fullname[HOSTLEN + 1];
  struct hostent*  hp = 0;

  if (cptr->dns_reply) {
    hp = cptr->dns_reply->hp;
    if (!validate_hostent(hp))
      hp = 0;
  }
  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (aconf->status != CONF_CLIENT)
      continue;
    if (aconf->port && aconf->port != cptr->listener->port)
      continue;
    if (!aconf->host || !aconf->name)
      continue;
    if (hp) {
      for (i = 0, hname = hp->h_name; hname; hname = hp->h_aliases[i++]) {
        ircd_strncpy(fullname, hname, HOSTLEN);
        fullname[HOSTLEN] = '\0';

        Debug((DEBUG_DNS, "a_il: %s->%s", cptr->sockhost, fullname));

        if (strchr(aconf->name, '@')) {
          strcpy(uhost, cptr->username);
          strcat(uhost, "@");
        }
        else
          *uhost = '\0';
        strncat(uhost, fullname, sizeof(uhost) - 1 - strlen(uhost));
        uhost[sizeof(uhost) - 1] = 0;
        if (0 == match(aconf->name, uhost)) {
          if (strchr(uhost, '@'))
            cptr->flags |= FLAGS_DOID;
          return check_limit_and_attach(cptr, aconf);
        }
      }
    }
    if (strchr(aconf->host, '@')) {
      ircd_strncpy(uhost, cptr->username, sizeof(uhost) - 2);
      uhost[sizeof(uhost) - 2] = 0;
      strcat(uhost, "@");
    }
    else
      *uhost = '\0';
    strncat(uhost, cptr->sock_ip, sizeof(uhost) - 1 - strlen(uhost));
    uhost[sizeof(uhost) - 1] = 0;
    if (match(aconf->host, uhost))
      continue;
    if (strchr(uhost, '@'))
      cptr->flags |= FLAGS_DOID;

    return check_limit_and_attach(cptr, aconf);
  }
  return ACR_NO_AUTHORIZATION;
}

/*
 * detach_conf - Disassociate configuration from the client.
 */
int detach_conf(struct Client *cptr, struct ConfItem *aconf)
{
  struct SLink** lp;
  struct SLink*  tmp;

  assert(0 != aconf);
  assert(0 != cptr);
  assert(0 < aconf->clients);

  lp = &(cptr->confs);

  while (*lp) {
    if ((*lp)->value.aconf == aconf) {
      if (aconf->confClass && (aconf->status & CONF_CLIENT_MASK) && 
          ConfLinks(aconf) > 0)
        --ConfLinks(aconf);
      if (0 == --aconf->clients && IsIllegal(aconf))
        free_conf(aconf);
      tmp = *lp;
      *lp = tmp->next;
      free_link(tmp);
      return 0;
    }
    else
      lp = &((*lp)->next);
  }
  return -1;
}

static int is_attached(struct ConfItem *aconf, struct Client *cptr)
{
  struct SLink *lp;

  for (lp = cptr->confs; lp; lp = lp->next)
    if (lp->value.aconf == aconf)
      break;

  return (lp) ? 1 : 0;
}

/*
 * attach_conf
 *
 * Associate a specific configuration entry to a *local*
 * client (this is the one which used in accepting the
 * connection). Note, that this automaticly changes the
 * attachment if there was an old one...
 */
enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf)
{
  struct SLink *lp;

  if (is_attached(aconf, cptr))
    return ACR_ALREADY_AUTHORIZED;
  if (IsIllegal(aconf))
    return ACR_NO_AUTHORIZATION;
  if ((aconf->status & (CONF_LOCOP | CONF_OPERATOR | CONF_CLIENT)) &&
      ConfLinks(aconf) >= ConfMaxLinks(aconf) && ConfMaxLinks(aconf) > 0)
    return ACR_TOO_MANY_IN_CLASS;  /* Use this for printing error message */
  lp = make_link();
  lp->next = cptr->confs;
  lp->value.aconf = aconf;
  cptr->confs = lp;
  ++aconf->clients;
  if (aconf->status & CONF_CLIENT_MASK)
    ConfLinks(aconf)++;
  return ACR_OK;
}

struct ConfItem *find_admin(void)
{
  struct ConfItem *aconf;

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (aconf->status & CONF_ADMIN)
      break;
  }
  return aconf;
}

struct ConfItem* find_me(void)
{
  struct ConfItem* aconf;
  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (aconf->status & CONF_ME)
      break;
  }
  return aconf;
}

/*
 * attach_confs_byname
 *
 * Attach a CONF line to a client if the name passed matches that for
 * the conf file (for non-C/N lines) or is an exact match (C/N lines
 * only).  The difference in behaviour is to stop C:*::* and N:*::*.
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

/*
 * Added for new access check    meLazy
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

/*
 * find a conf entry which matches the hostname and has the same name.
 */
struct ConfItem* find_conf_exact(const char* name, const char* user,
                                 const char* host, int statmask)
{
  struct ConfItem *tmp;
  char userhost[USERLEN + HOSTLEN + 3];

  if (user)
    ircd_snprintf(0, userhost, sizeof(userhost), "%s@%s", user, host);
  else
    ircd_strncpy(userhost, host, sizeof(userhost) - 1);

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (!(tmp->status & statmask) || !tmp->name || !tmp->host ||
        0 != ircd_strcmp(tmp->name, name))
      continue;
    /*
     * Accept if the *real* hostname (usually sockecthost)
     * socket host) matches *either* host or name field
     * of the configuration.
     */
    if (match(tmp->host, userhost))
      continue;
    if (tmp->status & (CONF_OPERATOR | CONF_LOCOP)) {
      if (tmp->clients < MaxLinks(tmp->confClass))
        return tmp;
      else
        continue;
    }
    else
      return tmp;
  }
  return 0;
}

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

/*
 * Added for new access check    meLazy
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

/*
 * find_conf_ip
 *
 * Find a conf line using the IP# stored in it to search upon.
 * Added 1/8/92 by Avalon.
 */
struct ConfItem* find_conf_byip(struct SLink* lp, const char* ip, 
                                int statmask)
{
  struct ConfItem* tmp;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)) {
      if (0 == memcmp(&tmp->ipnum, ip, sizeof(struct in_addr)))
        return tmp;
    }
  }
  return 0;
}

/*
 * find_conf_entry
 *
 * - looks for a match on all given fields.
 */
static struct ConfItem *find_conf_entry(struct ConfItem *aconf,
                                        unsigned int mask)
{
  struct ConfItem *bconf;
  assert(0 != aconf);

  mask &= ~CONF_ILLEGAL;

  for (bconf = GlobalConfList; bconf; bconf = bconf->next) {
    if (!(bconf->status & mask) || (bconf->port != aconf->port))
      continue;

    if ((EmptyString(bconf->host) && !EmptyString(aconf->host)) ||
        (EmptyString(aconf->host) && !EmptyString(bconf->host)))
      continue;
    if (!EmptyString(bconf->host) && 0 != ircd_strcmp(bconf->host, aconf->host))
      continue;

    if ((EmptyString(bconf->passwd) && !EmptyString(aconf->passwd)) ||
        (EmptyString(aconf->passwd) && !EmptyString(bconf->passwd)))
      continue;
    if (!EmptyString(bconf->passwd) && (!IsDigit(*bconf->passwd) || bconf->passwd[1])
#ifdef USEONE
        && 0 != ircd_strcmp(bconf->passwd, "ONE")
#endif
        && 0 != ircd_strcmp(bconf->passwd, aconf->passwd))
      continue;

    if ((EmptyString(bconf->name) && !EmptyString(aconf->name)) ||
        (EmptyString(aconf->name) && !EmptyString(bconf->name)))
      continue;
    if (!EmptyString(bconf->name) && 0 != ircd_strcmp(bconf->name, aconf->name))
      continue;
    break;
  }
  return bconf;
}

/*
 * rehash
 *
 * Actual REHASH service routine. Called with sig == 0 if it has been called
 * as a result of an operator issuing this command, else assume it has been
 * called as a result of the server receiving a HUP signal.
 */
int rehash(struct Client *cptr, int sig)
{
  struct ConfItem** tmp = &GlobalConfList;
  struct ConfItem*  tmp2;
  struct ConfClass* cltmp;
  struct Client*    acptr;
  struct MotdItem*  temp;
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
      if (!(tmp2->status & CONF_CLIENT)) {
        *tmp = tmp2->next;
        tmp2->next = 0;
      }
      else
        tmp = &tmp2->next;
      tmp2->status |= CONF_ILLEGAL;
    }
    else {
      *tmp = tmp2->next;
      /* free expression trees of connect rules */
      if ((tmp2->status & (CONF_CRULEALL | CONF_CRULEAUTO)) &&
          (tmp2->passwd != NULL))
        crule_free(&(tmp2->passwd));
      free_conf(tmp2);
    }
  }

  /*
   * We don't delete the class table, rather mark all entries
   * for deletion. The table is cleaned up by check_class(). - avalon
   */
  for (cltmp = NextClass(FirstClass()); cltmp; cltmp = NextClass(cltmp))
    MarkDelete(cltmp);

  /*
   * delete the juped nicks list
   */
  clearNickJupes();

  if (sig != 2)
    flush_resolver_cache();

  mark_listeners_closing();

  if (!conf_init())        /* This calls check_class(), */
    check_class();         /* unless it fails */

  /*
   * make sure that the server listener is re-added so it doesn't get
   * closed
   */
  close_listeners();

  /*
   * Flush out deleted I and P lines although still in use.
   */
  for (tmp = &GlobalConfList; (tmp2 = *tmp);) {
    if (!(tmp2->status & CONF_ILLEGAL))
      tmp = &tmp2->next;
    else
    {
      *tmp = tmp2->next;
      tmp2->next = NULL;
      if (!tmp2->clients)
        free_conf(tmp2);
    }
  }
  for (i = 0; i <= HighestFd; i++) {
    if ((acptr = LocalClientArray[i])) {
      assert(!IsMe(acptr));
      if (IsServer(acptr)) {
        det_confs_butmask(acptr,
            ~(CONF_HUB | CONF_LEAF | CONF_UWORLD | CONF_ILLEGAL));
        attach_confs_byname(acptr, acptr->name,
                            CONF_HUB | CONF_LEAF | CONF_UWORLD);
      }
      /* Because admin's are getting so uppity about people managing to
       * get past K/G's etc, we'll "fix" the bug by actually explaining
       * whats going on.
       */
      if ((found_g = find_kill(acptr))) {
        sendto_opmask_butone(0, found_g == -2 ? SNO_GLINE : SNO_OPERKILL,
			     found_g == -2 ? "G-line active for %s%s" :
			     "K-line active for %s%s",
			     IsUnknown(acptr) ? "Unregistered Client ":"",		     
			     get_client_name(acptr, HIDE_IP));
        if (exit_client(cptr, acptr, &me, found_g == -2 ? "G-lined" :
            "K-lined") == CPTR_KILLED)
          ret = CPTR_KILLED;
      }
    }
  }
  /* 
   * free old motd structs
   */
  while (motd) {
    temp = motd->next;
    MyFree(motd);
    motd = temp;
  }
  while (rmotd) {
    temp = rmotd->next;
    MyFree(rmotd);
    rmotd = temp;
  }
  /* reload motd files */
  read_tlines();
  rmotd = read_motd(RPATH);
  motd = read_motd(MPATH);
  return ret;
}


/*
 * If conf line is a class definition, create a class entry
 * for it and make the conf_line illegal and delete it.
 */
void conf_create_class(const char* const* fields, int count)
{
  if (count < 6)
    return;
  add_class(atoi(fields[1]), atoi(fields[2]), atoi(fields[3]),
            atoi(fields[4]), atoi(fields[5]));
}

/*
 * conf_init
 *
 * Read configuration file.
 *
 * returns 0, if file cannot be opened
 *         1, if file read
 */

#define MAXCONFLINKS 150


int conf_init(void)
{
  enum { MAX_FIELDS = 15 };

  char* src;
  char* dest;
  int quoted;
  FBFILE *file;
  char line[512];
  int ccount = 0;
  struct ConfItem *aconf = 0;
  
  int   field_count = 0;
  const char* field_vector[MAX_FIELDS + 1];

  Debug((DEBUG_DEBUG, "conf_init: ircd.conf = %s", configfile));
  if (0 == (file = fbopen(configfile, "r"))) {
    return 0;
  }

  while (fbgets(line, sizeof(line) - 1, file)) {
    if ('#' == *line || IsSpace(*line))
      continue;

    if ((src = strchr(line, '\n')))
      *src = '\0';
    
    if (':' != line[1]) {
      Debug((DEBUG_ERROR, "Bad config line: %s", line));
      sendto_op_mask(SNO_OLDSNO,"Bad Config line");
      continue;
    }

    /*
     * do escapes, quoting, comments, and field breakup in place
     * in one pass with a poor mans state machine
     */
    field_vector[0] = line;
    field_count = 1;
    quoted = 0;

    for (src = line, dest = line; *src; ) {
      switch (*src) {
      case '\\':
        ++src;
        switch (*src) {
        case 'b':
          *dest++ = '\b';
          ++src;
          break;
        case 'f':
          *dest++ = '\f';
          ++src;
          break;
        case 'n':
          *dest++ = '\n';
          ++src;
          break;
        case 'r':
          *dest++ = '\r';      
          ++src;
          break;
        case 't':
          *dest++ = '\t';
          ++src;
          break;
        case 'v':
          *dest++ = '\v';
          ++src;
          break;
        case '\\':
          *dest++ = '\\';
          ++src;
          break;
        case '\0':
          break;
        default:
          *dest++ = *src++;
          break;
        }
        break;
      case '"':
        if (quoted)
          quoted = 0;
        else
          quoted = 1;
        *dest++ = *src++;
        break;
      case ':':
        if (quoted)
          *dest++ = *src++;
        else {
          *dest++ = '\0';
          field_vector[field_count++] = dest;
          if (field_count > MAX_FIELDS)
            *src = '\0';
          else  
            ++src;
        }
        break;
      case '#':
        *src = '\0';
        break;
      default:
        *dest++ = *src++;
        break;
      }
    }
    *dest = '\0';

    if (field_count < 3 || EmptyString(field_vector[0]))
      continue;

    if (aconf)
      free_conf(aconf);

    aconf = make_conf();

    switch (*field_vector[0]) {
    case 'A':                /* Name, e-mail address of administrator */
    case 'a':                /* of this server. */
      aconf->status = CONF_ADMIN;
      break;
    case 'C':                /* Server where I should try to connect */
    case 'c':                /* in case of lp failures             */
      ++ccount;
      aconf->status = CONF_SERVER;
      break;
      /* Connect rule */
    case 'D':
      aconf->status = CONF_CRULEALL;
      break;
      /* Connect rule - autos only */
    case 'd':
      aconf->status = CONF_CRULEAUTO;
      break;
    case 'H':                /* Hub server line */
    case 'h':
      aconf->status = CONF_HUB;
      break;
    case 'I':                /* Just plain normal irc client trying  */
    case 'i':                /* to connect me */
      aconf->status = CONF_CLIENT;
      break;
    case 'K':                /* Kill user line on irc.conf           */
      aconf->status = CONF_KILL;
      break;
    case 'k':                /* Kill user line based on IP in ircd.conf */
      aconf->status = CONF_IPKILL;
      break;
      /* Operator. Line should contain at least */
      /* password and host where connection is  */
    case 'L':                /* guaranteed leaf server */
    case 'l':
      aconf->status = CONF_LEAF;
      break;
      /* Me. Host field is name used for this host */
      /* and port number is the number of the port */
    case 'M':
    case 'm':
      aconf->status = CONF_ME;
      break;
    case 'O':
      aconf->status = CONF_OPERATOR;
      break;
      /* Local Operator, (limited privs --SRB) */
    case 'o':
      aconf->status = CONF_LOCOP;
      break;
    case 'P':                /* listen port line */
    case 'p':
      aconf->status = CONF_LISTEN_PORT;
      break;
    case 'T':                /* print out different motd's */
    case 't':                /* based on hostmask */
      aconf->status = CONF_TLINES;
      break;
    case 'U':      /* Underworld server, allowed to hack modes */
    case 'u':      /* *Every* server on the net must define the same !!! */
      aconf->status = CONF_UWORLD;
      break;
    case 'Y':
    case 'y':      /* CONF_CLASS */
      conf_create_class(field_vector, field_count);
      aconf->status = CONF_ILLEGAL;
      break;
    default:
      Debug((DEBUG_ERROR, "Error in config file: %s", line));
      sendto_op_mask(SNO_OLDSNO,"Unknown prefix in config file: %c", *field_vector[0]);
      aconf->status = CONF_ILLEGAL;
      break;
    }
    if (IsIllegal(aconf))
      continue;

    if (!EmptyString(field_vector[1]))
      DupString(aconf->host, field_vector[1]);

    if (!EmptyString(field_vector[2]))
      DupString(aconf->passwd, field_vector[2]);

    if (field_count > 3 && !EmptyString(field_vector[3]))
        DupString(aconf->name, field_vector[3]);

    if (field_count > 4 && !EmptyString(field_vector[4]))
        aconf->port = atoi(field_vector[4]); 

    if (field_count > 5 && !EmptyString(field_vector[5])) {
      int n = atoi(field_vector[5]);
      if (CONF_ME == (aconf->status & CONF_ME))
        SetYXXServerName(&me, n);        /* Our Numeric Nick */
      else
        aconf->confClass = find_class(n);
    }
    else if (CONF_ME == (aconf->status & CONF_ME)) {
      Debug((DEBUG_FATAL, "Your M: line must have the Numeric, "
             "assigned to you by routing-com!\n"));
      ircd_log(L_WARNING, "Your M: line must have the Numeric, "
              "assigned to you by routing-com!\n");
      exit(-1);
    }
    /*
     * Associate each conf line with a class by using a pointer
     * to the correct class record. -avalon
     */
    if (aconf->status & CONF_CLIENT_MASK) {
      if (aconf->confClass == 0)
        aconf->confClass = find_class(0);
    }
    if (aconf->status & CONF_LISTEN_PORT) {
      int         is_server = 0;
      int         is_hidden = 0;
      if (!EmptyString(aconf->name)) {
        const char* x = aconf->name;
        if ('S' == ToUpper(*x))
          is_server = 1;
        ++x;
        if ('H' == ToUpper(*x))
          is_hidden = 1;
      }
      add_listener(aconf->port, aconf->passwd, aconf->host, 
                   is_server, is_hidden);
      continue;
    } 
    if (aconf->status & CONF_CLIENT) {
      struct ConfItem *bconf;

      if ((bconf = find_conf_entry(aconf, aconf->status))) {
        delist_conf(bconf);
        bconf->status &= ~CONF_ILLEGAL;
        if (aconf->status == CONF_CLIENT) {
          /*
           * copy the password field in case it changed
           */
          MyFree(bconf->passwd);
          bconf->passwd = aconf->passwd;
          aconf->passwd = 0;

          ConfLinks(bconf) -= bconf->clients;
          bconf->confClass = aconf->confClass;
          if (bconf->confClass)
            ConfLinks(bconf) += bconf->clients;
        }
        free_conf(aconf);
        aconf = bconf;
      }
    }
    if (aconf->status & CONF_SERVER) {
      if (ccount > MAXCONFLINKS || !aconf->host || strchr(aconf->host, '*') ||
          strchr(aconf->host, '?') || !aconf->name)
        continue;
    }
    if (aconf->status & (CONF_LOCOP | CONF_OPERATOR)) {
      if (!strchr(aconf->host, '@')) {
        char* newhost;
        int len = 3;                /* *@\0 = 3 */

        len += strlen(aconf->host);
        newhost = (char*) MyMalloc(len);
        assert(0 != newhost);
	ircd_snprintf(0, newhost, len, "*@%s", aconf->host);
        MyFree(aconf->host);
        aconf->host = newhost;
      }
    }
    if (aconf->status & CONF_SERVER) {
      if (EmptyString(aconf->passwd))
        continue;
      lookup_confhost(aconf);
    }

    /* Create expression tree from connect rule...
     * If there's a parsing error, nuke the conf structure */
    if (aconf->status & (CONF_CRULEALL | CONF_CRULEAUTO)) {
      MyFree(aconf->passwd);
      if ((aconf->passwd = (char *)crule_parse(aconf->name)) == NULL) {
        free_conf(aconf);
        aconf = NULL;
        continue;
      }
    }

    /*
     * Own port and name cannot be changed after the startup.
     * (or could be allowed, but only if all links are closed first).
     * Configuration info does not override the name and port
     * if previously defined. Note, that "info"-field can be
     * changed by "/rehash".
     */
    if (aconf->status == CONF_ME) {
      ircd_strncpy(me.info, aconf->name, REALLEN);
    }
    
    if (aconf->status == CONF_IPKILL) {
      /* 
       * Here we use the same kludge as in listener.c to parse
       * a.b.c.d, or a.b.c.*, or a.b.c.d/e.
       */
      int class;
      char ipname[16];
      int ad[4] = { 0 };
      int bits2=0;
      class=sscanf(aconf->host,"%d.%d.%d.%d/%d",
                   &ad[0], &ad[1], &ad[2], &ad[3], &bits2);
      if (class!=5) {
        aconf->bits=class*8;
      }
      else {
        aconf->bits=bits2;
      }
      sprintf_irc(ipname,"%d.%d.%d.%d",ad[0], ad[1], ad[2], ad[3]);
      
      /* This ensures endian correctness */
      aconf->ipnum.s_addr = inet_addr(ipname);
      Debug((DEBUG_DEBUG,"IPkill: %s = %08x/%i (%08x)",ipname,
      	aconf->ipnum.s_addr,aconf->bits,NETMASK(aconf->bits)));
    }

    /*
     * Juped nicks are listed in the 'password' field of U:lines,
     * the list is comma separated and might be empty and/or contain
     * empty elements... the only limit is that it MUST be shorter
     * than 512 chars, or they will be cutted out :)
     */
    if ((aconf->status == CONF_UWORLD) && (aconf->passwd) && (*aconf->passwd))
      addNickJupes(aconf->passwd);

    if (aconf->status & CONF_ADMIN) {
      if (!aconf->host || !aconf->passwd || !aconf->name) {
        Debug((DEBUG_FATAL, "Your A: line must have 4 fields!\n"));
        ircd_log(L_WARNING, "Your A: line must have 4 fields!\n");
        exit(-1);
      }
    }
    collapse(aconf->host);
    collapse(aconf->name);
    Debug((DEBUG_NOTICE,
        "Read Init: (%d) (%s) (%s) (%s) (%u) (%p)",
        aconf->status, aconf->host, aconf->passwd,
        aconf->name, aconf->port, aconf->confClass));
    aconf->next = GlobalConfList;
    GlobalConfList = aconf;
    aconf = NULL;
  }
  if (aconf)
    free_conf(aconf);
  fbclose(file);
  check_class();
  nextping = nextconnect = CurrentTime;
  return 1;
}


/* read_tlines 
 * Read info from T:lines into TRecords which include the file 
 * timestamp, the hostmask, and the contents of the motd file 
 * -Ghostwolf 7sep97
 */
void read_tlines()
{
  struct ConfItem *tmp;
  struct TRecord *temp;
  struct TRecord *last = NULL;        /* Init. to avoid compiler warning */
  struct MotdItem *amotd;

  /* Free the old trecords and the associated motd contents first */
  while (tdata)
  {
    last = tdata->next;
    while (tdata->tmotd)
    {
      amotd = tdata->tmotd->next;
      MyFree(tdata->tmotd);
      tdata->tmotd = amotd;
    }
    MyFree(tdata);
    tdata = last;
  }

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (tmp->status == CONF_TLINES && tmp->host && tmp->passwd) {
      temp = (struct TRecord*) MyMalloc(sizeof(struct TRecord));
      assert(0 != temp);

      temp->hostmask = tmp->host;
      temp->tmotd = read_motd(tmp->passwd);
      temp->tmotd_tm = motd_tm;
      temp->next = NULL;
      if (!tdata)
        tdata = temp;
      else
        last->next = temp;
      last = temp;
    }
  }
}

/*
 * find_kill
 * input:
 *  client pointer
 * returns:
 *  0: Client may continue to try and connect
 * -1: Client was K/k:'d - sideeffect: reason was sent.
 * -2: Client was G/g:'d - sideeffect: reason was sent.
 * sideeffects:
 *  Client may have been sent a reason why they are denied, as above.
 */
int find_kill(struct Client *cptr)
{
  const char*      host;
  const char*      name;
  struct ConfItem* tmp;
  struct Gline*    agline = NULL;

  assert(0 != cptr);

  if (!cptr->user)
    return 0;

  host = cptr->sockhost;
  name = cptr->user->username;

  assert(strlen(host) <= HOSTLEN);
  assert((name ? strlen(name) : 0) <= HOSTLEN);
  
  /* 2000-07-14: Rewrote this loop for massive speed increases.
   *             -- Isomer
   */
  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
  
    if ((tmp->status & CONF_KLINE) == 0)
    	continue;
    	
    /*
     * What is this for?  You can K: by port?!
     *   -- Isomer
     */
    if (tmp->port && tmp->port != cptr->listener->port)
    	continue;

    if (!tmp->name || match(tmp->name, name) != 0)
    	continue;
    	
    if (!tmp->host)
    	break;
    
    if (tmp->status != CONF_IPKILL) {
    	if (match(tmp->host, host) == 0)
    	  break;
    }
    else { /* k: by IP */
  	Debug((DEBUG_DEBUG, "ip: %08x network: %08x/%i mask: %08x",
  		cptr->ip.s_addr, tmp->ipnum.s_addr, tmp->bits, 
  		NETMASK(tmp->bits)));
    	if ((cptr->ip.s_addr & NETMASK(tmp->bits)) == tmp->ipnum.s_addr)
    		break;
    }
  }
  if (tmp) {
    if (EmptyString(tmp->passwd))
      send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
		 ":Connection from your host is refused on this server.");
    else {
      if (*tmp->passwd == '"') {
	send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%*s.",
		   strlen(tmp->passwd + 1) - 1, tmp->passwd + 1);
      }
      else if (*tmp->passwd == '!')
        killcomment(cptr, cptr->name, &tmp->passwd[1]);
      else
#ifdef COMMENT_IS_FILE
        killcomment(cptr, cptr->name, tmp->passwd);
#else
	send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s.",
		   tmp->passwd);
#endif
    }
  }

  /* find active glines */
  /* added a check against the user's IP address to find_gline() -Kev */
  else if ((agline = gline_lookup(cptr, 0)) && GlineIsActive(agline))
    send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s.",
	       GlineReason(agline));
  else
    agline = NULL;                /* if a gline was found, it was inactive */

  if (tmp)
    return -1;
  if (agline)
    return -2;
    
  return 0;
}

struct MotdItem* read_motd(const char* motdfile)
{
  FBFILE*          file = NULL;
  struct MotdItem* temp;
  struct MotdItem* newmotd;
  struct MotdItem* last;
  struct stat      sb;
  char             line[80];
  char*            tmp;

  if (NULL == (file = fbopen(motdfile, "r"))) {
    Debug((DEBUG_ERROR, "Couldn't open \"%s\": %s", motdfile, strerror(errno)));
    return NULL;
  }
  if (-1 == fbstat(&sb, file)) {
    fbclose(file);
    return NULL;
  }
  newmotd = last = NULL;
  motd_tm = *localtime((time_t *) & sb.st_mtime);        /* NetBSD needs cast */
  while (fbgets(line, sizeof(line) - 1, file)) {
    if ((tmp = (char *)strchr(line, '\n')))
      *tmp = '\0';
    if ((tmp = (char *)strchr(line, '\r')))
      *tmp = '\0';
    temp = (struct MotdItem*) MyMalloc(sizeof(struct MotdItem));
    assert(0 != temp);
    strcpy(temp->line, line);
    temp->next = NULL;
    if (!newmotd)
      newmotd = temp;
    else
      last->next = temp;
    last = temp;
  }
  fbclose(file);
  return newmotd;
}


/*
 * Ordinary client access check. Look for conf lines which have the same
 * status as the flags passed.
 */
enum AuthorizationCheckResult conf_check_client(struct Client *cptr)
{
  enum AuthorizationCheckResult acr = ACR_OK;

  ClearAccess(cptr);

  if ((acr = attach_iline(cptr))) {
    Debug((DEBUG_DNS, "ch_cl: access denied: %s[%s]", 
          cptr->name, cptr->sockhost));
    return acr;
  }
  return ACR_OK;
}

/*
 * check_server()
 *
 * Check access for a server given its name (passed in cptr struct).
 * Must check for all C/N lines which have a name which matches the
 * name given and a host which matches. A host alias which is the
 * same as the server name is also acceptable in the host field of a
 * C/N line.
 *
 * Returns
 *  0 = Success
 * -1 = Access denied
 * -2 = Bad socket.
 */
int conf_check_server(struct Client *cptr)
{
  struct ConfItem* c_conf = NULL;
  struct SLink*    lp;

  Debug((DEBUG_DNS, "sv_cl: check access for %s[%s]", 
        cptr->name, cptr->sockhost));

  if (IsUnknown(cptr) && !attach_confs_byname(cptr, cptr->name, CONF_SERVER)) {
    Debug((DEBUG_DNS, "No C/N lines for %s", cptr->sockhost));
    return -1;
  }
  lp = cptr->confs;
  /*
   * We initiated this connection so the client should have a C and N
   * line already attached after passing through the connect_server()
   * function earlier.
   */
  if (IsConnecting(cptr) || IsHandshake(cptr)) {
    c_conf = find_conf_byname(lp, cptr->name, CONF_SERVER);
    if (!c_conf) {
      sendto_opmask_butone(0, SNO_OLDSNO, "Connect Error: lost C:line for %s",
			   cptr->name);
      det_confs_butmask(cptr, 0);
      return -1;
    }
  }

  ClearAccess(cptr);

  if (!c_conf) {
    if (cptr->dns_reply) {
      int             i;
      struct hostent* hp = cptr->dns_reply->hp;
      const char*     name = hp->h_name;
      /*
       * If we are missing a C or N line from above, search for
       * it under all known hostnames we have for this ip#.
       */
      for (i = 0; name; name = hp->h_aliases[i++]) {
        if ((c_conf = find_conf_byhost(lp, name, CONF_SERVER))) {
          ircd_strncpy(cptr->sockhost, name, HOSTLEN);
          break;
        }
      }
      if (!c_conf) {
        for (i = 0; hp->h_addr_list[i]; i++) {
          if ((c_conf = find_conf_byip(lp, hp->h_addr_list[i], CONF_SERVER)))
            break;
        }
      }
    }
    else {
      /*
       * Check for C lines with the hostname portion the ip number
       * of the host the server runs on. This also checks the case where
       * there is a server connecting from 'localhost'.
       */
      c_conf = find_conf_byhost(lp, cptr->sockhost, CONF_SERVER);
    }
  }
  /*
   * Attach by IP# only if all other checks have failed.
   * It is quite possible to get here with the strange things that can
   * happen when using DNS in the way the irc server does. -avalon
   */
  if (!c_conf)
    c_conf = find_conf_byip(lp, (const char*) &cptr->ip, CONF_SERVER);
  /*
   * detach all conf lines that got attached by attach_confs()
   */
  det_confs_butmask(cptr, 0);
  /*
   * if no C or no N lines, then deny access
   */
  if (!c_conf) {
    Debug((DEBUG_DNS, "sv_cl: access denied: %s[%s@%s]",
          cptr->name, cptr->username, cptr->sockhost));
    return -1;
  }
  ircd_strncpy(cptr->name, c_conf->name, HOSTLEN);
  /*
   * attach the C and N lines to the client structure for later use.
   */
  attach_conf(cptr, c_conf);
  attach_confs_byname(cptr, cptr->name, CONF_HUB | CONF_LEAF | CONF_UWORLD);

  if (INADDR_NONE == c_conf->ipnum.s_addr)
    c_conf->ipnum.s_addr = cptr->ip.s_addr;

  Debug((DEBUG_DNS, "sv_cl: access ok: %s[%s]", cptr->name, cptr->sockhost));
  return 0;
}

