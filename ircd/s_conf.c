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

#include "sys.h"
#include <sys/socket.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#include <sys/stat.h>
#ifdef R_LINES
#include <signal.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include "h.h"
#include "struct.h"
#include "s_serv.h"
#include "opercmds.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "class.h"
#include "s_misc.h"
#include "match.h"
#include "common.h"
#include "s_err.h"
#include "s_bsd.h"
#include "ircd.h"
#include "crule.h"
#include "res.h"
#include "support.h"
#include "parse.h"
#include "numnicks.h"
#include "sprintf_irc.h"
#include "IPcheck.h"
#include "hash.h"
#include "fileio.h"

RCSTAG_CC("$Id$");

static int check_time_interval(char *, char *);
static int lookup_confhost(aConfItem *);
static int is_comment(char *);
static void killcomment(aClient *sptr, char *parv, char *filename);

aConfItem *conf = NULL;
aGline *gline = NULL;
aMotdItem *motd = NULL;
aMotdItem *rmotd = NULL;
atrecord *tdata = NULL;
struct tm motd_tm;

/*
 * field breakup for ircd.conf file.
 */
static char *gfline = NULL;
char *getfield(char *newline, char fs)
{
  char *end, *field;

  if (newline)
    gfline = newline;

  if (gfline == NULL)
    return NULL;

  end = field = gfline;

  if (fs != ':')
  {
    if (*end == fs)
      ++end;
    else
      fs = ':';
  }
  do
  {
    while (*end != fs)
    {
      if (!*end)
      {
	end = NULL;
	break;
      }
      ++end;
    }
  }
  while (end && fs != ':' && *++end != ':' && *end != '\n');

  if (end == NULL)
  {
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
void det_confs_butmask(aClient *cptr, int mask)
{
  Reg1 Link *tmp, *tmp2;

  for (tmp = cptr->confs; tmp; tmp = tmp2)
  {
    tmp2 = tmp->next;
    if ((tmp->value.aconf->status & mask) == 0)
      detach_conf(cptr, tmp->value.aconf);
  }
}

/*
 * Find the first (best) I line to attach.
 */
enum AuthorizationCheckResult attach_Iline(aClient *cptr, struct hostent *hp,
    char *sockhost)
{
  Reg1 aConfItem *aconf;
  Reg3 const char *hname;
  Reg4 int i;
  static char uhost[HOSTLEN + USERLEN + 3];
  static char fullname[HOSTLEN + 1];

  for (aconf = conf; aconf; aconf = aconf->next)
  {
    if (aconf->status != CONF_CLIENT)
      continue;
    if (aconf->port && aconf->port != cptr->acpt->port)
      continue;
    if (!aconf->host || !aconf->name)
      continue;
    if (hp)
      for (i = 0, hname = hp->h_name; hname; hname = hp->h_aliases[i++])
      {
	size_t fullnamelen = 0;
	size_t label_count = 0;
	int error;

	strncpy(fullname, hname, HOSTLEN);
	fullname[HOSTLEN] = 0;

	/*
	 * Disallow a hostname label to contain anything but a [-a-zA-Z0-9].
	 * It may not start or end on a '.'.
	 * A label may not end on a '-', the maximum length of a label is
	 * 63 characters.
	 * On top of that (which seems to be the RFC) we demand that the
	 * top domain does not contain any digits.
	 */
	error = (*hname == '.') ? 1 : 0;	/* May not start with a '.' */
	if (!error)
	{
	  char *p;
	  for (p = fullname; *p; ++p, ++fullnamelen)
	  {
	    if (*p == '.')
	    {
	      if (p[-1] == '-'	/* Label may not end on '-' */
		  || p[1] == 0)	/* May not end on a '.' */
	      {
		error = 1;
		break;
	      }
	      label_count = 0;
	      error = 0;	/* Was not top domain */
	      continue;
	    }
	    if (++label_count > 63)	/* Label not longer then 63 */
	    {
	      error = 1;
	      break;
	    }
	    if (*p >= '0' && *p <= '9')
	    {
	      error = 1;	/* In case this is top domain */
	      continue;
	    }
	    if (!(*p >= 'a' && *p <= 'z')
		&& !(*p >= 'A' && *p <= 'Z') && *p != '-')
	    {
	      error = 1;
	      break;
	    }
	  }
	}
	if (error)
	{
	  hp = NULL;
	  break;
	}

	add_local_domain(fullname, HOSTLEN - fullnamelen);
	Debug((DEBUG_DNS, "a_il: %s->%s", sockhost, fullname));
	if (strchr(aconf->name, '@'))
	{
	  strcpy(uhost, cptr->username);
	  strcat(uhost, "@");
	}
	else
	  *uhost = '\0';
	strncat(uhost, fullname, sizeof(uhost) - 1 - strlen(uhost));
	uhost[sizeof(uhost) - 1] = 0;
	if (!match(aconf->name, uhost))
	{
	  if (strchr(uhost, '@'))
	    cptr->flags |= FLAGS_DOID;
	  goto attach_iline;
	}
      }

    if (strchr(aconf->host, '@'))
    {
      strncpy(uhost, cptr->username, sizeof(uhost) - 2);
      uhost[sizeof(uhost) - 2] = 0;
      strcat(uhost, "@");
    }
    else
      *uhost = '\0';
    strncat(uhost, sockhost, sizeof(uhost) - 1 - strlen(uhost));
    uhost[sizeof(uhost) - 1] = 0;
    if (match(aconf->host, uhost))
      continue;
    if (strchr(uhost, '@'))
      cptr->flags |= FLAGS_DOID;
    if (hp && hp->h_name)
    {
      strncpy(uhost, hp->h_name, HOSTLEN);
      uhost[HOSTLEN] = 0;
      add_local_domain(uhost, HOSTLEN - strlen(uhost));
    }
  attach_iline:
    get_sockhost(cptr, uhost);

    if (aconf->passwd)
    {
      if (isDigit(*aconf->passwd) && !aconf->passwd[1])	/* Special case: exactly one digit */
      {
	/* Refuse connections when there are already <digit> clients connected with the same IP number */
	unsigned short nr = *aconf->passwd - '0';
	if (IPcheck_nr(cptr) > nr)
	  return ACR_TOO_MANY_FROM_IP;	/* Already got nr with that ip# */
      }
#ifdef USEONE
      else if (!strcmp(aconf->passwd, "ONE"))
      {
	for (i = highest_fd; i >= 0; i--)
	  if (loc_clients[i] && MyUser(loc_clients[i]) &&
	      loc_clients[i]->ip.s_addr == cptr->ip.s_addr)
	    return ACR_TOO_MANY_FROM_IP;	/* Already got one with that ip# */
      }
#endif
    }
    return attach_conf(cptr, aconf);
  }
  return ACR_NO_AUTHORIZATION;
}

/*
 * Find the single N line and return pointer to it (from list).
 * If more than one then return NULL pointer.
 */
aConfItem *count_cnlines(Link *lp)
{
  Reg1 aConfItem *aconf, *cline = NULL, *nline = NULL;

  for (; lp; lp = lp->next)
  {
    aconf = lp->value.aconf;
    if (!(aconf->status & CONF_SERVER_MASK))
      continue;
    if (aconf->status == CONF_CONNECT_SERVER && !cline)
      cline = aconf;
    else if (aconf->status == CONF_NOCONNECT_SERVER && !nline)
      nline = aconf;
  }
  return nline;
}

/*
 * detach_conf
 *
 * Disassociate configuration from the client.
 */
int detach_conf(aClient *cptr, aConfItem *aconf)
{
  Reg1 Link **lp, *tmp;

  lp = &(cptr->confs);

  while (*lp)
  {
    if ((*lp)->value.aconf == aconf)
    {
      if (aconf && (aconf->confClass)
	  && (aconf->status & CONF_CLIENT_MASK) && ConfLinks(aconf) > 0)
	--ConfLinks(aconf);
      if (aconf && !--aconf->clients && IsIllegal(aconf))
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

static int is_attached(aConfItem *aconf, aClient *cptr)
{
  Reg1 Link *lp;

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
enum AuthorizationCheckResult attach_conf(aClient *cptr, aConfItem *aconf)
{
  Reg1 Link *lp;

  if (is_attached(aconf, cptr))
    return ACR_ALREADY_AUTHORIZED;
  if (IsIllegal(aconf))
    return ACR_NO_AUTHORIZATION;
  if ((aconf->status & (CONF_LOCOP | CONF_OPERATOR | CONF_CLIENT)) &&
      ConfLinks(aconf) >= ConfMaxLinks(aconf) && ConfMaxLinks(aconf) > 0)
    return ACR_TOO_MANY_IN_CLASS;	/* Use this for printing error message */
  lp = make_link();
  lp->next = cptr->confs;
  lp->value.aconf = aconf;
  cptr->confs = lp;
  aconf->clients++;
  if (aconf->status & CONF_CLIENT_MASK)
    ConfLinks(aconf)++;
  return ACR_OK;
}

aConfItem *find_admin(void)
{
  Reg1 aConfItem *aconf;

  for (aconf = conf; aconf; aconf = aconf->next)
    if (aconf->status & CONF_ADMIN)
      break;

  return (aconf);
}

aConfItem *find_me(void)
{
  Reg1 aConfItem *aconf;
  for (aconf = conf; aconf; aconf = aconf->next)
    if (aconf->status & CONF_ME)
      break;

  return (aconf);
}

/*
 * attach_confs
 *
 * Attach a CONF line to a client if the name passed matches that for
 * the conf file (for non-C/N lines) or is an exact match (C/N lines
 * only).  The difference in behaviour is to stop C:*::* and N:*::*.
 */
aConfItem *attach_confs(aClient *cptr, const char *name, int statmask)
{
  Reg1 aConfItem *tmp;
  aConfItem *first = NULL;
  int len = strlen(name);

  if (!name || len > HOSTLEN)
    return NULL;
  for (tmp = conf; tmp; tmp = tmp->next)
  {
    if ((tmp->status & statmask) && !IsIllegal(tmp) &&
	((tmp->status & (CONF_SERVER_MASK | CONF_HUB)) == 0) &&
	tmp->name && !match(tmp->name, name))
    {
      if (attach_conf(cptr, tmp) == ACR_OK && !first)
	first = tmp;
    }
    else if ((tmp->status & statmask) && !IsIllegal(tmp) &&
	(tmp->status & (CONF_SERVER_MASK | CONF_HUB)) &&
	tmp->name && !strCasediff(tmp->name, name))
    {
      if (attach_conf(cptr, tmp) == ACR_OK && !first)
	first = tmp;
    }
  }
  return (first);
}

/*
 * Added for new access check    meLazy
 */
aConfItem *attach_confs_host(aClient *cptr, char *host, int statmask)
{
  Reg1 aConfItem *tmp;
  aConfItem *first = NULL;
  int len = strlen(host);

  if (!host || len > HOSTLEN)
    return NULL;

  for (tmp = conf; tmp; tmp = tmp->next)
  {
    if ((tmp->status & statmask) && !IsIllegal(tmp) &&
	(tmp->status & CONF_SERVER_MASK) == 0 &&
	(!tmp->host || match(tmp->host, host) == 0))
    {
      if (attach_conf(cptr, tmp) == ACR_OK && !first)
	first = tmp;
    }
    else if ((tmp->status & statmask) && !IsIllegal(tmp) &&
	(tmp->status & CONF_SERVER_MASK) &&
	(tmp->host && strCasediff(tmp->host, host) == 0))
    {
      if (attach_conf(cptr, tmp) == ACR_OK && !first)
	first = tmp;
    }
  }
  return (first);
}

/*
 * find a conf entry which matches the hostname and has the same name.
 */
aConfItem *find_conf_exact(char *name, char *user, char *host, int statmask)
{
  Reg1 aConfItem *tmp;
  char userhost[USERLEN + HOSTLEN + 3];

  sprintf_irc(userhost, "%s@%s", user, host);

  for (tmp = conf; tmp; tmp = tmp->next)
  {
    if (!(tmp->status & statmask) || !tmp->name || !tmp->host ||
	strCasediff(tmp->name, name))
      continue;
    /*
     * Accept if the *real* hostname (usually sockecthost)
     * socket host) matches *either* host or name field
     * of the configuration.
     */
    if (match(tmp->host, userhost))
      continue;
    if (tmp->status & (CONF_OPERATOR | CONF_LOCOP))
    {
      if (tmp->clients < MaxLinks(tmp->confClass))
	return tmp;
      else
	continue;
    }
    else
      return tmp;
  }
  return NULL;
}

aConfItem *find_conf(Link *lp, const char *name, int statmask)
{
  Reg1 aConfItem *tmp;
  int namelen = name ? strlen(name) : 0;

  if (namelen > HOSTLEN)
    return (aConfItem *)0;

  for (; lp; lp = lp->next)
  {
    tmp = lp->value.aconf;
    if ((tmp->status & statmask) &&
	(((tmp->status & (CONF_SERVER_MASK | CONF_HUB)) &&
	tmp->name && !strCasediff(tmp->name, name)) ||
	((tmp->status & (CONF_SERVER_MASK | CONF_HUB)) == 0 &&
	tmp->name && !match(tmp->name, name))))
      return tmp;
  }
  return NULL;
}

/*
 * Added for new access check    meLazy
 */
aConfItem *find_conf_host(Link *lp, char *host, int statmask)
{
  Reg1 aConfItem *tmp;
  int hostlen = host ? strlen(host) : 0;

  if (hostlen > HOSTLEN || BadPtr(host))
    return (aConfItem *)NULL;
  for (; lp; lp = lp->next)
  {
    tmp = lp->value.aconf;
    if (tmp->status & statmask &&
	(!(tmp->status & CONF_SERVER_MASK || tmp->host) ||
	(tmp->host && !match(tmp->host, host))))
      return tmp;
  }
  return NULL;
}

/*
 * find_conf_ip
 *
 * Find a conf line using the IP# stored in it to search upon.
 * Added 1/8/92 by Avalon.
 */
aConfItem *find_conf_ip(Link *lp, char *ip, char *user, int statmask)
{
  Reg1 aConfItem *tmp;
  Reg2 char *s;

  for (; lp; lp = lp->next)
  {
    tmp = lp->value.aconf;
    if (!(tmp->status & statmask))
      continue;
    s = strchr(tmp->host, '@');
    *s = '\0';
    if (match(tmp->host, user))
    {
      *s = '@';
      continue;
    }
    *s = '@';
    if (!memcmp(&tmp->ipnum, ip, sizeof(struct in_addr)))
      return tmp;
  }
  return NULL;
}

/*
 * find_conf_entry
 *
 * - looks for a match on all given fields.
 */
static aConfItem *find_conf_entry(aConfItem *aconf, unsigned int mask)
{
  Reg1 aConfItem *bconf;

  for (bconf = conf, mask &= ~CONF_ILLEGAL; bconf; bconf = bconf->next)
  {
    if (!(bconf->status & mask) || (bconf->port != aconf->port))
      continue;

    if ((BadPtr(bconf->host) && !BadPtr(aconf->host)) ||
	(BadPtr(aconf->host) && !BadPtr(bconf->host)))
      continue;
    if (!BadPtr(bconf->host) && strCasediff(bconf->host, aconf->host))
      continue;

    if ((BadPtr(bconf->passwd) && !BadPtr(aconf->passwd)) ||
	(BadPtr(aconf->passwd) && !BadPtr(bconf->passwd)))
      continue;
    if (!BadPtr(bconf->passwd) && (!isDigit(*bconf->passwd) || bconf->passwd[1])
#ifdef USEONE
	&& strCasediff(bconf->passwd, "ONE")
#endif
	&& strCasediff(bconf->passwd, aconf->passwd))
      continue;

    if ((BadPtr(bconf->name) && !BadPtr(aconf->name)) ||
	(BadPtr(aconf->name) && !BadPtr(bconf->name)))
      continue;
    if (!BadPtr(bconf->name) && strCasediff(bconf->name, aconf->name))
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
int rehash(aClient *cptr, int sig)
{
  Reg1 aConfItem **tmp = &conf, *tmp2;
  Reg2 aConfClass *cltmp;
  Reg1 aClient *acptr;
  Reg2 aMotdItem *temp;
  Reg2 int i;
  int ret = 0, found_g;

  if (sig == 1)
    sendto_ops("Got signal SIGHUP, reloading ircd conf. file");

  for (i = 0; i <= highest_fd; i++)
    if ((acptr = loc_clients[i]) && !IsMe(acptr))
    {
      /*
       * Nullify any references from client structures to
       * this host structure which is about to be freed.
       * Could always keep reference counts instead of
       * this....-avalon
       */
      acptr->hostp = NULL;
    }

  while ((tmp2 = *tmp))
    if (tmp2->clients || tmp2->status & CONF_LISTEN_PORT)
    {
      /*
       * Configuration entry is still in use by some
       * local clients, cannot delete it--mark it so
       * that it will be deleted when the last client
       * exits...
       */
      if (!(tmp2->status & (CONF_LISTEN_PORT | CONF_CLIENT)))
      {
	*tmp = tmp2->next;
	tmp2->next = NULL;
      }
      else
	tmp = &tmp2->next;
      tmp2->status |= CONF_ILLEGAL;
    }
    else
    {
      *tmp = tmp2->next;
      /* free expression trees of connect rules */
      if ((tmp2->status & (CONF_CRULEALL | CONF_CRULEAUTO)) &&
	  (tmp2->passwd != NULL))
	crule_free(&(tmp2->passwd));
      free_conf(tmp2);
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
    flush_cache();
  if (initconf(0) == -1)	/* This calls check_class(), */
    check_class();		/* unless it fails */
  close_listeners();

  /*
   * Flush out deleted I and P lines although still in use.
   */
  for (tmp = &conf; (tmp2 = *tmp);)
    if (!(tmp2->status & CONF_ILLEGAL))
      tmp = &tmp2->next;
    else
    {
      *tmp = tmp2->next;
      tmp2->next = NULL;
      if (!tmp2->clients)
	free_conf(tmp2);
    }

  for (i = 0; i <= highest_fd; i++) {
    if ((acptr = loc_clients[i]) && !IsMe(acptr)) {
      if (IsServer(acptr)) {
	det_confs_butmask(acptr,
	    ~(CONF_HUB | CONF_LEAF | CONF_UWORLD | CONF_ILLEGAL));
	attach_confs(acptr, acptr->name, CONF_HUB | CONF_LEAF | CONF_UWORLD);
      }
      if ((found_g = find_kill(acptr))) {
	sendto_op_mask(found_g == -2 ? SNO_GLINE : SNO_OPERKILL,
	    found_g == -2 ? "G-line active for %s" : "K-line active for %s",
	    get_client_name(acptr, FALSE));
	if (exit_client(cptr, acptr, &me, found_g == -2 ? "G-lined" :
	    "K-lined") == CPTR_KILLED)
	  ret = CPTR_KILLED;
      }
#if defined(R_LINES) && defined(R_LINES_REHASH) && !defined(R_LINES_OFTEN)
      if (find_restrict(acptr)) {
	sendto_ops("Restricting %s, closing lp", get_client_name(acptr, FALSE));
	if (exit_client(cptr, acptr, &me, "R-lined") == CPTR_KILLED)
	  ret = CPTR_KILLED;
      }
#endif
    }
  }

  /* free old motd structs */
  while (motd) {
    temp = motd->next;
    RunFree(motd);
    motd = temp;
  }
  while (rmotd) {
    temp = rmotd->next;
    RunFree(rmotd);
    rmotd = temp;
  }
  /* reload motd files */
  read_tlines();
  rmotd = read_motd(RPATH);
  motd = read_motd(MPATH);

  return ret;
}

/*
 * initconf
 *
 * Read configuration file.
 *
 * returns -1, if file cannot be opened
 *          0, if file opened
 */

#define MAXCONFLINKS 150

unsigned short server_port;

int initconf(int opt)
{
  static char quotes[9][2] = {
    {'b', '\b'},
    {'f', '\f'},
    {'n', '\n'},
    {'r', '\r'},
    {'t', '\t'},
    {'v', '\v'},
    {'\\', '\\'},
    {0, 0}
  };
  Reg1 char *tmp, *s;
  FBFILE *file;
  int i;
  char line[512];
  int ccount = 0, ncount = 0;
  aConfItem *aconf = NULL;

  Debug((DEBUG_DEBUG, "initconf(): ircd.conf = %s", configfile));
  if (NULL == (file = fbopen(configfile, "r")))
  {
    return -1;
  }
  while (fbgets(line, sizeof(line) - 1, file))
  {
    if ((tmp = strchr(line, '\n')))
      *tmp = '\0';
    /*
     * Do quoting of characters and # detection.
     */
    for (tmp = line; *tmp; tmp++)
    {
      if (*tmp == '\\')
      {
	for (i = 0; quotes[i][0]; i++)
	  if (quotes[i][0] == *(tmp + 1))
	  {
	    *tmp = quotes[i][1];
	    break;
	  }
	if (!quotes[i][0])
	  *tmp = *(tmp + 1);
	if (!*(tmp + 1))
	  break;
	else
	  for (s = tmp; (*s = *(s + 1)); s++)
	    ;
      }
      else if (*tmp == '#')
	*tmp = '\0';
    }
    if (!*line || line[0] == '#' || line[0] == '\n' ||
	line[0] == ' ' || line[0] == '\t')
      continue;
    /* Could we test if it's conf line at all?      -Vesa */
    if (line[1] != ':')
    {
      Debug((DEBUG_ERROR, "Bad config line: %s", line));
      continue;
    }
    if (aconf)
      free_conf(aconf);
    aconf = make_conf();

    tmp = getfield(line, ':');
    if (!tmp)
      continue;
    switch (*tmp)
    {
      case 'A':		/* Name, e-mail address of administrator */
      case 'a':		/* of this server. */
	aconf->status = CONF_ADMIN;
	break;
      case 'C':		/* Server where I should try to connect */
      case 'c':		/* in case of lp failures             */
	ccount++;
	aconf->status = CONF_CONNECT_SERVER;
	break;
	/* Connect rule */
      case 'D':
	aconf->status = CONF_CRULEALL;
	break;
	/* Connect rule - autos only */
      case 'd':
	aconf->status = CONF_CRULEAUTO;
	break;
      case 'H':		/* Hub server line */
      case 'h':
	aconf->status = CONF_HUB;
	break;
      case 'I':		/* Just plain normal irc client trying  */
      case 'i':		/* to connect me */
	aconf->status = CONF_CLIENT;
	break;
      case 'K':		/* Kill user line on irc.conf           */
	aconf->status = CONF_KILL;
	break;
      case 'k':		/* Kill user line based on IP in ircd.conf */
	aconf->status = CONF_IPKILL;
	break;
	/* Operator. Line should contain at least */
	/* password and host where connection is  */
      case 'L':		/* guaranteed leaf server */
      case 'l':
	aconf->status = CONF_LEAF;
	break;
	/* Me. Host field is name used for this host */
	/* and port number is the number of the port */
      case 'M':
      case 'm':
	aconf->status = CONF_ME;
	break;
      case 'N':		/* Server where I should NOT try to     */
      case 'n':		/* connect in case of lp failures     */
	/* but which tries to connect ME        */
	++ncount;
	aconf->status = CONF_NOCONNECT_SERVER;
	break;
      case 'O':
	aconf->status = CONF_OPERATOR;
	break;
	/* Local Operator, (limited privs --SRB) */
      case 'o':
	aconf->status = CONF_LOCOP;
	break;
      case 'P':		/* listen port line */
      case 'p':
	aconf->status = CONF_LISTEN_PORT;
	break;
#ifdef R_LINES
      case 'R':		/* extended K line */
      case 'r':		/* Offers more options of how to restrict */
	aconf->status = CONF_RESTRICT;
	break;
#endif
      case 'T':		/* print out different motd's */
      case 't':		/* based on hostmask */
	aconf->status = CONF_TLINES;
	break;
      case 'U':		/* Underworld server, allowed to hack modes */
      case 'u':		/* *Every* server on the net must define the same !!! */
	aconf->status = CONF_UWORLD;
	break;
      case 'Y':
      case 'y':
	aconf->status = CONF_CLASS;
	break;
      default:
	Debug((DEBUG_ERROR, "Error in config file: %s", line));
	break;
    }
    if (IsIllegal(aconf))
      continue;

    for (;;)			/* Fake loop, that I can use break here --msa */
    {
      if ((tmp = getfield(NULL, ':')) == NULL)
	break;
      DupString(aconf->host, tmp);
      if ((tmp = getfield(NULL, (aconf->status == CONF_KILL
	  || aconf->status == CONF_IPKILL) ? '"' : ':')) == NULL)
	break;
      DupString(aconf->passwd, tmp);
      if ((tmp = getfield(NULL, ':')) == NULL)
	break;
      DupString(aconf->name, tmp);
      if ((tmp = getfield(NULL, ':')) == NULL)
	break;
      aconf->port = atoi(tmp);
      tmp = getfield(NULL, ':');
      if (aconf->status & CONF_ME)
      {
	server_port = aconf->port;
	if (!tmp)
	{
	  Debug((DEBUG_FATAL, "Your M: line must have the Numeric, "
	      "assigned to you by routing-com, behind the port number!\n"));
#ifdef USE_SYSLOG
	  syslog(LOG_WARNING, "Your M: line must have the Numeric, "
	      "assigned to you by routing-com, behind the port number!\n");
#endif
	  exit(-1);
	}
	SetYXXServerName(&me, atoi(tmp));	/* Our Numeric Nick */
      }
      else if (tmp)
	aconf->confClass = find_class(atoi(tmp));
      break;
    }
    /*
     * If conf line is a class definition, create a class entry
     * for it and make the conf_line illegal and delete it.
     */
    if (aconf->status & CONF_CLASS)
    {
      add_class(atoi(aconf->host), atoi(aconf->passwd),
	  atoi(aconf->name), aconf->port, tmp ? atoi(tmp) : 0);
      continue;
    }
    /*
     * Associate each conf line with a class by using a pointer
     * to the correct class record. -avalon
     */
    if (aconf->status & (CONF_CLIENT_MASK | CONF_LISTEN_PORT))
    {
      if (aconf->confClass == 0)
	aconf->confClass = find_class(0);
    }
    if (aconf->status & (CONF_LISTEN_PORT | CONF_CLIENT))
    {
      aConfItem *bconf;

      if ((bconf = find_conf_entry(aconf, aconf->status)))
      {
	delist_conf(bconf);
	bconf->status &= ~CONF_ILLEGAL;
	if (aconf->status == CONF_CLIENT)
	{
	  char *passwd = bconf->passwd;
	  bconf->passwd = aconf->passwd;
	  aconf->passwd = passwd;
	  ConfLinks(bconf) -= bconf->clients;
	  bconf->confClass = aconf->confClass;
	  if (bconf->confClass)
	    ConfLinks(bconf) += bconf->clients;
	}
	free_conf(aconf);
	aconf = bconf;
      }
      else if (aconf->host && aconf->status == CONF_LISTEN_PORT)
	add_listener(aconf);
    }
    if (aconf->status & CONF_SERVER_MASK)
      if (ncount > MAXCONFLINKS || ccount > MAXCONFLINKS ||
	  !aconf->host || strchr(aconf->host, '*') ||
	  strchr(aconf->host, '?') || !aconf->name)
	continue;

    if (aconf->status & (CONF_SERVER_MASK | CONF_LOCOP | CONF_OPERATOR))
      if (!strchr(aconf->host, '@') && *aconf->host != '/')
      {
	char *newhost;
	int len = 3;		/* *@\0 = 3 */

	len += strlen(aconf->host);
	newhost = (char *)RunMalloc(len);
	sprintf_irc(newhost, "*@%s", aconf->host);
	RunFree(aconf->host);
	aconf->host = newhost;
      }
    if (aconf->status & CONF_SERVER_MASK)
    {
      if (BadPtr(aconf->passwd))
	continue;
      else if (!(opt & BOOT_QUICK))
	lookup_confhost(aconf);
    }

    /* Create expression tree from connect rule...
     * If there's a parsing error, nuke the conf structure */
    if (aconf->status & (CONF_CRULEALL | CONF_CRULEAUTO))
    {
      RunFree(aconf->passwd);
      if ((aconf->passwd = (char *)crule_parse(aconf->name)) == NULL)
      {
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
    if (aconf->status == CONF_ME)
    {
      strncpy(me.info, aconf->name, sizeof(me.info) - 1);
      if (me.name[0] == '\0' && aconf->host[0])
	strncpy(me.name, aconf->host, sizeof(me.name) - 1);
      if (portnum == 0)
	portnum = aconf->port;
    }

    /*
     * Juped nicks are listed in the 'password' field of U:lines,
     * the list is comma separated and might be empty and/or contain
     * empty elements... the only limit is that it MUST be shorter
     * than 512 chars, or they will be cutted out :)
     */
    if ((aconf->status == CONF_UWORLD) && (aconf->passwd) && (*aconf->passwd))
      addNickJupes(aconf->passwd);

    if (aconf->status & CONF_ADMIN)
      if (!aconf->host || !aconf->passwd || !aconf->name)
      {
	Debug((DEBUG_FATAL, "Your A: line must have 4 fields!\n"));
#ifdef USE_SYSLOG
	syslog(LOG_WARNING, "Your A: line must have 4 fields!\n");
#endif
	exit(-1);
      }

    collapse(aconf->host);
    collapse(aconf->name);
    Debug((DEBUG_NOTICE,
	"Read Init: (%d) (%s) (%s) (%s) (%u) (%p)",
	aconf->status, aconf->host, aconf->passwd,
	aconf->name, aconf->port, aconf->confClass));
    aconf->next = conf;
    conf = aconf;
    aconf = NULL;
  }
  if (aconf)
    free_conf(aconf);
  fbclose(file);
  check_class();
  nextping = nextconnect = now;
  return 0;
}

/*
 * lookup_confhost
 *
 * Do (start) DNS lookups of all hostnames in the conf line and convert
 * an IP addresses in a.b.c.d number for to IP#s.
 */
static int lookup_confhost(aConfItem *aconf)
{
  Reg2 char *s;
  Reg3 struct hostent *hp;
  Link ln;

  if (BadPtr(aconf->host) || BadPtr(aconf->name))
    goto badlookup;
  if ((s = strchr(aconf->host, '@')))
    s++;
  else
    s = aconf->host;
  /*
   * Do name lookup now on hostnames given and store the
   * ip numbers in conf structure.
   */
  if (!isAlpha(*s) && !isDigit(*s))
    goto badlookup;

  /*
   * Prepare structure in case we have to wait for a
   * reply which we get later and store away.
   */
  ln.value.aconf = aconf;
  ln.flags = ASYNC_CONF;

  if (isDigit(*s))
    aconf->ipnum.s_addr = inet_addr(s);
  else if ((hp = gethost_byname(s, &ln)))
    memcpy(&(aconf->ipnum), hp->h_addr, sizeof(struct in_addr));

  if (aconf->ipnum.s_addr == INADDR_NONE)
    goto badlookup;
  return 0;
badlookup:
  if (aconf->ipnum.s_addr == INADDR_NONE)
    memset(&aconf->ipnum, 0, sizeof(struct in_addr));
  Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
      aconf->host, aconf->name));
  return -1;
}

/* read_tlines 
 * Read info from T:lines into trecords which include the file 
 * timestamp, the hostmask, and the contents of the motd file 
 * -Ghostwolf 7sep97
 */
void read_tlines()
{
  aConfItem *tmp;
  atrecord *temp, *last = NULL;	/* Init. to avoid compiler warning */
  aMotdItem *amotd;

  /* Free the old trecords and the associated motd contents first */
  while (tdata)
  {
    last = tdata->next;
    while (tdata->tmotd)
    {
      amotd = tdata->tmotd->next;
      RunFree(tdata->tmotd);
      tdata->tmotd = amotd;
    }
    RunFree(tdata);
    tdata = last;
  }

  for (tmp = conf; tmp; tmp = tmp->next)
    if (tmp->status == CONF_TLINES && tmp->host && tmp->passwd)
    {
      temp = (atrecord *) RunMalloc(sizeof(atrecord));
      if (!temp)
	outofmemory();
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

int find_kill(aClient *cptr)
{
  char reply[256], *host, *name;
  aConfItem *tmp;
  aGline *agline = NULL;

  if (!cptr->user)
    return 0;

  host = cptr->sockhost;
  name = cptr->user->username;

  if (strlen(host) > (size_t)HOSTLEN ||
      (name ? strlen(name) : 0) > (size_t)HOSTLEN)
    return (0);

  reply[0] = '\0';

  for (tmp = conf; tmp; tmp = tmp->next)
    /* Added a check against the user's IP address as well.
     * If the line is either CONF_KILL or CONF_IPKILL, check it; if and only
     * if it's CONF_IPKILL, check the IP address as well (the && below will
     * short circuit and the match won't even get run) -Kev
     */
    if ((tmp->status & CONF_KLINE) && tmp->host && tmp->name &&
	(match(tmp->host, host) == 0 ||
	((tmp->status == CONF_IPKILL) &&
	match(tmp->host, inetntoa(cptr->ip)) == 0)) &&
	(!name || match(tmp->name, name) == 0) &&
	(!tmp->port || (tmp->port == cptr->acpt->port)))
    {
      /*
       * Can short-circuit evaluation - not taking chances
       * because check_time_interval destroys tmp->passwd
       * - Mmmm
       */
      if (BadPtr(tmp->passwd))
	break;
      else if (is_comment(tmp->passwd))
	break;
      else if (check_time_interval(tmp->passwd, reply))
	break;
    }

  if (reply[0])
    sendto_one(cptr, reply, me.name, ERR_YOUREBANNEDCREEP, cptr->name);
  else if (tmp)
  {
    if (BadPtr(tmp->passwd))
      sendto_one(cptr,
	  ":%s %d %s :Connection from your host is refused on this server.",
	  me.name, ERR_YOUREBANNEDCREEP, cptr->name);
    else
    {
      if (*tmp->passwd == '"')
      {
	char *sbuf =
	    sprintf_irc(sendbuf, ":%s %d %s :%s", me.name, ERR_YOUREBANNEDCREEP,
	    cptr->name, &tmp->passwd[1]);
	sbuf[-1] = '.';		/* Overwrite last quote with a dot */
	sendbufto_one(cptr);
      }
      else if (*tmp->passwd == '!')
	killcomment(cptr, cptr->name, &tmp->passwd[1]);
      else
#ifdef COMMENT_IS_FILE
	killcomment(cptr, cptr->name, tmp->passwd);
#else
	sendto_one(cptr, ":%s %d %s :%s.", me.name, ERR_YOUREBANNEDCREEP,
	    cptr->name, tmp->passwd);
#endif
    }
  }

  /* find active glines */
  /* added a check against the user's IP address to find_gline() -Kev */
  else if ((agline = find_gline(cptr, NULL)) && GlineIsActive(agline))
    sendto_one(cptr, ":%s %d %s :%s.", me.name, ERR_YOUREBANNEDCREEP,
	cptr->name, agline->reason);
  else
    agline = NULL;		/* if a gline was found, it was inactive */

  return (tmp ? -1 : (agline ? -2 : 0));
}

#ifdef R_LINES
/*
 * find_restrict
 *
 * Works against host/name and calls an outside program
 * to determine whether a client is allowed to connect.  This allows
 * more freedom to determine who is legal and who isn't, for example
 * machine load considerations.  The outside program is expected to
 * return a reply line where the first word is either 'Y' or 'N' meaning
 * "Yes Let them in" or "No don't let them in."  If the first word
 * begins with neither 'Y' or 'N' the default is to let the person on.
 * It returns a value of 0 if the user is to be let through -Hoppie
 */
int find_restrict(aClient *cptr)
{
  aConfItem *tmp;
  char reply[80], temprpl[80];
  char *rplhold = reply, *host, *name, *s;
  char rplchar = 'Y';
  int pi[2], rc = 0, n;
  FBFILE *file = NULL;

  if (!cptr->user)
    return 0;
  name = cptr->user->username;
  host = cptr->sockhost;
  Debug((DEBUG_INFO, "R-line check for %s[%s]", name, host));

  for (tmp = conf; tmp; tmp = tmp->next)
  {
    if (tmp->status != CONF_RESTRICT ||
	(tmp->host && host && match(tmp->host, host)) ||
	(tmp->name && name && match(tmp->name, name)))
      continue;

    if (BadPtr(tmp->passwd))
    {
      sendto_ops("Program missing on R-line %s/%s, ignoring", name, host);
      continue;
    }

    if (pipe(pi) == -1)
    {
      report_error("Error creating pipe for R-line %s: %s", &me);
      return 0;
    }
    switch (rc = fork())
    {
      case -1:
	report_error("Error forking for R-line %s: %s", &me);
	return 0;
      case 0:
      {
	Reg1 int i;

	close(pi[0]);
	for (i = 2; i < MAXCONNECTIONS; i++)
	  if (i != pi[1])
	    close(i);
	if (pi[1] != 2)
	  dup2(pi[1], 2);
	dup2(2, 1);
	if (pi[1] != 2 && pi[1] != 1)
	  close(pi[1]);
	execlp(tmp->passwd, tmp->passwd, name, host, 0);
	exit(-1);
      }
      default:
	close(pi[1]);
	break;
    }
    *reply = '\0';
    file = fdbopen(pi[0], "r");
    while (fbgets(temprpl, sizeof(temprpl) - 1, file))
    {
      if ((s = strchr(temprpl, '\n')))
	*s = '\0';
      if (strlen(temprpl) + strlen(reply) < sizeof(reply) - 2)
	sprintf_irc(rplhold, "%s %s", rplhold, temprpl);
      else
      {
	sendto_ops("R-line %s/%s: reply too long!", name, host);
	break;
      }
    }
    fbclose(file);
    kill(rc, SIGKILL);		/* cleanup time */
    wait(0);

    rc = 0;
    while (*rplhold == ' ')
      rplhold++;
    rplchar = *rplhold;		/* Pull out the yes or no */
    while (*rplhold != ' ')
      rplhold++;
    while (*rplhold == ' ')
      rplhold++;
    strcpy(reply, rplhold);
    rplhold = reply;

    if ((rc = (rplchar == 'n' || rplchar == 'N')))
      break;
  }
  if (rc)
  {
    sendto_one(cptr, ":%s %d %s :Restriction: %s",
	me.name, ERR_YOUREBANNEDCREEP, cptr->name, reply);
    return -1;
  }
  return 0;
}
#endif

/*
 * output the reason for being k lined from a file  - Mmmm
 * sptr is server
 * parv is the sender prefix
 * filename is the file that is to be output to the K lined client
 */
static void killcomment(aClient *sptr, char *parv, char *filename)
{
  FBFILE *file = NULL;
  char line[80];
  Reg1 char *tmp;
  struct stat sb;
  struct tm *tm;

  if (NULL == (file = fbopen(filename, "r")))
  {
    sendto_one(sptr, err_str(ERR_NOMOTD), me.name, parv);
    sendto_one(sptr,
	":%s %d %s :Connection from your host is refused on this server.",
	me.name, ERR_YOUREBANNEDCREEP, parv);
    return;
  }
  fbstat(&sb, file);
  tm = localtime((time_t *) & sb.st_mtime);	/* NetBSD needs cast */
  while (fbgets(line, sizeof(line) - 1, file))
  {
    if ((tmp = strchr(line, '\n')))
      *tmp = '\0';
    if ((tmp = strchr(line, '\r')))
      *tmp = '\0';
    /* sendto_one(sptr,
     * ":%s %d %s : %s.",
     * me.name, ERR_YOUREBANNEDCREEP, parv,line); */
    sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv, line);
  }
  sendto_one(sptr,
      ":%s %d %s :Connection from your host is refused on this server.",
      me.name, ERR_YOUREBANNEDCREEP, parv);
  fbclose(file);
  return;
}

/*
 *  is the K line field an interval or a comment? - Mmmm
 */
static int is_comment(char *comment)
{
  size_t i;
  for (i = 0; i < strlen(comment); i++)
    if ((comment[i] != ' ') && (comment[i] != '-')
	&& (comment[i] != ',') && ((comment[i] < '0') || (comment[i] > '9')))
      return (1);

  return (0);
}

/*
 *  check against a set of time intervals
 */
static int check_time_interval(char *interval, char *reply)
{
  struct tm *tptr;
  char *p;
  int perm_min_hours, perm_min_minutes, perm_max_hours, perm_max_minutes;
  int nowm, perm_min, perm_max;

  tptr = localtime(&now);
  nowm = tptr->tm_hour * 60 + tptr->tm_min;

  while (interval)
  {
    p = strchr(interval, ',');
    if (p)
      *p = '\0';
    if (sscanf(interval, "%2d%2d-%2d%2d", &perm_min_hours, &perm_min_minutes,
	&perm_max_hours, &perm_max_minutes) != 4)
    {
      if (p)
	*p = ',';
      return (0);
    }
    if (p)
      *(p++) = ',';
    perm_min = 60 * perm_min_hours + perm_min_minutes;
    perm_max = 60 * perm_max_hours + perm_max_minutes;
    /*
     * The following check allows intervals over midnight ...
     */
    if ((perm_min < perm_max)
	? (perm_min <= nowm && nowm <= perm_max)
	: (perm_min <= nowm || nowm <= perm_max))
    {
      printf(reply,
	  ":%%s %%d %%s :%s %d:%02d to %d:%02d.",
	  "You are not allowed to connect from",
	  perm_min_hours, perm_min_minutes, perm_max_hours, perm_max_minutes);
      return (ERR_YOUREBANNEDCREEP);
    }
    if ((perm_min < perm_max)
	? (perm_min <= nowm + 5 && nowm + 5 <= perm_max)
	: (perm_min <= nowm + 5 || nowm + 5 <= perm_max))
    {
      sprintf_irc(reply, ":%%s %%d %%s :%d minute%s%s",
	  perm_min - nowm, (perm_min - nowm) > 1 ? "s " : " ",
	  "and you will be denied for further access");
      return (ERR_YOUWILLBEBANNED);
    }
    interval = p;
  }
  return (0);
}

aMotdItem *read_motd(char *motdfile)
{
  FBFILE *file = NULL;
  register aMotdItem *temp, *newmotd, *last;
  struct stat sb;
  char line[80];
  register char *tmp;

  if (NULL == (file = fbopen(motdfile, "r")))
  {
    Debug((DEBUG_ERROR, "Couldn't open \"%s\": %s", motdfile, strerror(errno)));
    return NULL;
  }
  if (-1 == fbstat(&sb, file))
  {
    return NULL;
  }
  newmotd = last = NULL;
  motd_tm = *localtime((time_t *) & sb.st_mtime);	/* NetBSD needs cast */
  while (fbgets(line, sizeof(line) - 1, file))
  {
    if ((tmp = (char *)strchr(line, '\n')))
      *tmp = '\0';
    if ((tmp = (char *)strchr(line, '\r')))
      *tmp = '\0';
    temp = (aMotdItem *) RunMalloc(sizeof(aMotdItem));
    if (!temp)
      outofmemory();
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
