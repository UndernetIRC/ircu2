/*
 * IRC - Internet Relay Chat, ircd/s_serv.c (formerly ircd/s_msg.c)
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
#include <stdlib.h>
#include "h.h"
#include "struct.h"
#include "ircd.h"
#include "s_serv.h"
#include "s_misc.h"
#include "sprintf_irc.h"
#include "send.h"
#include "s_err.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "hash.h"
#include "common.h"
#include "match.h"
#include "crule.h"
#include "parse.h"
#include "numnicks.h"
#include "userload.h"
#include "s_user.h"
#include "channel.h"
#include "querycmds.h"
#include "IPcheck.h"

RCSTAG_CC("$Id$");

static int exit_new_server(aClient *cptr, aClient *sptr,
    char *host, time_t timestamp, char *fmt, ...)
    __attribute__ ((format(printf, 5, 6)));

/* *INDENT-OFF* */

#ifdef CRYPT_LINK_PASSWORD
__BEGIN_DECLS
/* This is not ANSI, but we have it anyway... */
char *crypt(const char *key, const char *salt);
__END_DECLS
#endif /* CRYPT_LINK_PASSWORD */

/* *INDENT-ON* */

unsigned int max_connection_count = 0, max_client_count = 0;

static int exit_new_server(aClient *cptr, aClient *sptr,
    char *host, time_t timestamp, char *fmt, ...)
{
  va_list vl;
  char *buf =
      (char *)RunMalloc(strlen(me.name) + strlen(host) + 22 + strlen(fmt));
  va_start(vl, fmt);
  if (!IsServer(sptr))
    return vexit_client_msg(cptr, cptr, &me, fmt, vl);
  sprintf_irc(buf, ":%s SQUIT %s " TIME_T_FMT " :", me.name, host, timestamp);
  strcat(buf, fmt);
  vsendto_one(cptr, buf, vl);
  va_end(vl);
  RunFree(buf);
  return 0;
}

static int a_kills_b_too(aClient *a, aClient *b)
{
  for (; b != a && b != &me; b = b->serv->up);
  return (a == b ? 1 : 0);
}

extern unsigned short server_port;

/*
 *  m_server
 *
 *    parv[0] = sender prefix
 *    parv[1] = servername
 *    parv[2] = hopcount
 *    parv[3] = start timestamp
 *    parv[4] = link timestamp
 *    parv[5] = major protocol version: P09/P10
 *    parv[parc-1] = serverinfo
 *  If cptr is P10:
 *    parv[6] = "YMM", where 'Y' is the server numeric and "MM" is the
 *              numeric nick mask of this server.
 *    parv[7] = 0 (not used yet, mandatory unsigned int after u2.10.06)
 */
int m_server(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 char *ch;
  Reg2 int i;
  char info[REALLEN + 1], *inpath, *host, *s;
  aClient *acptr, *bcptr, *LHcptr = NULL;
  aConfItem *aconf = NULL, *bconf = NULL, *cconf, *lhconf = NULL;
  int hop, ret, active_lh_line = 0;
  unsigned short int prot;
  time_t start_timestamp, timestamp = 0, recv_time, ghost = 0;

  if (IsUser(cptr))
  {
    sendto_one(cptr, err_str(ERR_ALREADYREGISTRED), me.name, parv[0]);
    return 0;
  }

  if (IsUserPort(cptr))
    return exit_client_msg(cptr, cptr, &me,
	"You cannot connect a server to a user port; connect to %s port %u",
	me.name, server_port);

  recv_time = TStime();
  info[0] = '\0';
  inpath = get_client_name(cptr, TRUE);
  if (parc < 7)
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "SERVER");
    return exit_client(cptr, cptr, &me, "Need more parameters");
  }
  host = parv[1];
  /* Detect protocol */
  if (strlen(parv[5]) != 3 || (parv[5][0] != 'P' && parv[5][0] != 'J'))
    return exit_client_msg(cptr, sptr, &me, "Bogus protocol (%s)", parv[5]);
  if (!IsServer(cptr))		/* Don't allow silently connecting a server */
    *parv[5] = 'J';
  prot = atoi(parv[5] + 1);
  if (prot > atoi(MAJOR_PROTOCOL))
    prot = atoi(MAJOR_PROTOCOL);
  /* Because the previous test is only in 2.10, the following is needed
   * till all servers are 2.10: */
  if (IsServer(cptr) && prot > Protocol(cptr))
    prot = Protocol(cptr);
  hop = atoi(parv[2]);
  start_timestamp = atoi(parv[3]);
  timestamp = atoi(parv[4]);
  Debug((DEBUG_INFO, "Got SERVER %s with timestamp [%s] age " TIME_T_FMT " ("
      TIME_T_FMT ")", host, parv[4], start_timestamp, me.serv->timestamp));
  if ((timestamp < 780000000 || (hop == 1 && start_timestamp < 780000000)))
  {
    return exit_client_msg(cptr, sptr, &me,
	"Bogus timestamps (%s %s)", parv[3], parv[4]);
  }
  strncpy(info, parv[parc - 1], REALLEN);
  info[REALLEN] = 0;
  if (prot < atoi(MINOR_PROTOCOL))
  {
    sendto_ops("Got incompatible protocol version (%s) from %s",
	parv[5], get_client_name(cptr, TRUE));
    return exit_new_server(cptr, sptr, host, timestamp,
	"Incompatible protocol: %s", parv[5]);
  }
  /*
   * Check for "FRENCH " infection ;-) (actually this should
   * be replaced with routine to check the hostname syntax in
   * general). [ This check is still needed, even after the parse
   * is fixed, because someone can send "SERVER :foo bar " ].
   * Also, changed to check other "difficult" characters, now
   * that parse lets all through... --msa
   */
  if (strlen(host) > HOSTLEN)
    host[HOSTLEN] = '\0';
  for (ch = host; *ch; ch++)
    if (*ch <= ' ' || *ch > '~')
      break;
  if (*ch || !strchr(host, '.'))
  {
    sendto_ops("Bogus server name (%s) from %s",
	host, get_client_name(cptr, TRUE));
    return exit_client_msg(cptr, cptr, &me, "Bogus server name (%s)", host);
  }

  if (IsServer(cptr))
  {
    /*
     * A local server introduces a new server behind this link.
     * Check if this is allowed according L:, H: and Q: lines.
     */
    if (info[0] == '\0')
      return exit_client_msg(cptr, cptr, &me,
	  "No server info specified for %s", host);

    /*
     * See if the newly found server is behind a guaranteed
     * leaf (L-line). If so, close the link.
     */
    if ((lhconf = find_conf_host(cptr->confs, host, CONF_LEAF)) &&
	(!lhconf->port || (hop > lhconf->port)))
    {
      /*
       * L: lines normally come in pairs, here we try to
       * make sure that the oldest link is squitted, not
       * both.
       */
      active_lh_line = 1;
      if (timestamp <= cptr->serv->timestamp)
	LHcptr = NULL;		/* Kill incoming server */
      else
	LHcptr = cptr;		/* Squit ourselfs */
    }
    else if (!(lhconf = find_conf_host(cptr->confs, host, CONF_HUB)) ||
	(lhconf->port && (hop > lhconf->port)))
    {
      aClient *ac3ptr;
      active_lh_line = 2;
      /* Look for net junction causing this: */
      LHcptr = NULL;		/* incoming server */
      if (*parv[5] != 'J')
	for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = ac3ptr->serv->up)
	  if (IsJunction(ac3ptr))
	  {
	    LHcptr = ac3ptr;
	    break;
	  }
    }
  }

  if (IsUnknown(cptr) || IsHandshake(cptr))
  {
    char *encr;

    /*
     * A local link that is still in undefined state wants
     * to be a SERVER. Check if this is allowed and change
     * status accordingly...
     */
    /*
     * If there is more then one server on the same machine
     * that we try to connect to, it could be that the /CONNECT
     * <mask> caused this connect to be put at the wrong place
     * in the hashtable.        --Run
     * Same thing for Unknown connections that first send NICK.
     *                          --Xorath
     * Better check if the two strings are (caseless) identical 
     * and not mess with hash internals. 
     *                          --Nemesi
     */
    if ((!(BadPtr(cptr->name)))
	&& (IsUnknown(cptr) || IsHandshake(cptr))
	&& strCasediff(cptr->name, host))
      hChangeClient(cptr, host);
    strncpy(cptr->name, host, sizeof(cptr->name) - 1);
    strncpy(cptr->info, info[0] ? info : me.name, sizeof(cptr->info) - 1);
    cptr->hopcount = hop;

    /* check connection rules */
    for (cconf = conf; cconf; cconf = cconf->next)
      if ((cconf->status == CONF_CRULEALL) && (match(cconf->host, host) == 0))
	if (crule_eval(cconf->passwd))
	{
	  ircstp->is_ref++;
	  sendto_ops("Refused connection from %s.", get_client_host(cptr));
	  return exit_client(cptr, cptr, &me, "Disallowed by connection rule");
	}

    if (check_server(cptr))
    {
      ircstp->is_ref++;
      sendto_ops("Received unauthorized connection from %s.",
	  get_client_host(cptr));
      return exit_client(cptr, cptr, &me, "No C/N conf lines");
    }

    host = cptr->name;

    update_load();

    if (!(aconf = find_conf(cptr->confs, host, CONF_NOCONNECT_SERVER)))
    {
      ircstp->is_ref++;
#ifndef GODMODE
      sendto_ops("Access denied. No N line for server %s", inpath);
      return exit_client_msg(cptr, cptr, &me,
	  "Access denied. No N line for server %s", inpath);
#else /* GODMODE */
      sendto_ops("General C/N: line active: No N line for server %s", inpath);
      aconf =
	  find_conf(cptr->confs, "general.undernet.org", CONF_NOCONNECT_SERVER);
      bconf =
	  find_conf(cptr->confs, "general.undernet.org", CONF_CONNECT_SERVER);
      if (!aconf || !bconf)
      {
	sendto_ops("Neither C/N lines for server %s nor "
	    "\"general.undernet.org\"", inpath);
	return exit_client_msg(cptr, cptr, &me,
	    "No C/N lines for server %s", inpath);
      }
#endif /* GODMODE */
    }
    else if (!(bconf = find_conf(cptr->confs, host, CONF_CONNECT_SERVER)))
    {
      ircstp->is_ref++;
      sendto_ops("Only N (no C) field for server %s", inpath);
      return exit_client_msg(cptr, cptr, &me,
	  "Only N (no C) field for server %s", inpath);
    }

#ifdef CRYPT_LINK_PASSWORD
    /* passwd may be NULL. Head it off at the pass... */
    if (*cptr->passwd)
    {
      char salt[3];

      salt[0] = aconf->passwd[0];
      salt[1] = aconf->passwd[1];
      salt[2] = '\0';
      encr = crypt(cptr->passwd, salt);
    }
    else
      encr = "";
#else
    encr = cptr->passwd;
#endif /* CRYPT_LINK_PASSWORD */
#ifndef GODMODE
    if (*aconf->passwd && !!strcmp(aconf->passwd, encr))
    {
      ircstp->is_ref++;
      sendto_ops("Access denied (passwd mismatch) %s", inpath);
      return exit_client_msg(cptr, cptr, &me,
	  "No Access (passwd mismatch) %s", inpath);
    }
#endif /* not GODMODE */
    memset(cptr->passwd, 0, sizeof(cptr->passwd));

#ifndef HUB
    for (i = 0; i <= highest_fd; i++)
      if (loc_clients[i] && IsServer(loc_clients[i]))
      {
	active_lh_line = 3;
	LHcptr = NULL;
	break;
      }
#endif
    if (!IsUnknown(cptr))
    {
      s = strchr(aconf->host, '@');
      *s = '\0';		/* should never be NULL */
      Debug((DEBUG_INFO, "Check Usernames [%s]vs[%s]",
	  aconf->host, cptr->username));
      if (match(aconf->host, cptr->username))
      {
	*s = '@';
	ircstp->is_ref++;
	sendto_ops("Username mismatch [%s]v[%s] : %s",
	    aconf->host, cptr->username, get_client_name(cptr, TRUE));
	return exit_client(cptr, cptr, &me, "Bad Username");
      }
      *s = '@';
    }
  }

  /*
   *  We want to find IsConnecting() and IsHandshake() too,
   *  use FindClient().
   *  The second finds collisions with numeric representation of existing
   *  servers - these shouldn't happen anymore when all upgraded to 2.10.
   *  -- Run
   */
  while ((acptr = FindClient(host)) ||
      (parc > 7 && (acptr = FindNServer(parv[6]))))
  {
    /*
     *  This link is trying feed me a server that I already have
     *  access through another path
     *
     *  Do not allow Uworld to do this.
     *  Do not allow servers that are juped.
     *  Do not allow servers that have older link timestamps
     *    then this try.
     *  Do not allow servers that use the same numeric as an existing
     *    server, but have a different name.
     *
     *  If my ircd.conf sucks, I can try to connect to myself:
     */
    if (acptr == &me)
      return exit_client_msg(cptr, cptr, &me,
	  "nick collision with me (%s)", host);
    /*
     * Detect wrong numeric.
     */
    if (strCasediff(acptr->name, host))
    {
      sendto_serv_butone(cptr,
	  ":%s WALLOPS :SERVER Numeric Collision: %s != %s",
	  me.name, acptr->name, host);
      return exit_client_msg(cptr, cptr, &me,
	  "NUMERIC collision between %s and %s."
	  " Is your server numeric correct ?", host, acptr->name);
    }
    /*
     *  Kill our try, if we had one.
     */
    if (IsConnecting(acptr))
    {
      if (!active_lh_line && exit_client(cptr, acptr, &me,
	  "Just connected via another link") == CPTR_KILLED)
	return CPTR_KILLED;
      /*
       * We can have only ONE 'IsConnecting', 'IsHandshake' or
       * 'IsServer', because new 'IsConnecting's are refused to
       * the same server if we already had it.
       */
      break;
    }
    /*
     * Avoid other nick collisions...
     * This is a doubtfull test though, what else would it be
     * when it has a server.name ?
     */
    else if (!IsServer(acptr) && !IsHandshake(acptr))
      return exit_client_msg(cptr, cptr, &me,
	  "Nickname %s already exists!", host);
    /*
     * Our new server might be a juped server,
     * or someone trying abuse a second Uworld:
     */
    else if (IsServer(acptr) && (strnCasecmp(acptr->info, "JUPE", 4) == 0 ||
	find_conf_host(cptr->confs, acptr->name, CONF_UWORLD)))
    {
      if (!IsServer(sptr))
	return exit_client(cptr, sptr, &me, acptr->info);
      sendto_one(cptr, ":%s WALLOPS :Received :%s SERVER %s from %s !?!",
	  me.name, parv[0], parv[1], cptr->name);
      return exit_new_server(cptr, sptr, host, timestamp, "%s", acptr->info);
    }
    /*
     * Of course we find the handshake this link was before :)
     */
    else if (IsHandshake(acptr) && acptr == cptr)
      break;
    /*
     * Here we have a server nick collision...
     * We don't want to kill the link that was last /connected,
     * but we neither want to kill a good (old) link.
     * Therefor we kill the second youngest link.
     */
    if (1)
    {
      aClient *c2ptr = NULL, *c3ptr = acptr;
      aClient *ac2ptr, *ac3ptr;

      /* Search youngest link: */
      for (ac3ptr = acptr; ac3ptr != &me; ac3ptr = ac3ptr->serv->up)
	if (ac3ptr->serv->timestamp > c3ptr->serv->timestamp)
	  c3ptr = ac3ptr;
      if (IsServer(sptr))
      {
	for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = ac3ptr->serv->up)
	  if (ac3ptr->serv->timestamp > c3ptr->serv->timestamp)
	    c3ptr = ac3ptr;
      }
      if (timestamp > c3ptr->serv->timestamp)
      {
	c3ptr = NULL;
	c2ptr = acptr;		/* Make sure they differ */
      }
      /* Search second youngest link: */
      for (ac2ptr = acptr; ac2ptr != &me; ac2ptr = ac2ptr->serv->up)
	if (ac2ptr != c3ptr &&
	    ac2ptr->serv->timestamp >
	    (c2ptr ? c2ptr->serv->timestamp : timestamp))
	  c2ptr = ac2ptr;
      if (IsServer(sptr))
      {
	for (ac2ptr = sptr; ac2ptr != &me; ac2ptr = ac2ptr->serv->up)
	  if (ac2ptr != c3ptr &&
	      ac2ptr->serv->timestamp >
	      (c2ptr ? c2ptr->serv->timestamp : timestamp))
	    c2ptr = ac2ptr;
      }
      if (c3ptr && timestamp > (c2ptr ? c2ptr->serv->timestamp : timestamp))
	c2ptr = NULL;
      /* If timestamps are equal, decide which link to break
       *  by name.
       */
      if ((c2ptr ? c2ptr->serv->timestamp : timestamp) ==
	  (c3ptr ? c3ptr->serv->timestamp : timestamp))
      {
	char *n2, *n2up;
	char *n3, *n3up;
	if (c2ptr)
	{
	  n2 = c2ptr->name;
	  n2up = MyConnect(c2ptr) ? me.name : c2ptr->serv->up->name;
	}
	else
	{
	  n2 = host;
	  n2up = IsServer(sptr) ? sptr->name : me.name;
	}
	if (c3ptr)
	{
	  n3 = c3ptr->name;
	  n3up = MyConnect(c3ptr) ? me.name : c3ptr->serv->up->name;
	}
	else
	{
	  n3 = host;
	  n3up = IsServer(sptr) ? sptr->name : me.name;
	}
	if (strcmp(n2, n2up) > 0)
	  n2 = n2up;
	if (strcmp(n3, n3up) > 0)
	  n3 = n3up;
	if (strcmp(n3, n2) > 0)
	{
	  ac2ptr = c2ptr;
	  c2ptr = c3ptr;
	  c3ptr = ac2ptr;
	}
      }
      /* Now squit the second youngest link: */
      if (!c2ptr)
	return exit_new_server(cptr, sptr, host, timestamp,
	    "server %s already exists and is %ld seconds younger.",
	    host, (long)acptr->serv->timestamp - (long)timestamp);
      else if (c2ptr->from == cptr || IsServer(sptr))
      {
	aClient *killedptrfrom = c2ptr->from;
	if (active_lh_line)
	{
	  /*
	   * If the L: or H: line also gets rid of this link,
	   * we sent just one squit.
	   */
	  if (LHcptr && a_kills_b_too(LHcptr, c2ptr))
	    break;
	  /*
	   * If breaking the loop here solves the L: or H:
	   * line problem, we don't squit that.
	   */
	  if (c2ptr->from == cptr || (LHcptr && a_kills_b_too(c2ptr, LHcptr)))
	    active_lh_line = 0;
	  else
	  {
	    /*
	     * If we still have a L: or H: line problem,
	     * we prefer to squit the new server, solving
	     * loop and L:/H: line problem with only one squit.
	     */
	    LHcptr = NULL;
	    break;
	  }
	}
	/*
	 * If the new server was introduced by a server that caused a
	 * Ghost less then 20 seconds ago, this is probably also
	 * a Ghost... (20 seconds is more then enough because all
	 * SERVER messages are at the beginning of a net.burst). --Run
	 */
	if (now - cptr->serv->ghost < 20)
	{
	  killedptrfrom = acptr->from;
	  if (exit_client(cptr, acptr, &me, "Ghost loop") == CPTR_KILLED)
	    return CPTR_KILLED;
	}
	else if (exit_client_msg(cptr, c2ptr, &me,
	    "Loop <-- %s (new link is %ld seconds younger)", host,
	    (c3ptr ? (long)c3ptr->serv->timestamp : timestamp) -
	    (long)c2ptr->serv->timestamp) == CPTR_KILLED)
	  return CPTR_KILLED;
	/*
	 * Did we kill the incoming server off already ?
	 */
	if (killedptrfrom == cptr)
	  return 0;
      }
      else
      {
	if (active_lh_line)
	{
	  if (LHcptr && a_kills_b_too(LHcptr, acptr))
	    break;
	  if (acptr->from == cptr || (LHcptr && a_kills_b_too(acptr, LHcptr)))
	    active_lh_line = 0;
	  else
	  {
	    LHcptr = NULL;
	    break;
	  }
	}
	/*
	 * We can't believe it is a lagged server message
	 * when it directly connects to us...
	 * kill the older link at the ghost, rather then
	 * at the second youngest link, assuming it isn't
	 * a REAL loop.
	 */
	ghost = now;		/* Mark that it caused a ghost */
	if (exit_client(cptr, acptr, &me, "Ghost") == CPTR_KILLED)
	  return CPTR_KILLED;
	break;
      }
    }
  }

  if (active_lh_line)
  {
    if (LHcptr == NULL)
      return exit_new_server(cptr, sptr, host, timestamp,
	  (active_lh_line == 2) ?
	  "Non-Hub link %s <- %s(%s)" : "Leaf-only link %s <- %s(%s)",
	  get_client_name(cptr, TRUE), host,
	  lhconf ? (lhconf->host ? lhconf->host : "*") : "!");
    else
    {
      register int killed = a_kills_b_too(LHcptr, sptr);
      if (active_lh_line < 3)
      {
	if (exit_client_msg(cptr, LHcptr, &me,
	    (active_lh_line == 2) ?
	    "Non-Hub link %s <- %s(%s)" : "Leaf-only link %s <- %s(%s)",
	    get_client_name(cptr, TRUE), host,
	    lhconf ? (lhconf->host ? lhconf->host : "*") : "!") == CPTR_KILLED)
	  return CPTR_KILLED;
      }
      else
      {
	ircstp->is_ref++;
	if (exit_client(cptr, LHcptr, &me, "I'm a leaf") == CPTR_KILLED)
	  return CPTR_KILLED;
      }
      /*
       * Did we kill the incoming server off already ?
       */
      if (killed)
	return 0;
    }
  }

  if (IsServer(cptr))
  {
    /*
     * Server is informing about a new server behind
     * this link. Create REMOTE server structure,
     * add it to list and propagate word to my other
     * server links...
     */

    acptr = make_client(cptr, STAT_SERVER);
    make_server(acptr);
    acptr->serv->prot = prot;
    acptr->serv->timestamp = timestamp;
    acptr->hopcount = hop;
    strncpy(acptr->name, host, sizeof(acptr->name) - 1);
    strncpy(acptr->info, info, sizeof(acptr->info) - 1);
    acptr->serv->up = sptr;
    acptr->serv->updown = add_dlink(&sptr->serv->down, acptr);
    /* Use cptr, because we do protocol 9 -> 10 translation
       for numeric nicks ! */
    SetServerYXX(cptr, acptr, parv[6]);
    Count_newremoteserver(nrof);
    if (Protocol(acptr) < 10)
      acptr->flags |= FLAGS_TS8;
    add_client_to_list(acptr);
    hAddClient(acptr);
    if (*parv[5] == 'J')
    {
      if (Protocol(acptr) > 9)
	SetBurst(acptr);
      sendto_op_mask(SNO_NETWORK, "Net junction: %s %s",
	  sptr->name, acptr->name);
      SetJunction(acptr);
    }
    /*
     * Old sendto_serv_but_one() call removed because we now need to send
     * different names to different servers (domain name matching).
     */
    for (i = 0; i <= highest_fd; i++)
    {
      if (!(bcptr = loc_clients[i]) || !IsServer(bcptr) ||
	  bcptr == cptr || IsMe(bcptr))
	continue;
      if (!(cconf = bcptr->serv->nline))
      {
	sendto_ops("Lost N-line for %s on %s. Closing",
	    get_client_name(cptr, TRUE), host);
	return exit_client(cptr, cptr, &me, "Lost N line");
      }
      if (match(my_name_for_link(me.name, cconf), acptr->name) == 0)
	continue;
      if (Protocol(bcptr) > 9)
	sendto_one(bcptr, "%s SERVER %s %d 0 %s %s %s%s 0 :%s",
	    NumServ(sptr), acptr->name, hop + 1, parv[4], parv[5],
	    NumServCap(acptr), acptr->info);
      else
	sendto_one(bcptr, ":%s SERVER %s %d 0 %s %s %s%s 0 :%s",
	    parv[0], acptr->name, hop + 1, parv[4], parv[5],
	    NumServCap(acptr), acptr->info);
    }
    return 0;
  }

  if (IsUnknown(cptr) || IsHandshake(cptr))
  {
    make_server(cptr);
    cptr->serv->timestamp = timestamp;
    cptr->serv->prot = prot;
    cptr->serv->ghost = ghost;
    SetServerYXX(cptr, cptr, parv[6]);
    if (start_timestamp > 780000000)
    {
#ifndef RELIABLE_CLOCK
#ifdef TESTNET
      sendto_ops("Debug: my start time: " TIME_T_FMT " ; others start time: "
	  TIME_T_FMT, me.serv->timestamp, start_timestamp);
      sendto_ops("Debug: receive time: " TIME_T_FMT " ; received timestamp: "
	  TIME_T_FMT " ; difference %ld",
	  recv_time, timestamp, timestamp - recv_time);
#endif
      if (start_timestamp < me.serv->timestamp)
      {
	sendto_ops("got earlier start time: " TIME_T_FMT " < " TIME_T_FMT,
	    start_timestamp, me.serv->timestamp);
	me.serv->timestamp = start_timestamp;
	TSoffset += timestamp - recv_time;
	sendto_ops("clock adjusted by adding %d", (int)(timestamp - recv_time));
      }
      else if ((start_timestamp > me.serv->timestamp) && IsUnknown(cptr))
	cptr->serv->timestamp = TStime();

      else if (timestamp != recv_time)
	/* Equal start times, we have a collision.  Let the connected-to server
	   decide. This assumes leafs issue more than half of the connection
	   attempts. */
      {
	if (IsUnknown(cptr))
	  cptr->serv->timestamp = TStime();
	else if (IsHandshake(cptr))
	{
	  sendto_ops("clock adjusted by adding %d",
	      (int)(timestamp - recv_time));
	  TSoffset += timestamp - recv_time;
	}
      }
#else /* RELIABLE CLOCK IS TRUE, we _always_ use our own clock */
      if (start_timestamp < me.serv->timestamp)
	me.serv->timestamp = start_timestamp;
      if (IsUnknown(cptr))
	cptr->serv->timestamp = TStime();
#endif
    }

    ret = m_server_estab(cptr, aconf, bconf);
  }
  else
    ret = 0;
#ifdef RELIABLE_CLOCK
  if (abs(cptr->serv->timestamp - recv_time) > 30)
  {
    sendto_ops("Connected to a net with a timestamp-clock"
	" difference of " STIME_T_FMT " seconds! Used SETTIME to correct"
	" this.", timestamp - recv_time);
    sendto_one(cptr, ":%s SETTIME " TIME_T_FMT " :%s",
	me.name, TStime(), me.name);
  }
#endif

  return ret;
}

/*
 * m_server_estab
 *
 * May only be called after a SERVER was received from cptr,
 * and thus make_server was called, and serv->prot set. --Run
 */
int m_server_estab(aClient *cptr, aConfItem *aconf, aConfItem *bconf)
{
  Reg3 aClient *acptr;
  char *inpath, *host;
  int split, i;

  split = (strCasediff(cptr->name, cptr->sockhost)
      && strnCasecmp(cptr->info, "JUPE", 4));
  inpath = get_client_name(cptr, TRUE);
  host = cptr->name;

  if (IsUnknown(cptr))
  {
    if (bconf->passwd[0])
      sendto_one(cptr, "PASS :%s", bconf->passwd);
    /*
     *  Pass my info to the new server
     */
    sendto_one(cptr, "SERVER %s 1 " TIME_T_FMT " " TIME_T_FMT " J%s %s%s :%s",
	my_name_for_link(me.name, aconf), me.serv->timestamp,
	cptr->serv->timestamp, MAJOR_PROTOCOL, NumServCap(&me),
	(me.info[0]) ? (me.info) : "IRCers United");

    IPcheck_connect_fail(cptr);	/* Don't charge this IP# for connecting */
  }

  det_confs_butmask(cptr,
      CONF_LEAF | CONF_HUB | CONF_NOCONNECT_SERVER | CONF_UWORLD);

  if (!IsHandshake(cptr))
    hAddClient(cptr);
  SetServer(cptr);
  Count_unknownbecomesserver(nrof);
  if (Protocol(cptr) > 9)
    SetBurst(cptr);
  else
    cptr->flags |= FLAGS_TS8;
  nextping = now;
  if (cptr->serv->user && *cptr->serv->by &&
      (acptr = findNUser(cptr->serv->by)) && acptr->user == cptr->serv->user)
  {
    if (MyUser(acptr) || Protocol(acptr->from) < 10)
      sendto_one(acptr, ":%s NOTICE %s :Link with %s established.",
	  me.name, acptr->name, inpath);
    else
      sendto_one(acptr, "%s NOTICE %s%s :Link with %s established.",
	  NumServ(&me), NumNick(acptr), inpath);
  }
  else
    acptr = NULL;
  sendto_lops_butone(acptr, "Link with %s established.", inpath);
  cptr->serv->up = &me;
  cptr->serv->updown = add_dlink(&me.serv->down, cptr);
  cptr->serv->nline = aconf;
  sendto_op_mask(SNO_NETWORK, "Net junction: %s %s", me.name, cptr->name);
  SetJunction(cptr);
  /*
   * Old sendto_serv_but_one() call removed because we now
   * need to send different names to different servers
   * (domain name matching) Send new server to other servers.
   */
  for (i = 0; i <= highest_fd; i++)
  {
    if (!(acptr = loc_clients[i]) || !IsServer(acptr) ||
	acptr == cptr || IsMe(acptr))
      continue;
    if ((aconf = acptr->serv->nline) &&
	!match(my_name_for_link(me.name, aconf), cptr->name))
      continue;
    if (split)
    {
      if (Protocol(acptr) > 9)
	sendto_one(acptr,
	    "%s SERVER %s 2 0 " TIME_T_FMT " %s%u %s%s 0 :[%s] %s",
	    NumServ(&me), cptr->name, cptr->serv->timestamp,
	    (Protocol(cptr) > 9) ? "J" : "J0", Protocol(cptr), NumServCap(cptr),
	    cptr->sockhost, cptr->info);
      else
	sendto_one(acptr,
	    ":%s SERVER %s 2 0 " TIME_T_FMT " %s%u %s%s 0 :[%s] %s", me.name,
	    cptr->name, cptr->serv->timestamp,
	    (Protocol(cptr) > 9) ? "J" : "J0", Protocol(cptr), NumServCap(cptr),
	    cptr->sockhost, cptr->info);
    }
    else
    {
      if (Protocol(acptr) > 9)
	sendto_one(acptr, "%s SERVER %s 2 0 " TIME_T_FMT " %s%u %s%s 0 :%s",
	    NumServ(&me), cptr->name, cptr->serv->timestamp,
	    (Protocol(cptr) > 9) ? "J" : "J0", Protocol(cptr),
	    NumServCap(cptr), cptr->info);
      else
	sendto_one(acptr, ":%s SERVER %s 2 0 " TIME_T_FMT " %s%u %s%s 0 :%s",
	    me.name, cptr->name, cptr->serv->timestamp,
	    (Protocol(cptr) > 9) ? "J" : "J0", Protocol(cptr),
	    NumServCap(cptr), cptr->info);
    }
  }

  /*
   * Pass on my client information to the new server
   *
   * First, pass only servers (idea is that if the link gets
   * cancelled beacause the server was already there,
   * there are no NICK's to be cancelled...). Of course,
   * if cancellation occurs, all this info is sent anyway,
   * and I guess the link dies when a read is attempted...? --msa
   *
   * Note: Link cancellation to occur at this point means
   * that at least two servers from my fragment are building
   * up connection this other fragment at the same time, it's
   * a race condition, not the normal way of operation...
   */

  aconf = cptr->serv->nline;
  for (acptr = &me; acptr; acptr = acptr->prev)
  {
    /* acptr->from == acptr for acptr == cptr */
    if (acptr->from == cptr)
      continue;
    if (IsServer(acptr))
    {
      char *protocol_str =
	  (Protocol(acptr) > 9) ? (IsBurst(acptr) ? "J" : "P") : "P0";
      if (match(my_name_for_link(me.name, aconf), acptr->name) == 0)
	continue;
      split = (MyConnect(acptr) && strCasediff(acptr->name, acptr->sockhost) &&
	  strnCasecmp(acptr->info, "JUPE", 4));
      if (split)
      {
	if (Protocol(cptr) > 9)
	  sendto_one(cptr,
	      "%s SERVER %s %d 0 " TIME_T_FMT " %s%u %s%s 0 :[%s] %s",
	      NumServ(acptr->serv->up), acptr->name,
	      acptr->hopcount + 1, acptr->serv->timestamp,
	      protocol_str, Protocol(acptr),
	      NumServCap(acptr), acptr->sockhost, acptr->info);
	else
	  sendto_one(cptr,
	      ":%s SERVER %s %d 0 " TIME_T_FMT " %s%u %s%s 0 :[%s] %s",
	      acptr->serv->up->name, acptr->name,
	      acptr->hopcount + 1, acptr->serv->timestamp,
	      protocol_str, Protocol(acptr),
	      NumServCap(acptr), acptr->sockhost, acptr->info);
      }
      else
      {
	if (Protocol(cptr) > 9)
	  sendto_one(cptr,
	      "%s SERVER %s %d 0 " TIME_T_FMT " %s%u %s%s 0 :%s",
	      NumServ(acptr->serv->up), acptr->name,
	      acptr->hopcount + 1, acptr->serv->timestamp,
	      protocol_str, Protocol(acptr), NumServCap(acptr), acptr->info);
	else
	  sendto_one(cptr,
	      ":%s SERVER %s %d 0 " TIME_T_FMT " %s%u %s%s 0 :%s",
	      acptr->serv->up->name, acptr->name,
	      acptr->hopcount + 1, acptr->serv->timestamp,
	      protocol_str, Protocol(acptr), NumServCap(acptr), acptr->info);
      }
    }
  }

  for (acptr = &me; acptr; acptr = acptr->prev)
  {
    /* acptr->from == acptr for acptr == cptr */
    if (acptr->from == cptr)
      continue;
    if (IsUser(acptr))
    {
      if (Protocol(cptr) < 10)
      {
	/*
	 * IsUser(x) is true only *BOTH* NICK and USER have
	 * been received. -avalon
	 * Or only NICK in new format. --Run
	 */
	sendto_one(cptr, ":%s NICK %s %d " TIME_T_FMT " %s %s %s :%s",
	    acptr->user->server->name,
	    acptr->name, acptr->hopcount + 1, acptr->lastnick,
	    acptr->user->username, acptr->user->host,
	    acptr->user->server->name, acptr->info);
	send_umode(cptr, acptr, 0, SEND_UMODES);
	send_user_joins(cptr, acptr);
      }
      else
      {
	char xxx_buf[8];
	char *s = umode_str(acptr);
	sendto_one(cptr, *s ?
	    "%s NICK %s %d " TIME_T_FMT " %s %s +%s %s %s%s :%s" :
	    "%s NICK %s %d " TIME_T_FMT " %s %s %s%s %s%s :%s",
	    NumServ(acptr->user->server),
	    acptr->name, acptr->hopcount + 1, acptr->lastnick,
	    acptr->user->username, acptr->user->host,
	    s, inttobase64(xxx_buf, ntohl(acptr->ip.s_addr), 6),
	    NumNick(acptr), acptr->info);
      }
    }
  }
  /*
   * Last, send the BURST.
   * (Or for 2.9 servers: pass all channels plus statuses)
   */
  {
    Reg1 aChannel *chptr;
    for (chptr = channel; chptr; chptr = chptr->nextch)
      send_channel_modes(cptr, chptr);
  }
  if (Protocol(cptr) >= 10)
    sendto_one(cptr, "%s END_OF_BURST", NumServ(&me));
  return 0;
}

/*
 * m_error
 *
 * parv[0] = sender prefix
 * parv[parc-1] = text
 */
int m_error(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 char *para;

  para = (parc > 1 && *parv[parc - 1] != '\0') ? parv[parc - 1] : "<>";

  Debug((DEBUG_ERROR, "Received ERROR message from %s: %s", sptr->name, para));
  /*
   * Ignore error messages generated by normal user clients
   * (because ill-behaving user clients would flood opers
   * screen otherwise). Pass ERROR's from other sources to
   * the local operator...
   */
  if (IsUser(cptr))
    return 0;
  if (IsUnknown(cptr))
    return exit_client_msg(cptr, cptr, &me, "Register first");

  if (cptr == sptr)
    sendto_ops("ERROR :from %s -- %s", get_client_name(cptr, FALSE), para);
  else
    sendto_ops("ERROR :from %s via %s -- %s",
	sptr->name, get_client_name(cptr, FALSE), para);

  if (sptr->serv)
  {
    RunFree(sptr->serv->last_error_msg);
    DupString(sptr->serv->last_error_msg, para);
  }

  return 0;
}

/*
 * m_end_of_burst  - Added Xorath 6-14-96, rewritten by Run 24-7-96
 *                 - and fixed by record and Kev 8/1/96
 *                 - and really fixed by Run 15/8/96 :p
 * This the last message in a net.burst.
 * It clears a flag for the server sending the burst.
 *
 * parv[0] - sender prefix
 */
int m_end_of_burst(aClient *cptr, aClient *sptr, int UNUSED(parc),
    char **UNUSED(parv))
{
  if (!IsServer(sptr))
    return 0;

  sendto_op_mask(SNO_NETWORK, "Completed net.burst from %s.", sptr->name);
#ifdef NO_PROTOCOL9
  sendto_serv_butone(cptr, "%s END_OF_BURST", NumServ(sptr));
#else
  sendto_highprot_butone(cptr, 10, "%s END_OF_BURST", NumServ(sptr));
#endif
  ClearBurst(sptr);
  SetBurstAck(sptr);
  if (MyConnect(sptr))
    sendto_one(sptr, "%s EOB_ACK", NumServ(&me));

  return 0;
}

/*
 * m_end_of_burst_ack
 *
 * This the acknowledge message of the `END_OF_BURST' message.
 * It clears a flag for the server receiving the burst.
 *
 * parv[0] - sender prefix
 */
int m_end_of_burst_ack(aClient *cptr, aClient *sptr, int UNUSED(parc),
    char **UNUSED(parv))
{
  if (!IsServer(sptr))
    return 0;

  sendto_op_mask(SNO_NETWORK, "%s acknowledged end of net.burst.", sptr->name);
#ifdef NO_PROTOCOL9
  sendto_serv_butone(cptr, "%s EOB_ACK", NumServ(sptr));
#else
  sendto_highprot_butone(cptr, 10, "%s EOB_ACK", NumServ(sptr));
#endif
  ClearBurstAck(sptr);

  return 0;
}

/*
 * m_desynch
 *
 * Writes to all +g users; for sending wall type debugging/anti-hack info.
 * Added 23 Apr 1998  --Run
 *
 * parv[0] - sender prefix
 * parv[parc-1] - message text
 */
int m_desynch(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  if (IsServer(sptr) && parc >= 2)
  {
    int i;
    aClient *acptr;
    /* Send message to local +g clients as if it were a wallops */
    sprintf_irc(sendbuf, ":%s WALLOPS :%s", parv[0], parv[parc - 1]);
    for (i = 0; i <= highest_fd; i++)
      if ((acptr = loc_clients[i]) && !IsServer(acptr) && !IsMe(acptr) &&
	  SendDebug(acptr))
	sendbufto_one(acptr);
    /* Send message to remote +g clients */
    sendto_g_serv_butone(cptr, "%s DESYNCH :%s", NumServ(sptr), parv[parc - 1]);
  }
  return 0;
}
