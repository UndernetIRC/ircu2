/*
 * IRC - Internet Relay Chat, ircd/m_server.c
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
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "send.h"
#include "userload.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * mr_server - registration message handler
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
 *    parv[7] = +hs (h == hub, s == service)
 */
int mr_server(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*            ch;
  int              i;
  char             info[REALLEN + 1];
  char*            host;
  struct Client*   acptr;
  struct Client*   bcptr;
  struct Client*   LHcptr = 0;
  struct ConfItem* aconf = 0;
  struct ConfItem* lhconf = 0;
  struct Jupe*     ajupe = 0;
  int              hop;
  int              ret;
  int              active_lh_line = 0;
  unsigned short   prot;
  time_t           start_timestamp;
  time_t           timestamp = 0;
  time_t           recv_time;
  time_t           ghost = 0;

  if (IsUserPort(cptr))
    return exit_client_msg(cptr, cptr, &me, 
                           "Cannot connect a server to a user port");

  recv_time = TStime();
  info[0] = '\0';

  if (parc < 8)
  {
    need_more_params(sptr, "SERVER");
    return exit_client(cptr, cptr, &me, "Need more parameters");
  }
  host = parv[1];

  if ((ajupe = jupe_find(host)) && JupeIsActive(ajupe))
    return exit_client_msg(cptr, sptr, &me, "Juped: %s", JupeReason(ajupe));

  log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE, "SERVER: %s %s[%s]", parv[1],
	    cli_sockhost(cptr), cli_sock_ip(cptr));

  /*
   * Detect protocol
   */
  if (strlen(parv[5]) != 3 || (parv[5][0] != 'P' && parv[5][0] != 'J'))
    return exit_client_msg(cptr, sptr, &me, "Bogus protocol (%s)", parv[5]);

  if (!IsServer(cptr))          /* Don't allow silently connecting a server */
    *parv[5] = 'J';

  if (*parv[7] == '+') {
    for (ch = parv[7] + 1; *ch; ch++)
      switch (*ch) {
      case 'h':
	SetHub(cptr);
	break;
      case 's':
	SetService(cptr);
	break;
      }
  }

  prot = atoi(parv[5] + 1);
  if (prot > atoi(MAJOR_PROTOCOL))
    prot = atoi(MAJOR_PROTOCOL);
  /*
   * Because the previous test is only in 2.10, the following is needed
   * till all servers are 2.10:
   */
  if (IsServer(cptr) && prot > Protocol(cptr))
    prot = Protocol(cptr);
  hop = atoi(parv[2]);
  start_timestamp = atoi(parv[3]);
  timestamp = atoi(parv[4]);
  Debug((DEBUG_INFO, "Got SERVER %s with timestamp [%s] age %Tu (%Tu)",
	 host, parv[4], start_timestamp, cli_serv(&me)->timestamp));

  if ((timestamp < OLDEST_TS || (hop == 1 && start_timestamp < OLDEST_TS)))
  {
    return exit_client_msg(cptr, sptr, &me,
        "Bogus timestamps (%s %s)", parv[3], parv[4]);
  }
  ircd_strncpy(info, parv[parc - 1], REALLEN);
  info[REALLEN] = '\0';
  if (prot < atoi(MINOR_PROTOCOL)) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Got incompatible protocol version "
			 "(%s) from %s", parv[5], cli_name(cptr));
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

  for (ch = host; *ch; ch++) {
    if (*ch <= ' ' || *ch > '~')
      break;
  }
  if (*ch || !strchr(host, '.')) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Bogus server name (%s) from %s",
			 host, cli_name(cptr));
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
    if ((lhconf = find_conf_byhost(cli_confs(cptr), cli_name(cptr), CONF_LEAF)) &&
        (!lhconf->port || (hop > lhconf->port)))
    {
      /*
       * L: lines normally come in pairs, here we try to
       * make sure that the oldest link is squitted, not
       * both.
       */
      active_lh_line = 1;
      if (timestamp <= cli_serv(cptr)->timestamp)
        LHcptr = 0;          /* Kill incoming server */
      else
        LHcptr = cptr;          /* Squit ourselfs */
    }
    else if (!(lhconf = find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_HUB)) ||
             (lhconf->port && (hop > lhconf->port)))
    {
      struct Client *ac3ptr;
      active_lh_line = 2;
      /* Look for net junction causing this: */
      LHcptr = 0;            /* incoming server */
      if (*parv[5] != 'J') {
        for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up) {
          if (IsJunction(ac3ptr)) {
            LHcptr = ac3ptr;
            break;
          }
        }
      }
    }
  }

  if (IsUnknown(cptr) || IsHandshake(cptr))
  {
    const char* encr;

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
    if (!EmptyString(cli_name(cptr)) && 
        (IsUnknown(cptr) || IsHandshake(cptr)) &&
        0 != ircd_strcmp(cli_name(cptr), host))
      hChangeClient(cptr, host);
    ircd_strncpy(cli_name(cptr), host, HOSTLEN);
    ircd_strncpy(cli_info(cptr), info[0] ? info : cli_name(&me), REALLEN);
    cli_hopcount(cptr) = hop;

    /* check connection rules */
    if (0 != conf_eval_crule(host, CRULE_ALL)) {
      ServerStats->is_ref++;
      sendto_opmask_butone(0, SNO_OLDSNO, "Refused connection from %s.", cli_name(cptr));
      return exit_client(cptr, cptr, &me, "Disallowed by connection rule");
    }

    if (conf_check_server(cptr)) {
      ++ServerStats->is_ref;
      sendto_opmask_butone(0, SNO_OLDSNO, "Received unauthorized connection "
			   "from %s.", cli_name(cptr));
      log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE, "Received unauthorized "
		"connection from %C [%s]", cptr,
		ircd_ntoa((const char *)&(cli_ip(cptr))));
      return exit_client(cptr, cptr, &me, "No C:line");
    }

    host = cli_name(cptr);

    update_load();

    if (!(aconf = find_conf_byname(cli_confs(cptr), host, CONF_SERVER))) {
      ++ServerStats->is_ref;
      sendto_opmask_butone(0, SNO_OLDSNO, "Access denied. No conf line for "
			   "server %s", cli_name(cptr));
      return exit_client_msg(cptr, cptr, &me,
          "Access denied. No conf line for server %s", cli_name(cptr));
    }
    encr = cli_passwd(cptr);

    if (*aconf->passwd && !!strcmp(aconf->passwd, encr)) {
      ++ServerStats->is_ref;
      sendto_opmask_butone(0, SNO_OLDSNO, "Access denied (passwd mismatch) %s",
			   cli_name(cptr));
      return exit_client_msg(cptr, cptr, &me,
          "No Access (passwd mismatch) %s", cli_name(cptr));
    }

    memset(cli_passwd(cptr), 0, sizeof(cli_passwd(cptr)));

    if (!feature_bool(FEAT_HUB)) {
      for (i = 0; i <= HighestFd; i++)
	if (LocalClientArray[i] && IsServer(LocalClientArray[i])) {
	  active_lh_line = 3;
	  LHcptr = 0;
	  break;
	}
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
      return exit_client_msg(cptr, cptr, &me, "nick collision with me (%s), check server number in M:?", host);
    /*
     * Detect wrong numeric.
     */
    if (0 != ircd_strcmp(cli_name(acptr), host)) {
      sendcmdto_serv_butone(&me, CMD_WALLOPS, cptr,
			    ":SERVER Numeric Collision: %s != %s",
			    cli_name(acptr), host);
      return exit_client_msg(cptr, cptr, &me,
          "NUMERIC collision between %s and %s."
          " Is your server numeric correct ?", host, cli_name(acptr));
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
    else if (IsServer(acptr) && (0 == ircd_strncmp(cli_info(acptr), "JUPE", 4) ||
        find_conf_byhost(cli_confs(cptr), cli_name(acptr), CONF_UWORLD)))
    {
      if (!IsServer(sptr))
        return exit_client(cptr, sptr, &me, cli_info(acptr));
      sendcmdto_serv_butone(&me, CMD_WALLOPS, cptr,
			    ":Received :%s SERVER %s from %s !?!", parv[0],
			    parv[1], cli_name(cptr));
      return exit_new_server(cptr, sptr, host, timestamp, "%s", cli_info(acptr));
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
      struct Client* c2ptr = 0;
      struct Client* c3ptr = acptr;
      struct Client* ac2ptr;
      struct Client* ac3ptr;

      /* Search youngest link: */
      for (ac3ptr = acptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up)
        if (cli_serv(ac3ptr)->timestamp > cli_serv(c3ptr)->timestamp)
          c3ptr = ac3ptr;
      if (IsServer(sptr))
      {
        for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up)
          if (cli_serv(ac3ptr)->timestamp > cli_serv(c3ptr)->timestamp)
            c3ptr = ac3ptr;
      }
      if (timestamp > cli_serv(c3ptr)->timestamp)
      {
        c3ptr = 0;
        c2ptr = acptr;          /* Make sure they differ */
      }
      /* Search second youngest link: */
      for (ac2ptr = acptr; ac2ptr != &me; ac2ptr = cli_serv(ac2ptr)->up)
        if (ac2ptr != c3ptr &&
            cli_serv(ac2ptr)->timestamp >
            (c2ptr ? cli_serv(c2ptr)->timestamp : timestamp))
          c2ptr = ac2ptr;
      if (IsServer(sptr))
      {
        for (ac2ptr = sptr; ac2ptr != &me; ac2ptr = cli_serv(ac2ptr)->up)
          if (ac2ptr != c3ptr &&
              cli_serv(ac2ptr)->timestamp >
              (c2ptr ? cli_serv(c2ptr)->timestamp : timestamp))
            c2ptr = ac2ptr;
      }
      if (c3ptr && timestamp > (c2ptr ? cli_serv(c2ptr)->timestamp : timestamp))
        c2ptr = 0;
      /* If timestamps are equal, decide which link to break
       *  by name.
       */
      if ((c2ptr ? cli_serv(c2ptr)->timestamp : timestamp) ==
          (c3ptr ? cli_serv(c3ptr)->timestamp : timestamp))
      {
        char* n2;
        char* n2up;
        char* n3;
        char* n3up;
        if (c2ptr)
        {
          n2 = cli_name(c2ptr);
          n2up = MyConnect(c2ptr) ? cli_name(&me) : cli_name(cli_serv(c2ptr)->up);
        }
        else
        {
          n2 = host;
          n2up = IsServer(sptr) ? cli_name(sptr) : cli_name(&me);
        }
        if (c3ptr)
        {
          n3 = cli_name(c3ptr);
          n3up = MyConnect(c3ptr) ? cli_name(&me) : cli_name(cli_serv(c3ptr)->up);
        }
        else
        {
          n3 = host;
          n3up = IsServer(sptr) ? cli_name(sptr) : cli_name(&me);
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
                               host, (long)cli_serv(acptr)->timestamp - (long)timestamp);
      else if (cli_from(c2ptr) == cptr || IsServer(sptr))
      {
        struct Client *killedptrfrom = cli_from(c2ptr);
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
          if (cli_from(c2ptr) == cptr || (LHcptr && a_kills_b_too(c2ptr, LHcptr)))
            active_lh_line = 0;
          else
          {
            /*
             * If we still have a L: or H: line problem,
             * we prefer to squit the new server, solving
             * loop and L:/H: line problem with only one squit.
             */
            LHcptr = 0;
            break;
          }
        }
        /*
         * If the new server was introduced by a server that caused a
         * Ghost less then 20 seconds ago, this is probably also
         * a Ghost... (20 seconds is more then enough because all
         * SERVER messages are at the beginning of a net.burst). --Run
         */
        if (CurrentTime - cli_serv(cptr)->ghost < 20)
        {
          killedptrfrom = cli_from(acptr);
          if (exit_client(cptr, acptr, &me, "Ghost loop") == CPTR_KILLED)
            return CPTR_KILLED;
        }
        else if (exit_client_msg(cptr, c2ptr, &me,
            "Loop <-- %s (new link is %ld seconds younger)", host,
            (c3ptr ? (long)cli_serv(c3ptr)->timestamp : timestamp) -
            (long)cli_serv(c2ptr)->timestamp) == CPTR_KILLED)
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
          if (cli_from(acptr) == cptr || (LHcptr && a_kills_b_too(acptr, LHcptr)))
            active_lh_line = 0;
          else
          {
            LHcptr = 0;
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
        ghost = CurrentTime;            /* Mark that it caused a ghost */
        if (exit_client(cptr, acptr, &me, "Ghost") == CPTR_KILLED)
          return CPTR_KILLED;
        break;
      }
    }
  }

  if (active_lh_line)
  {
    if (LHcptr == 0) {
      return exit_new_server(cptr, sptr, host, timestamp,
          (active_lh_line == 2) ?  "Non-Hub link %s <- %s(%s), check H:" : 
                                   "Leaf-only link %s <- %s(%s), check L:",
          cli_name(cptr), host, 
          lhconf ? (lhconf->name ? lhconf->name : "*") : "!");
    }
    else
    {
      int killed = a_kills_b_too(LHcptr, sptr);
      if (active_lh_line < 3)
      {
        if (exit_client_msg(cptr, LHcptr, &me,
            (active_lh_line == 2) ?  "Non-Hub link %s <- %s(%s), check H:" : 
                                     "Leaf-only link %s <- %s(%s), check L:",
            cli_name(cptr), host,
            lhconf ? (lhconf->name ? lhconf->name : "*") : "!") == CPTR_KILLED)
          return CPTR_KILLED;
      }
      else
      {
        ServerStats->is_ref++;
        if (exit_client(cptr, LHcptr, &me, "I'm a leaf, define HUB") == CPTR_KILLED)
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
    cli_serv(acptr)->prot = prot;
    cli_serv(acptr)->timestamp = timestamp;
    cli_hopcount(acptr) = hop;
    ircd_strncpy(cli_name(acptr), host, HOSTLEN);
    ircd_strncpy(cli_info(acptr), info, REALLEN);
    cli_serv(acptr)->up = sptr;
    cli_serv(acptr)->updown = add_dlink(&(cli_serv(sptr))->down, acptr);
    /* Use cptr, because we do protocol 9 -> 10 translation
       for numeric nicks ! */
    SetServerYXX(cptr, acptr, parv[6]);

    Count_newremoteserver(UserStats);
    if (Protocol(acptr) < 10)
      SetFlag(acptr, FLAG_TS8);
    add_client_to_list(acptr);
    hAddClient(acptr);
    if (*parv[5] == 'J')
    {
      SetBurst(acptr);
      sendto_opmask_butone(0, SNO_NETWORK, "Net junction: %s %s",
          cli_name(sptr), cli_name(acptr));
      SetJunction(acptr);
    }
    /*
     * Old sendto_serv_but_one() call removed because we now need to send
     * different names to different servers (domain name matching).
     *
     * Personally, I think this is bogus; it's a feature we don't use here.
     * -Kev
     */
    for (i = 0; i <= HighestFd; i++)
    {
      if (!(bcptr = LocalClientArray[i]) || !IsServer(bcptr) ||
          bcptr == cptr || IsMe(bcptr))
        continue;
      if (0 == match(cli_name(&me), cli_name(acptr)))
        continue;
      sendcmdto_one(sptr, CMD_SERVER, bcptr, "%s %d 0 %s %s %s%s +%s%s :%s",
		    cli_name(acptr), hop + 1, parv[4], parv[5],
		    NumServCap(acptr), IsHub(acptr) ? "h" : "",
		    IsService(acptr) ? "s" : "", cli_info(acptr));
    }
    return 0;
  }

  if (IsUnknown(cptr) || IsHandshake(cptr))
  {
    make_server(cptr);
    cli_serv(cptr)->timestamp = timestamp;
    cli_serv(cptr)->prot = prot;
    cli_serv(cptr)->ghost = ghost;
    SetServerYXX(cptr, cptr, parv[6]);
    if (start_timestamp > OLDEST_TS)
    {
      Debug((DEBUG_DEBUG, "My start time: %Tu; other's start time: %Tu",
	     cli_serv(&me)->timestamp, start_timestamp));
      Debug((DEBUG_DEBUG, "Receive time: %Tu; received timestamp: %Tu; "
	     "difference %ld", recv_time, timestamp, timestamp - recv_time));
      if (feature_bool(FEAT_RELIABLE_CLOCK)) {
	if (start_timestamp < cli_serv(&me)->timestamp)
	  cli_serv(&me)->timestamp = start_timestamp;
	if (IsUnknown(cptr))
	  cli_serv(cptr)->timestamp = TStime();
      } else {
	if (start_timestamp < cli_serv(&me)->timestamp) {
	  sendto_opmask_butone(0, SNO_OLDSNO, "got earlier start time: "
			       "%Tu < %Tu", start_timestamp,
			       cli_serv(&me)->timestamp);
	  cli_serv(&me)->timestamp = start_timestamp;
	  TSoffset += timestamp - recv_time;
	  sendto_opmask_butone(0, SNO_OLDSNO, "clock adjusted by adding %d",
			       (int)(timestamp - recv_time));
	} else if ((start_timestamp > cli_serv(&me)->timestamp) &&
		 IsUnknown(cptr))
	  cli_serv(cptr)->timestamp = TStime();

	else if (timestamp != recv_time) {
	  /*
	   * Equal start times, we have a collision.  Let the connected-to
	   * server decide. This assumes leafs issue more than half of the
	   * connection attempts.
	   */
	  if (IsUnknown(cptr))
	    cli_serv(cptr)->timestamp = TStime();
	  else if (IsHandshake(cptr)) {
	    sendto_opmask_butone(0, SNO_OLDSNO, "clock adjusted by adding %d",
				 (int)(timestamp - recv_time));
	    TSoffset += timestamp - recv_time;
	  }
	}
      }
    }

    ret = server_estab(cptr, aconf);
  }
  else
    ret = 0;

  if (feature_bool(FEAT_RELIABLE_CLOCK) &&
      abs(cli_serv(cptr)->timestamp - recv_time) > 30) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Connected to a net with a "
			 "timestamp-clock difference of %Td seconds! "
			 "Used SETTIME to correct this.",
			 timestamp - recv_time);
    sendcmdto_prio_one(&me, CMD_SETTIME, cptr, "%Tu :%s", TStime(),
		       cli_name(&me));
  }

  return ret;
}

/*
 * ms_server - server message handler
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
 *    parv[7] = +hs (h == hub, s == service)
 */
int ms_server(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*            ch;
  int              i;
  char             info[REALLEN + 1];
  char*            host;
  struct Client*   acptr;
  struct Client*   bcptr;
  struct Client*   LHcptr = 0;
  struct ConfItem* aconf = 0;
  struct ConfItem* lhconf = 0;
  int              hop;
  int              ret;
  int              active_lh_line = 0;
  unsigned short   prot;
  unsigned char    is_hub = 0;
  unsigned char    is_service = 0;
  time_t           start_timestamp;
  time_t           timestamp = 0;
  time_t           recv_time;
  time_t           ghost = 0;

  if (IsUserPort(cptr))
    return exit_client_msg(cptr, cptr, &me,
                           "Cannot connect a server to a user port");

  recv_time = TStime();
  info[0] = '\0';
  if (parc < 7)
  {
    return need_more_params(sptr, "SERVER");
    return exit_client(cptr, cptr, &me, "Need more parameters");
  }
  host = parv[1];

  /*
   * Detect protocol
   */
  if (strlen(parv[5]) != 3 || (parv[5][0] != 'P' && parv[5][0] != 'J'))
    return exit_client_msg(cptr, sptr, &me, "Bogus protocol (%s)", parv[5]);

  if (!IsServer(cptr))          /* Don't allow silently connecting a server */
    *parv[5] = 'J';

  if (*parv[7] == '+') {
    for (ch = parv[7] + 1; *ch; ch++)
      switch (*ch) {
      case 'h':
	is_hub = 1;
	break;
      case 's':
	is_service = 1;
	break;
      }
  }

  prot = atoi(parv[5] + 1);
  if (prot > atoi(MAJOR_PROTOCOL))
    prot = atoi(MAJOR_PROTOCOL);
  /*
   * Because the previous test is only in 2.10, the following is needed
   * till all servers are 2.10:
   */
  if (IsServer(cptr) && prot > Protocol(cptr))
    prot = Protocol(cptr);
  hop = atoi(parv[2]);
  start_timestamp = atoi(parv[3]);
  timestamp = atoi(parv[4]);
  Debug((DEBUG_INFO, "Got SERVER %s with timestamp [%s] age %Tu (%Tu)",
	 host, parv[4], start_timestamp, cli_serv(&me)->timestamp));
  if ((timestamp < OLDEST_TS || (hop == 1 && start_timestamp < OLDEST_TS)))
  {
    return exit_client_msg(cptr, sptr, &me,
        "Bogus timestamps (%s %s)", parv[3], parv[4]);
  }
  ircd_strncpy(info, parv[parc - 1], REALLEN);
  info[REALLEN] = '\0';
  if (prot < atoi(MINOR_PROTOCOL)) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Got incompatible protocol version "
			 "(%s) from %s", parv[5], cli_name(cptr));
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
  if (*ch || !strchr(host, '.')) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Bogus server name (%s) from %s",
			 host, cli_name(cptr));
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
    if ((lhconf = find_conf_byhost(cli_confs(cptr), cli_name(cptr), CONF_LEAF)) &&
        (!lhconf->port || (hop > lhconf->port)))
    {
      /*
       * L: lines normally come in pairs, here we try to
       * make sure that the oldest link is squitted, not
       * both.
       */
      active_lh_line = 1;
      if (timestamp <= cli_serv(cptr)->timestamp)
        LHcptr = 0;          /* Kill incoming server */
      else
        LHcptr = cptr;          /* Squit ourselfs */
    }
    else if (!(lhconf = find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_HUB)) ||
             (lhconf->port && (hop > lhconf->port)) ||
             (!BadPtr(lhconf->host) && match(lhconf->host, parv[1])))
    {
      struct Client *ac3ptr;
      active_lh_line = 2;
      /* Look for net junction causing this: */
      LHcptr = 0;            /* incoming server */
      if (*parv[5] != 'J') {
        for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up) {
          if (IsJunction(ac3ptr)) {
            LHcptr = ac3ptr;
            break;
          }
        }
      }
    }
  }

  if (IsUnknown(cptr) || IsHandshake(cptr))
  {
    const char* encr;

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
    if ((!(EmptyString(cli_name(cptr))))
        && (IsUnknown(cptr) || IsHandshake(cptr))
        && 0 != ircd_strcmp(cli_name(cptr), host))
      hChangeClient(cptr, host);
    ircd_strncpy(cli_name(cptr), host, HOSTLEN);
    ircd_strncpy(cli_info(cptr), info[0] ? info : cli_name(&me), REALLEN);
    cli_hopcount(cptr) = hop;

    /* check connection rules */
    if (0 != conf_eval_crule(host, CRULE_ALL)) {
      ServerStats->is_ref++;
      sendto_opmask_butone(0, SNO_OLDSNO, "Refused connection from %s.", cli_name(cptr));
      return exit_client(cptr, cptr, &me, "Disallowed by connection rule");
    }
    if (conf_check_server(cptr)) {
      ++ServerStats->is_ref;
      sendto_opmask_butone(0, SNO_OLDSNO, "Received unauthorized connection "
			   "from %s.", cli_name(cptr));
      log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE, "Received unauthorized "
		"connection from %C [%s]", cptr,
		ircd_ntoa((const char *)&(cli_ip(cptr))));
      return exit_client(cptr, cptr, &me, "No C conf lines");
    }

    host = cli_name(cptr);

    update_load();

    if (!(aconf = find_conf_byname(cli_confs(cptr), host, CONF_SERVER))) {
      ++ServerStats->is_ref;
      sendto_opmask_butone(0, SNO_OLDSNO, "Access denied. No conf line for "
			   "server %s", cli_name(cptr));
      return exit_client_msg(cptr, cptr, &me,
                             "Access denied. No conf line for server %s", cli_name(cptr));
    }
    encr = cli_passwd(cptr);

    if (*(aconf->passwd) && !!strcmp(aconf->passwd, encr)) {
      ++ServerStats->is_ref;
      sendto_opmask_butone(0, SNO_OLDSNO, "Access denied (passwd mismatch) %s",
			   cli_name(cptr));
      return exit_client_msg(cptr, cptr, &me,
                             "No Access (passwd mismatch) %s", cli_name(cptr));
    }
    memset(cli_passwd(cptr), 0, sizeof(cli_passwd(cptr)));

    if (!feature_bool(FEAT_HUB)) {
      for (i = 0; i <= HighestFd; i++)
	if (LocalClientArray[i] && IsServer(LocalClientArray[i])) {
	  active_lh_line = 3;
	  LHcptr = 0;
	  break;
	}
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
          "nick collision with me, check server number in M:? (%s)", host);
    /*
     * Detect wrong numeric.
     */
    if (0 != ircd_strcmp(cli_name(acptr), host))
    {
      sendcmdto_serv_butone(&me, CMD_WALLOPS, cptr,
			    ":SERVER Numeric Collision: %s != %s", cli_name(acptr),
			    host);
      return exit_client_msg(cptr, cptr, &me,
          "NUMERIC collision between %s and %s."
          " Is your server numeric correct ?", host, cli_name(acptr));
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
    else if (IsServer(acptr) && (0 == ircd_strncmp(cli_info(acptr), "JUPE", 4) ||
        find_conf_byhost(cli_confs(cptr), cli_name(acptr), CONF_UWORLD)))
    {
      if (!IsServer(sptr))
        return exit_client(cptr, sptr, &me, cli_info(acptr));
      sendcmdto_one(&me, CMD_WALLOPS, cptr, ":Received :%s SERVER %s "
		    "from %s !?!", parv[0], parv[1], cli_name(cptr));
      return exit_new_server(cptr, sptr, host, timestamp, "%s", cli_info(acptr));
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
      struct Client* c2ptr = 0;
      struct Client* c3ptr = acptr;
      struct Client* ac2ptr;
      struct Client* ac3ptr;

      /* Search youngest link: */
      for (ac3ptr = acptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up)
        if (cli_serv(ac3ptr)->timestamp > cli_serv(c3ptr)->timestamp)
          c3ptr = ac3ptr;
      if (IsServer(sptr))
      {
        for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up)
          if (cli_serv(ac3ptr)->timestamp > cli_serv(c3ptr)->timestamp)
            c3ptr = ac3ptr;
      }
      if (timestamp > cli_serv(c3ptr)->timestamp)
      {
        c3ptr = 0;
        c2ptr = acptr;          /* Make sure they differ */
      }
      /* Search second youngest link: */
      for (ac2ptr = acptr; ac2ptr != &me; ac2ptr = cli_serv(ac2ptr)->up)
        if (ac2ptr != c3ptr &&
            cli_serv(ac2ptr)->timestamp >
            (c2ptr ? cli_serv(c2ptr)->timestamp : timestamp))
          c2ptr = ac2ptr;
      if (IsServer(sptr))
      {
        for (ac2ptr = sptr; ac2ptr != &me; ac2ptr = cli_serv(ac2ptr)->up)
          if (ac2ptr != c3ptr &&
              cli_serv(ac2ptr)->timestamp >
              (c2ptr ? cli_serv(c2ptr)->timestamp : timestamp))
            c2ptr = ac2ptr;
      }
      if (c3ptr && timestamp > (c2ptr ? cli_serv(c2ptr)->timestamp : timestamp))
        c2ptr = 0;
      /* If timestamps are equal, decide which link to break
       *  by name.
       */
      if ((c2ptr ? cli_serv(c2ptr)->timestamp : timestamp) ==
          (c3ptr ? cli_serv(c3ptr)->timestamp : timestamp))
      {
        char* n2;
        char* n2up;
        char* n3;
        char* n3up;
        if (c2ptr)
        {
          n2 = cli_name(c2ptr);
          n2up = MyConnect(c2ptr) ? cli_name(&me) : cli_name(cli_serv(c2ptr)->up);
        }
        else
        {
          n2 = host;
          n2up = IsServer(sptr) ? cli_name(sptr) : cli_name(&me);
        }
        if (c3ptr)
        {
          n3 = cli_name(c3ptr);
          n3up = MyConnect(c3ptr) ? cli_name(&me) : cli_name(cli_serv(c3ptr)->up);
        }
        else
        {
          n3 = host;
          n3up = IsServer(sptr) ? cli_name(sptr) : cli_name(&me);
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
            host, (long)cli_serv(acptr)->timestamp - (long)timestamp);
      else if (cli_from(c2ptr) == cptr || IsServer(sptr))
      {
        struct Client *killedptrfrom = cli_from(c2ptr);
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
          if (cli_from(c2ptr) == cptr || (LHcptr && a_kills_b_too(c2ptr, LHcptr)))
            active_lh_line = 0;
          else
          {
            /*
             * If we still have a L: or H: line problem,
             * we prefer to squit the new server, solving
             * loop and L:/H: line problem with only one squit.
             */
            LHcptr = 0;
            break;
          }
        }
        /*
         * If the new server was introduced by a server that caused a
         * Ghost less then 20 seconds ago, this is probably also
         * a Ghost... (20 seconds is more then enough because all
         * SERVER messages are at the beginning of a net.burst). --Run
         */
        if (CurrentTime - cli_serv(cptr)->ghost < 20)
        {
          killedptrfrom = cli_from(acptr);
          if (exit_client(cptr, acptr, &me, "Ghost loop") == CPTR_KILLED)
            return CPTR_KILLED;
        }
        else if (exit_client_msg(cptr, c2ptr, &me,
            "Loop <-- %s (new link is %ld seconds younger)", host,
            (c3ptr ? (long)cli_serv(c3ptr)->timestamp : timestamp) -
            (long)cli_serv(c2ptr)->timestamp) == CPTR_KILLED)
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
          if (cli_from(acptr) == cptr || (LHcptr && a_kills_b_too(acptr, LHcptr)))
            active_lh_line = 0;
          else
          {
            LHcptr = 0;
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
        ghost = CurrentTime;            /* Mark that it caused a ghost */
        if (exit_client(cptr, acptr, &me, "Ghost") == CPTR_KILLED)
          return CPTR_KILLED;
        break;
      }
    }
  }

  if (active_lh_line)
  {
    if (LHcptr == 0) {
      return exit_new_server(cptr, sptr, host, timestamp,
          (active_lh_line == 2) ?  "Non-Hub link %s <- %s(%s)" : "Leaf-only link %s <- %s(%s)",
          cli_name(cptr), host,
          lhconf ? (lhconf->name ? lhconf->name : "*") : "!");
    }
    else
    {
      int killed = a_kills_b_too(LHcptr, sptr);
      if (active_lh_line < 3)
      {
        if (exit_client_msg(cptr, LHcptr, &me,
            (active_lh_line == 2) ?  "Non-Hub link %s <- %s(%s)" : "Leaf-only link %s <- %s(%s)",
            cli_name(cptr), host,
            lhconf ? (lhconf->name ? lhconf->name : "*") : "!") == CPTR_KILLED)
          return CPTR_KILLED;
      }
      else
      {
        ServerStats->is_ref++;
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
    cli_serv(acptr)->prot = prot;
    cli_serv(acptr)->timestamp = timestamp;
    cli_hopcount(acptr) = hop;
    if (is_hub)
      SetFlag(acptr, FLAG_HUB);
    if (is_service)
      SetFlag(acptr, FLAG_SERVICE);
    ircd_strncpy(cli_name(acptr), host, HOSTLEN);
    ircd_strncpy(cli_info(acptr), info, REALLEN);
    cli_serv(acptr)->up = sptr;
    cli_serv(acptr)->updown = add_dlink(&(cli_serv(sptr))->down, acptr);
    /* Use cptr, because we do protocol 9 -> 10 translation
       for numeric nicks ! */
    SetServerYXX(cptr, acptr, parv[6]);

    Count_newremoteserver(UserStats);
    if (Protocol(acptr) < 10)
      SetFlag(acptr, FLAG_TS8);
    add_client_to_list(acptr);
    hAddClient(acptr);
    if (*parv[5] == 'J')
    {
      SetBurst(acptr);
      sendto_opmask_butone(0, SNO_NETWORK, "Net junction: %s %s",
			   cli_name(sptr), cli_name(acptr));
      SetJunction(acptr);
    }
    /*
     * Old sendto_serv_but_one() call removed because we now need to send
     * different names to different servers (domain name matching).
     */
    for (i = 0; i <= HighestFd; i++)
    {
      if (!(bcptr = LocalClientArray[i]) || !IsServer(bcptr) ||
          bcptr == cptr || IsMe(bcptr))
        continue;
      if (0 == match(cli_name(&me), cli_name(acptr)))
        continue;
      sendcmdto_one(sptr, CMD_SERVER, bcptr, "%s %d 0 %s %s %s%s +%s%s :%s",
		    cli_name(acptr), hop + 1, parv[4], parv[5],
		    NumServCap(acptr), IsHub(acptr) ? "h" : "",
		    IsService(acptr) ? "s" : "", cli_info(acptr));
    }
    return 0;
  }

  if (IsUnknown(cptr) || IsHandshake(cptr))
  {
    make_server(cptr);
    cli_serv(cptr)->timestamp = timestamp;
    cli_serv(cptr)->prot = prot;
    cli_serv(cptr)->ghost = ghost;
    SetServerYXX(cptr, cptr, parv[6]);
    if (start_timestamp > OLDEST_TS)
    {
      Debug((DEBUG_DEBUG, "My start time: %Tu; other's start time: %Tu",
	     cli_serv(&me)->timestamp, start_timestamp));
      Debug((DEBUG_DEBUG, "Receive time: %Tu; received timestamp: %Tu; "
	     "difference %ld", recv_time, timestamp, timestamp - recv_time));
      if (feature_bool(FEAT_RELIABLE_CLOCK)) {
	if (start_timestamp < cli_serv(&me)->timestamp)
	  cli_serv(&me)->timestamp = start_timestamp;
	if (IsUnknown(cptr))
	  cli_serv(cptr)->timestamp = TStime();
      } else {
	if (start_timestamp < cli_serv(&me)->timestamp) {
	  sendto_opmask_butone(0, SNO_OLDSNO, "got earlier start time: "
			       "%Tu < %Tu", start_timestamp,
			       cli_serv(&me)->timestamp);
	  cli_serv(&me)->timestamp = start_timestamp;
	  TSoffset += timestamp - recv_time;
	  sendto_opmask_butone(0, SNO_OLDSNO, "clock adjusted by adding %d",
			       (int)(timestamp - recv_time));
	} else if ((start_timestamp > cli_serv(&me)->timestamp) &&
		   IsUnknown(cptr))
	  cli_serv(cptr)->timestamp = TStime();

	else if (timestamp != recv_time) {
	  /*
	   * Equal start times, we have a collision.  Let the connected-to
	   * server decide. This assumes leafs issue more than half of the
	   * connection attempts.
	   */
	  if (IsUnknown(cptr))
	    cli_serv(cptr)->timestamp = TStime();
	  else if (IsHandshake(cptr)) {
	    sendto_opmask_butone(0, SNO_OLDSNO, "clock adjusted by adding %d",
				 (int)(timestamp - recv_time));
	    TSoffset += timestamp - recv_time;
	  }
	}
      }
    }

    ret = server_estab(cptr, aconf);
  }
  else
    ret = 0;

  if (feature_bool(FEAT_RELIABLE_CLOCK) &&
      abs(cli_serv(cptr)->timestamp - recv_time) > 30) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Connected to a net with a "
			 "timestamp-clock difference of %Td seconds! Used "
			 "SETTIME to correct this.", timestamp - recv_time);
    sendcmdto_prio_one(&me, CMD_SETTIME, cptr, "%Tu :%s", TStime(),
		       cli_name(&me));
  }

  return ret;
}
