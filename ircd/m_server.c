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
 */
/** @file
 * @brief Handlers for the SERVER command.
 * @version $Id$
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

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Clean up a server name.
 * @param[in] host Input server name.
 * @return NULL if the name is invalid, else pointer to cleaned-up name.
 */
static char *
clean_servername(char *host)
{
  char*            ch;
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
  if (*ch || !strchr(host, '.') || strlen(host) > HOSTLEN)
    return NULL;
  return host;
}

/** Parse protocol version from a string.
 * @param[in] proto String version of protocol number.
 * @return Zero if \a proto is unrecognized, else protocol version.
 */
static unsigned short
parse_protocol(const char *proto)
{
  unsigned short prot;
  if (strlen(proto) != 3 || (proto[0] != 'P' && proto[0] != 'J'))
    return 0;
  prot = atoi(proto+1);
  if (prot > atoi(MAJOR_PROTOCOL))
    prot = atoi(MAJOR_PROTOCOL);
  return prot;
}

/** Reason not to accept a server's new announcement. */
enum lh_type {
  ALLOWED, /**< The new server link is accepted. */
  MAX_HOPS_EXCEEDED, /**< The path to the server is too long. */
  NOT_ALLOWED_TO_HUB, /**< My peer is not allowed to hub for the server. */
  I_AM_NOT_HUB /**< I have another active server link but not FEAT_HUB. */
};

/** Check whether the introduction of a new server would cause a loop
 * or be disallowed by leaf and hub configuration directives.
 * @param[in] cptr Neighbor who sent the message.
 * @param[in] sptr Client that originated the message.
 * @param[out] ghost If non-NULL, receives ghost timestamp for new server.
 * @param[in] host Name of new server.
 * @param[in] numnick Numnick mask of new server.
 * @param[in] timestamp Claimed link timestamp of new server.
 * @param[in] hop Number of hops to the new server.
 * @param[in] junction Non-zero if the new server is still bursting.
 * @return CPTR_KILLED if \a cptr was SQUIT.  0 if some other server
 * was SQUIT.  1 if the new server is allowed.
 */
static int
check_loop_and_lh(struct Client* cptr, struct Client *sptr, time_t *ghost, const char *host, const char *numnick, time_t timestamp, int hop, int junction)
{
  struct Client* acptr;
  struct Client* LHcptr = NULL;
  struct ConfItem* lhconf;
  enum lh_type active_lh_line = ALLOWED;
  int ii;

  if (ghost)
    *ghost = 0;

  /*
   * Calculate type of connect limit and applicable config item.
   */
  lhconf = find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_SERVER);
  assert(lhconf != NULL);
  if (ghost)
  {
    if (!feature_bool(FEAT_HUB))
      for (ii = 0; ii <= HighestFd; ii++)
        if (LocalClientArray[ii] && IsServer(LocalClientArray[ii])) {
          active_lh_line = I_AM_NOT_HUB;
          break;
        }
  }
  else if (hop > lhconf->maximum)
  {
    /* Because "maximum" should be 0 for non-hub links, check whether
     * there is a hub mask -- if not, complain that the server isn't
     * allowed to hub.
     */
    active_lh_line = lhconf->hub_limit ? MAX_HOPS_EXCEEDED : NOT_ALLOWED_TO_HUB;
  }
  else if (lhconf->hub_limit && match(lhconf->hub_limit, host))
  {
    struct Client *ac3ptr;
    active_lh_line = NOT_ALLOWED_TO_HUB;
    if (junction)
      for (ac3ptr = sptr; ac3ptr != &me; ac3ptr = cli_serv(ac3ptr)->up)
        if (IsJunction(ac3ptr)) {
          LHcptr = ac3ptr;
          break;
        }
  }

  /*
   *  We want to find IsConnecting() and IsHandshake() too,
   *  use FindClient().
   *  The second finds collisions with numeric representation of existing
   *  servers - these shouldn't happen anymore when all upgraded to 2.10.
   *  -- Run
   */
  while ((acptr = FindClient(host))
         || (numnick && (acptr = FindNServer(numnick))))
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
    if (0 != ircd_strcmp(cli_name(acptr), host))
    {
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
      if (active_lh_line == ALLOWED && exit_client(cptr, acptr, &me,
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
     * This is a doubtful test though, what else would it be
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
			    ":Received :%s SERVER %s from %s !?!",
                            NumServ(cptr), host, cli_name(cptr));
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
        const char *n2, *n2up, *n3, *n3up;
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
        if (active_lh_line != ALLOWED)
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
            active_lh_line = ALLOWED;
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
        if (active_lh_line != ALLOWED)
        {
          if (LHcptr && a_kills_b_too(LHcptr, acptr))
            break;
          if (cli_from(acptr) == cptr || (LHcptr && a_kills_b_too(acptr, LHcptr)))
            active_lh_line = ALLOWED;
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
        if (ghost)
          *ghost = CurrentTime;            /* Mark that it caused a ghost */
        if (exit_client(cptr, acptr, &me, "Ghost") == CPTR_KILLED)
          return CPTR_KILLED;
        break;
      }
    }
  }

  if (active_lh_line != ALLOWED)
  {
    if (!LHcptr)
      LHcptr = sptr;
    if (active_lh_line == MAX_HOPS_EXCEEDED)
    {
      return exit_client_msg(cptr, LHcptr, &me,
                             "Maximum hops exceeded for %s at %s",
                             cli_name(cptr), host);
    }
    else if (active_lh_line == NOT_ALLOWED_TO_HUB)
    {
      return exit_client_msg(cptr, LHcptr, &me,
                             "%s is not allowed to hub for %s",
                             cli_name(cptr), host);
    }
    else /* I_AM_NOT_HUB */
    {
      ++ServerStats->is_not_hub;
      return exit_client(cptr, LHcptr, &me, "I'm a leaf, define the HUB feature");
    }
  }

  return 1;
}

/** Update server start timestamps and TS offsets.
 * @param[in] cptr Server that just connected.
 * @param[in] timestamp Current time according to \a cptr.
 * @param[in] start_timestamp Time that \a cptr started.
 * @param[in] recv_time Current time as we know it.
 */
static void
check_start_timestamp(struct Client *cptr, time_t timestamp, time_t start_timestamp, time_t recv_time)
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
  } else if (start_timestamp < cli_serv(&me)->timestamp) {
    sendto_opmask_butone(0, SNO_OLDSNO, "got earlier start time: "
                         "%Tu < %Tu", start_timestamp,
                         cli_serv(&me)->timestamp);
    cli_serv(&me)->timestamp = start_timestamp;
    TSoffset += timestamp - recv_time;
    sendto_opmask_butone(0, SNO_OLDSNO, "clock adjusted by adding %d",
                         (int)(timestamp - recv_time));
  } else if ((start_timestamp > cli_serv(&me)->timestamp) &&
             IsUnknown(cptr)) {
    cli_serv(cptr)->timestamp = TStime();
  } else if (timestamp != recv_time) {
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

/** Interpret a server's flags.
 *
 * @param[in] cptr New server structure.
 * @param[in] flags String listing server's P10 flags.
 */
void set_server_flags(struct Client *cptr, const char *flags)
{
    while (*flags) switch (*flags++) {
    case 'h': SetHub(cptr); break;
    case 's': SetService(cptr); break;
    case '6': SetIPv6(cptr); break;
    }
}

/** Handle a SERVER message from an unregistered connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the server name
 * \li \a parv[2] is the hop count to the server
 * \li \a parv[3] is the start timestamp for the server
 * \li \a parv[4] is the link timestamp
 * \li \a parv[5] is the protocol version (P10 or J10)
 * \li \a parv[6] is the numnick mask for the server
 * \li \a parv[7] is a string of flags like +hs to mark hubs and services
 * \li \a parv[\a parc - 1] is the server description
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mr_server(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*            host;
  struct ConfItem* aconf;
  struct Jupe*     ajupe;
  int              hop;
  int              ret;
  unsigned short   prot;
  time_t           start_timestamp;
  time_t           timestamp;
  time_t           recv_time;
  time_t           ghost;

  if (IsUserPort(cptr))
    return exit_client_msg(cptr, cptr, &me,
                           "Cannot connect a server to a user port");

  if (parc < 8)
  {
    need_more_params(sptr, "SERVER");
    return exit_client(cptr, cptr, &me, "Need more parameters");
  }
  host = clean_servername(parv[1]);
  if (!host)
  {
    sendto_opmask_butone(0, SNO_OLDSNO, "Bogus server name (%s) from %s",
			 host, cli_name(cptr));
    return exit_client_msg(cptr, cptr, &me, "Bogus server name (%s)", host);
  }

  if ((ajupe = jupe_find(host)) && JupeIsActive(ajupe))
    return exit_client_msg(cptr, sptr, &me, "Juped: %s", JupeReason(ajupe));

  /* check connection rules */
  if (0 != conf_eval_crule(host, CRULE_ALL)) {
    ++ServerStats->is_crule_fail;
    sendto_opmask_butone(0, SNO_OLDSNO, "Refused connection from %s.", cli_name(cptr));
    return exit_client(cptr, cptr, &me, "Disallowed by connection rule");
  }

  log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE, "SERVER: %s %s[%s]", host,
	    cli_sockhost(cptr), cli_sock_ip(cptr));

  /*
   * Detect protocol
   */
  hop = atoi(parv[2]);
  start_timestamp = atoi(parv[3]);
  timestamp = atoi(parv[4]);
  prot = parse_protocol(parv[5]);
  if (!prot)
    return exit_client_msg(cptr, sptr, &me, "Bogus protocol (%s)", parv[5]);
  else if (prot < atoi(MINOR_PROTOCOL))
    return exit_new_server(cptr, sptr, host, timestamp,
                           "Incompatible protocol: %s", parv[5]);

  Debug((DEBUG_INFO, "Got SERVER %s with timestamp [%s] age %Tu (%Tu)",
	 host, parv[4], start_timestamp, cli_serv(&me)->timestamp));

  if (timestamp < OLDEST_TS || start_timestamp < OLDEST_TS)
    return exit_client_msg(cptr, sptr, &me,
        "Bogus timestamps (%s %s)", parv[3], parv[4]);

  /* If the server had a different name before, change it. */
  if (!EmptyString(cli_name(cptr)) &&
      (IsUnknown(cptr) || IsHandshake(cptr)) &&
      0 != ircd_strcmp(cli_name(cptr), host))
    hChangeClient(cptr, host);
  ircd_strncpy(cli_name(cptr), host, HOSTLEN);
  ircd_strncpy(cli_info(cptr), parv[parc-1][0] ? parv[parc-1] : cli_name(&me), REALLEN);
  cli_hopcount(cptr) = hop;

  if (conf_check_server(cptr)) {
    ++ServerStats->is_not_server;
    sendto_opmask_butone(0, SNO_OLDSNO, "Received unauthorized connection "
                         "from %s.", cli_name(cptr));
    log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE, "Received unauthorized "
              "connection from %C [%s]", cptr,
              ircd_ntoa(&cli_ip(cptr)));
    return exit_client(cptr, cptr, &me, "No Connect block");
  }

  host = cli_name(cptr);

  update_load();

  if (!(aconf = find_conf_byname(cli_confs(cptr), host, CONF_SERVER))) {
    ++ServerStats->is_not_server;
    sendto_opmask_butone(0, SNO_OLDSNO, "Access denied. No conf line for "
                         "server %s", cli_name(cptr));
    return exit_client_msg(cptr, cptr, &me,
                           "Access denied. No conf line for server %s", cli_name(cptr));
  }

  if (*aconf->passwd && !!strcmp(aconf->passwd, cli_passwd(cptr))) {
    ++ServerStats->is_bad_server;
    sendto_opmask_butone(0, SNO_OLDSNO, "Access denied (passwd mismatch) %s",
                         cli_name(cptr));
    return exit_client_msg(cptr, cptr, &me,
                           "No Access (passwd mismatch) %s", cli_name(cptr));
  }

  memset(cli_passwd(cptr), 0, sizeof(cli_passwd(cptr)));

  ret = check_loop_and_lh(cptr, sptr, &ghost, host, (parc > 7 ? parv[6] : NULL), timestamp, hop, 1);
  if (ret != 1)
    return ret;

  make_server(cptr);
  cli_serv(cptr)->timestamp = timestamp;
  cli_serv(cptr)->prot = prot;
  cli_serv(cptr)->ghost = ghost;
  memset(cli_privs(cptr), 255, sizeof(struct Privs));
  ClrPriv(cptr, PRIV_SET);
  SetServerYXX(cptr, cptr, parv[6]);

  /* Attach any necessary UWorld config items. */
  attach_confs_byhost(cptr, host, CONF_UWORLD);

  if (*parv[7] == '+')
    set_server_flags(cptr, parv[7] + 1);

  recv_time = TStime();
  check_start_timestamp(cptr, timestamp, start_timestamp, recv_time);
  ret = server_estab(cptr, aconf);

  if (feature_bool(FEAT_RELIABLE_CLOCK) &&
      labs(cli_serv(cptr)->timestamp - recv_time) > 30) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Connected to a net with a "
			 "timestamp-clock difference of %Td seconds! "
			 "Used SETTIME to correct this.",
			 timestamp - recv_time);
    sendcmdto_prio_one(&me, CMD_SETTIME, cptr, "%Tu :%s", TStime(),
		       cli_name(&me));
  }

  return ret;
}

/** Handle a SERVER message from another server.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the server name
 * \li \a parv[2] is the hop count to the server
 * \li \a parv[3] is the start timestamp for the server
 * \li \a parv[4] is the link timestamp
 * \li \a parv[5] is the protocol version (P10 or J10)
 * \li \a parv[6] is the numnick mask for the server
 * \li \a parv[7] is a string of flags like +hs to mark hubs and services
 * \li \a parv[\a parc - 1] is the server description
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_server(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int              i;
  char*            host;
  struct Client*   acptr;
  struct Client*   bcptr;
  int              hop;
  int              ret;
  unsigned short   prot;
  time_t           start_timestamp;
  time_t           timestamp;

  if (parc < 8)
  {
    return need_more_params(sptr, "SERVER");
  }
  host = clean_servername(parv[1]);
  if (!host)
  {
    sendto_opmask_butone(0, SNO_OLDSNO, "Bogus server name (%s) from %s",
			 host, cli_name(cptr));
    return exit_client_msg(cptr, cptr, &me, "Bogus server name (%s)", host);
  }

  /*
   * Detect protocol
   */
  hop = atoi(parv[2]);
  start_timestamp = atoi(parv[3]);
  timestamp = atoi(parv[4]);
  prot = parse_protocol(parv[5]);
  if (!prot)
    return exit_client_msg(cptr, sptr, &me, "Bogus protocol (%s)", parv[5]);
  else if (prot < atoi(MINOR_PROTOCOL))
    return exit_new_server(cptr, sptr, host, timestamp,
                           "Incompatible protocol: %s", parv[5]);

  Debug((DEBUG_INFO, "Got SERVER %s with timestamp [%s] age %Tu (%Tu)",
	 host, parv[4], start_timestamp, cli_serv(&me)->timestamp));

  if (timestamp < OLDEST_TS)
    return exit_client_msg(cptr, sptr, &me,
        "Bogus timestamps (%s %s)", parv[3], parv[4]);

  if (parv[parc - 1][0] == '\0')
    return exit_client_msg(cptr, cptr, &me,
                           "No server info specified for %s", host);

  ret = check_loop_and_lh(cptr, sptr, NULL, host, (parc > 7 ? parv[6] : NULL), timestamp, hop, parv[5][0] == 'J');
  if (ret != 1)
    return ret;

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
  ircd_strncpy(cli_info(acptr), parv[parc-1], REALLEN);
  cli_serv(acptr)->up = sptr;
  cli_serv(acptr)->updown = add_dlink(&(cli_serv(sptr))->down, acptr);
  /* Use cptr, because we do protocol 9 -> 10 translation
     for numeric nicks ! */
  SetServerYXX(cptr, acptr, parv[6]);

  /* Attach any necessary UWorld config items. */
  attach_confs_byhost(cptr, host, CONF_UWORLD);

  if (*parv[7] == '+')
    set_server_flags(acptr, parv[7] + 1);

  Count_newremoteserver(UserStats);
  if (Protocol(acptr) < 10)
    SetFlag(acptr, FLAG_TS8);
  add_client_to_list(acptr);
  hAddClient(acptr);
  if (*parv[5] == 'J')
  {
    SetBurst(acptr);
    SetJunction(acptr);
    for (bcptr = cli_serv(acptr)->up; !IsMe(bcptr); bcptr = cli_serv(bcptr)->up)
      if (IsBurstOrBurstAck(bcptr))
          break;
    if (IsMe(bcptr))
      sendto_opmask_butone(0, SNO_NETWORK, "Net junction: %s %s",
                           cli_name(sptr), cli_name(acptr));
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
    sendcmdto_one(sptr, CMD_SERVER, bcptr, "%s %d 0 %s %s %s%s +%s%s%s :%s",
                  cli_name(acptr), hop + 1, parv[4], parv[5],
                  NumServCap(acptr), IsHub(acptr) ? "h" : "",
                  IsService(acptr) ? "s" : "", IsIPv6(acptr) ? "6" : "",
                  cli_info(acptr));
  }
  return 0;
}
