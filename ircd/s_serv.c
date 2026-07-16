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
/** @file
 * @brief Miscellaneous server support functions.
 * @version $Id$
 */
#include "config.h"

#include "s_serv.h"
#include "IPcheck.h"
#include "channel.h"
#include "client.h"
#include "gline.h"
#include "sline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_netconf.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_crypt.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"
#include "sasl.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/* Forward declaration */
static void assign_secure_group(struct Client *cptr, int sid);

/* Static variable to track the next available secure group ID */
static int next_secure_group_id = 1;
/** Maximum connection count since last restart. */
unsigned int max_connection_count = 0;
/** Maximum (local) client count since last restart. */
unsigned int max_client_count = 0;

/** Squit a new (pre-burst) server.
 * @param cptr Local client that tried to introduce the server.
 * @param sptr Server to disconnect.
 * @param host Name of server being disconnected.
 * @param timestamp Link time of server being disconnected.
 * @param pattern Format string for squit message.
 * @return CPTR_KILLED if cptr == sptr, else 0.
 */
int exit_new_server(struct Client *cptr, struct Client *sptr, const char *host,
                    time_t timestamp, const char *pattern, ...)
{
  struct VarData vd;
  int retval = 0;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  if (!IsServer(sptr))
    retval = vexit_client_msg(cptr, cptr, &me, pattern, vd.vd_args);
  else
    sendcmdto_one(&me, CMD_SQUIT, cptr, "%s %Tu :%v", host, timestamp, &vd);

  va_end(vd.vd_args);

  return retval;
}

/** Indicate whether \a a is between \a b and #me (that is, \a b would
 * be killed if \a a squits).
 * @param a A server that may be between us and \a b.
 * @param b A client that may be on the far side of \a a.
 * @return Non-zero if \a a is between \a b and #me.
 */
int a_kills_b_too(struct Client *a, struct Client *b)
{
  for (; b != a && b != &me; b = cli_serv(b)->up);
  return (a == b ? 1 : 0);
}

/** Handle a connection that has sent a valid PASS and SERVER.
 * @param cptr New peer server.
 * @param aconf Connect block for \a cptr.
 * @return Zero.
 */
int server_estab(struct Client *cptr, struct ConfItem *aconf)
{
  struct Client* acptr = 0;
  const char*    inpath;
  int            i;

  assert(0 != cptr);
  assert(0 != cli_local(cptr));

  inpath = cli_name(cptr);

  if (IsUnknown(cptr)) {
    if (aconf->passwd[0])
      sendrawto_one(cptr, MSG_PASS " :%s", aconf->passwd);
    /*
     *  Pass my info to the new server
     */
    sendrawto_one(cptr, MSG_SERVER " %s 1 %Tu %Tu J%s %s%s +%s6 :%s",
		  cli_name(&me), cli_serv(&me)->timestamp,
		  cli_serv(cptr)->timestamp, MAJOR_PROTOCOL, NumServCap(&me),
		  feature_bool(FEAT_HUB) ? "h" : "",
		  *(cli_info(&me)) ? cli_info(&me) : "IRCers United");
  }

  det_confs_butmask(cptr, CONF_SERVER | CONF_UWORLD);

  if (!IsHandshake(cptr))
    hAddClient(cptr);
  SetServer(cptr);
  cli_handler(cptr) = SERVER_HANDLER;
  Count_unknownbecomesserver(UserStats);
  SetBurst(cptr);

/*    nextping = CurrentTime; */

  /*
   * NOTE: check for acptr->user == cptr->serv->user is necessary to insure
   * that we got the same one... bleah
   */
  if (cli_serv(cptr)->user && *(cli_serv(cptr))->by &&
      (acptr = findNUser(cli_serv(cptr)->by))) {
    if (cli_user(acptr) == cli_serv(cptr)->user) {
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Link with %s established.",
                    acptr, inpath);
    }
    else {
      /*
       * if not the same client, set by to empty string
       */
      acptr = 0;
      *(cli_serv(cptr))->by = '\0';
    }
  }

  sendto_opmask_butone(acptr, SNO_OLDSNO, "Link with %s established.", inpath);
  cli_serv(cptr)->up = &me;
  cli_serv(cptr)->updown = add_dlink(&(cli_serv(&me))->down, cptr);
  sendto_opmask_butone(0, SNO_NETWORK, "Net junction: %s %s", cli_name(&me),
                       cli_name(cptr));
  SetJunction(cptr);
  /*
   * Old sendto_serv_but_one() call removed because we now
   * need to send different names to different servers
   * (domain name matching) Send new server to other servers.
   */
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(acptr = LocalClientArray[i]) || !IsServer(acptr) ||
        acptr == cptr || IsMe(acptr))
      continue;
    if (!match(cli_name(&me), cli_name(cptr)))
      continue;
    sendcmdto_one(&me, CMD_SERVER, acptr,
		  "%s 2 0 %Tu J%02u %s%s +%s%s%s%s :%s", cli_name(cptr),
		  cli_serv(cptr)->timestamp, Protocol(cptr), NumServCap(cptr),
		  IsHub(cptr) ? "h" : "", IsService(cptr) ? "s" : "",
		  IsIPv6(cptr) ? "6" : "", IsTLS(cptr) ? "z" : "", cli_info(cptr));
  }

  /* Send these as early as possible so that glined users/juped servers can
   * be removed from the network while the remote server is still chewing
   * our burst.
   */
  gline_burst(cptr);
  jupe_burst(cptr);
  sline_burst(cptr);

  /* Burst server configuration. */
  config_burst(cptr);

  /*
   * Pass on my client information to the new server
   *
   * First, pass only servers (idea is that if the link gets
   * canceled because the server was already there,
   * there are no NICK's to be canceled...). Of course,
   * if cancellation occurs, all this info is sent anyway,
   * and I guess the link dies when a read is attempted...? --msa
   *
   * Note: Link cancellation to occur at this point means
   * that at least two servers from my fragment are building
   * up connection this other fragment at the same time, it's
   * a race condition, not the normal way of operation...
   */

  for (acptr = &me; acptr; acptr = cli_prev(acptr)) {
    /* acptr->from == acptr for acptr == cptr */
    if (cli_from(acptr) == cptr)
      continue;
    if (IsServer(acptr)) {
      const char* protocol_str;

      if (Protocol(acptr) > 9)
        protocol_str = IsBurst(acptr) ? "J" : "P";
      else
        protocol_str = IsBurst(acptr) ? "J0" : "P0";

      if (0 == match(cli_name(&me), cli_name(acptr)))
        continue;
      sendcmdto_one(cli_serv(acptr)->up, CMD_SERVER, cptr,
		    "%s %d 0 %Tu %s%u %s%s +%s%s%s%s :%s", cli_name(acptr),
		    cli_hopcount(acptr) + 1, cli_serv(acptr)->timestamp,
		    protocol_str, Protocol(acptr), NumServCap(acptr),
		    IsHub(acptr) ? "h" : "", IsService(acptr) ? "s" : "",
		    IsIPv6(acptr) ? "6" : "", IsTLS(acptr) ? "z" : "", cli_info(acptr));
    }
  }

  for (acptr = &me; acptr; acptr = cli_prev(acptr))
  {
    /* acptr->from == acptr for acptr == cptr */
    if (cli_from(acptr) == cptr)
      continue;
    if (IsUser(acptr))
    {
      char xxx_buf[25];
      char *s = umode_str(acptr);
      sendcmdto_one(cli_user(acptr)->server, CMD_NICK, cptr,
		    "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
		    cli_name(acptr), cli_hopcount(acptr) + 1, cli_lastnick(acptr),
		    cli_user(acptr)->username, cli_user(acptr)->realhost,
		    *s ? "+" : "", s, *s ? " " : "",
		    iptobase64(xxx_buf, &cli_ip(acptr), sizeof(xxx_buf), IsIPv6(cptr)),
		    NumNick(acptr), cli_info(acptr));
      if (feature_bool(FEAT_AWAY_BURST) && cli_user(acptr)->away)
        sendcmdto_one(acptr, CMD_AWAY, cptr, ":%s", cli_user(acptr)->away);
    }
  }
  /*
   * Last, send the BURST.
   * (Or for 2.9 servers: pass all channels plus statuses)
   */
  {
    struct Channel *chptr;
    for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
      send_channel_modes(cptr, chptr);
  }
  sendcmdto_one(&me, CMD_END_OF_BURST, cptr, "");
  
  return 0;
}

/** Compute secure path groups for all servers in the network.
 * Two servers share a secure group if and only if every server link
 * on the path between them is TLS; the groups are the connected
 * components of the server tree restricted to TLS links.  Every
 * server always belongs to a group -- a server with no TLS server
 * links forms a group of its own, so two TLS clients on the same
 * server share a secure path (no server link is involved between
 * them).
 * This function should be called whenever the network topology changes.
 */
void compute_secure_path_groups(void)
{
  struct Client *cptr;

  /* Reset the static counter */
  next_secure_group_id = 1;

  /* Reset all server sids before reassignment */
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if ((IsServer(cptr) || IsMe(cptr)) && cli_serv(cptr))
      cli_serv(cptr)->sid = 0;
  }

  /* Flood-fill each connected component of TLS links */
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!(IsServer(cptr) || IsMe(cptr)) || !cli_serv(cptr))
      continue;

    /* Skip if already assigned a group */
    if (cli_serv(cptr)->sid != 0)
      continue;

    assign_secure_group(cptr, next_secure_group_id);
    next_secure_group_id++;
  }
}

/** Assign secure group ID to a new server based on its uplink.
 * This is used for incremental updates when a new server joins the network.
 * &me is assigned a secure group ID based on its downlinks.
 * @param new_server The newly added server
 */
void assign_sid(struct Client *new_server)
{
  if (!new_server || (!IsServer(new_server) && !IsMe(new_server)) || !cli_serv(new_server))
    return;
    
  if (cli_serv(new_server)->sid != 0)
    return;
    
  /* Non-TLS servers stay in group 0, except &me which can be assigned based on downlinks */
  if (!IsTLS(new_server) && !IsMe(new_server))
    return;
    
  if (cli_serv(&me)->sid == 0) {
    struct DLink *down;
    int has_tls_downlinks = 0;
    
    for (down = cli_serv(&me)->down; down; down = down->next) {
      if (IsServer(down->value.cptr) && IsTLS(down->value.cptr)) {
        has_tls_downlinks = 1;
        break;
      }
    }
    
    if (has_tls_downlinks) {
      assign_secure_group(&me, next_secure_group_id);
      next_secure_group_id++;
    }
  }
  
  /* Special case: if this is &me, we're done */
  if (IsMe(new_server)) {
    return;
  }
  
  if (cli_serv(new_server)->up && cli_serv(cli_serv(new_server)->up)->sid > 0) {
    /* Assign to the same group as uplink */
    cli_serv(new_server)->sid = cli_serv(cli_serv(new_server)->up)->sid;
  } else {
    /* Assign new group ID to this server and all servers in its secure path */
    assign_secure_group(new_server, next_secure_group_id);
    next_secure_group_id++;
  }
}

/** Assign a secure group ID to a server and all servers in its secure path.
 * @param cptr Server to assign group ID to
 * @param sid Group ID to assign
 */
static void assign_secure_group(struct Client *cptr, int sid)
{
  struct Client *up;
  struct DLink *down;
  struct Client *down_server;
  
  /* Assign group ID to current server */
  cli_serv(cptr)->sid = sid;

  /* Recursively assign to the uplink; the link between cptr and its
   * uplink is TLS iff IsTLS(cptr).  (&me is its own uplink.)
   */
  up = cli_serv(cptr)->up;
  if (up && up != cptr && (IsServer(up) || IsMe(up)) && IsTLS(cptr) &&
      cli_serv(up) && cli_serv(up)->sid == 0) {
    assign_secure_group(up, sid);
  }

  /* Recursively assign to all downlinks whose connection to current server is TLS */
  for (down = cli_serv(cptr)->down; down; down = down->next) {
    down_server = down->value.cptr;
    if (down_server && IsServer(down_server) && IsTLS(down_server) && 
        cli_serv(down_server)->sid == 0) {
      assign_secure_group(down_server, sid);
    }
  }
}


/** Get the secure group ID (sid) for any client (user or server).
 * Servers always belong to a group; users belong to their server's
 * group when their own connection is TLS and to group 0 otherwise.
 * @param cli Client to get secure group ID for
 * @return Secure group ID, or 0 if not on a secure path
 */
int get_secure_group_id(struct Client *cli)
{
  if (!cli)
    return 0;
    
  if (IsServer(cli) || IsMe(cli)) {
    /* For servers (including &me), get sid directly */
    if (!cli_serv(cli))
      return 0;
    return cli_serv(cli)->sid;
  } else if (IsUser(cli)) {
    /* Users must be on a TLS connection to belong to a secure group */
    if (!IsTLS(cli))
      return 0;
    /* For users, get sid from their server */
    struct Client *user_server = cli_user(cli)->server;
    if (!user_server || (!IsServer(user_server) && !IsMe(user_server)) || !cli_serv(user_server)) {
      return 0;
    }
    return cli_serv(user_server)->sid;
  }
  
  return 0;
}

/** Check if two clients are on the same secure network path.
 * @param c1 First client (user or server)
 * @param c2 Second client (user or server)
 * @return Non-zero if both clients are on the same secure path, 0 otherwise
 */
int is_secure_path(struct Client *c1, struct Client *c2)
{
  int sid1, sid2;
  
  if (!c1 || !c2)
    return 0;
    
  /* Get secure group IDs */
  sid1 = get_secure_group_id(c1);
  sid2 = get_secure_group_id(c2);
  
  /* Both must be on secure paths (sid > 0) and have the same sid */
  if (sid1 <= 0 || sid2 <= 0 || sid1 != sid2) {
    return 0;
  }
    
  /* Additional TLS checks */
  if (IsUser(c1)) {
    /* For users, check that their connection to their server is TLS */
    if (!IsTLS(c1)) {
      return 0;
    }
  }
  
  if (IsUser(c2)) {
    /* For users, check that their connection to their server is TLS */
    if (!IsTLS(c2)) {
      return 0;
    }
  }
  
  /* For servers, having the same sid > 0 is sufficient proof of secure path */
  /* No need to check IsTLS() since sid is only assigned to TLS-connected servers */
  
  return 1;
}

