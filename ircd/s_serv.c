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
 *
 * $Id$
 */
#include "s_serv.h"
#include "IPcheck.h"
#include "channel.h"
#include "client.h"
#include "crule.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_xopen.h"
#include "jupe.h"
#include "list.h"
#include "msg.h"
#include "match.h"
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
#include "sprintf_irc.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

unsigned int max_connection_count = 0;
unsigned int max_client_count = 0;
#if 0
int exit_new_server(struct Client* cptr, struct Client* sptr,
                    const char* host, time_t timestamp, const char* fmt, ...)
{
  va_list vl;
  char *buf =
      (char*) MyMalloc(strlen(me.name) + strlen(host) + 22 + strlen(fmt));
  assert(0 != buf);
  va_start(vl, fmt);
  if (!IsServer(sptr))
    return vexit_client_msg(cptr, cptr, &me, fmt, vl);
  sprintf_irc(buf, ":%s " TOK_SQUIT " %s " TIME_T_FMT " :", me.name, host, timestamp);
  strcat(buf, fmt);
  vsendto_one(cptr, buf, vl); /* XXX DEAD */
  va_end(vl);
  MyFree(buf);
  return 0;
}
#endif /* 0 */

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

int a_kills_b_too(struct Client *a, struct Client *b)
{
  for (; b != a && b != &me; b = b->serv->up);
  return (a == b ? 1 : 0);
}

/*
 * server_estab
 *
 * May only be called after a SERVER was received from cptr,
 * and thus make_server was called, and serv->prot set. --Run
 */
int server_estab(struct Client *cptr, struct ConfItem *aconf)
{
  struct Client* acptr = 0;
  const char*    inpath;
  int split,     i;

  assert(0 != cptr);
  assert(0 != cptr->local);

  split = (0 != ircd_strcmp(cptr->name, cptr->sockhost)
      &&   0 != ircd_strncmp(cptr->info, "JUPE", 4));
  inpath = cptr->name;

  if (IsUnknown(cptr)) {
    if (aconf->passwd[0])
      sendrawto_one(cptr, MSG_PASS " :%s", aconf->passwd);
    /*
     *  Pass my info to the new server
     */
    sendrawto_one(cptr, MSG_SERVER " %s 1 %Tu %Tu J%s %s%s :%s", me.name,
		  me.serv->timestamp, cptr->serv->timestamp, MAJOR_PROTOCOL,
		  NumServCap(&me), *me.info ? me.info : "IRCers United");
    /*
     * Don't charge this IP# for connecting
     * XXX - if this comes from a server port, it will not have been added
     * to the IP check registry, see add_connection in s_bsd.c 
     */
    IPcheck_connect_fail(cptr->ip);
  }

  det_confs_butmask(cptr, CONF_LEAF | CONF_HUB | CONF_SERVER | CONF_UWORLD);

  if (!IsHandshake(cptr))
    hAddClient(cptr);
  SetServer(cptr);
  cptr->handler = SERVER_HANDLER;
  Count_unknownbecomesserver(UserStats);

  release_dns_reply(cptr);

  SetBurst(cptr);

  nextping = CurrentTime;

  /*
   * NOTE: check for acptr->user == cptr->serv->user is necessary to insure
   * that we got the same one... bleah
   */
  if (cptr->serv->user && *cptr->serv->by &&
      (acptr = findNUser(cptr->serv->by))) {
    if (acptr->user == cptr->serv->user) {
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Link with %s established.",
		    acptr, inpath);
    }
    else {
      /*
       * if not the same client, set by to empty string
       */
      acptr = 0;
      *cptr->serv->by = '\0';
    }
  }

  sendto_opmask_butone(acptr, SNO_OLDSNO, "Link with %s established.", inpath);
  cptr->serv->up = &me;
  cptr->serv->updown = add_dlink(&me.serv->down, cptr);
  sendto_opmask_butone(0, SNO_NETWORK, "Net junction: %s %s", me.name,
		       cptr->name);
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
    if (!match(me.name, cptr->name))
      continue;
    sendcmdto_one(&me, CMD_SERVER, acptr, "%s 2 0 %Tu J%02u %s%s 0 :%s",
		  cptr->name, cptr->serv->timestamp, Protocol(cptr),
		  NumServCap(cptr), cptr->info);
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

  for (acptr = &me; acptr; acptr = acptr->prev) {
    /* acptr->from == acptr for acptr == cptr */
    if (acptr->from == cptr)
      continue;
    if (IsServer(acptr)) {
      const char* protocol_str;

      if (Protocol(acptr) > 9)
        protocol_str = IsBurst(acptr) ? "J" : "P";
      else
        protocol_str = IsBurst(acptr) ? "J0" : "P0";

      if (0 == match(me.name, acptr->name))
        continue;
      split = (MyConnect(acptr) && 
               0 != ircd_strcmp(acptr->name, acptr->sockhost) &&
               0 != ircd_strncmp(acptr->info, "JUPE", 4));
      sendcmdto_one(acptr->serv->up, CMD_SERVER, cptr, "%s %d 0 %Tu %s%u "
		    "%s%s 0 :%s", acptr->name, acptr->hopcount + 1,
		    acptr->serv->timestamp, protocol_str, Protocol(acptr),
		    NumServCap(acptr), acptr->info);
    }
  }

  for (acptr = &me; acptr; acptr = acptr->prev)
  {
    /* acptr->from == acptr for acptr == cptr */
    if (acptr->from == cptr)
      continue;
    if (IsUser(acptr))
    {
      char xxx_buf[8];
      char *s = umode_str(acptr);
      sendcmdto_one(acptr->user->server, CMD_NICK, cptr, *s ?
		    "%s %d %Tu %s %s +%s %s %s%s :%s" :
		    "%s %d %Tu %s %s %s%s %s%s :%s",
		    acptr->name, acptr->hopcount + 1, acptr->lastnick,
		    acptr->user->username, acptr->user->host, s,
		    inttobase64(xxx_buf, ntohl(acptr->ip.s_addr), 6),
		    NumNick(acptr), acptr->info);
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
  jupe_burst(cptr);
  gline_burst(cptr);
  sendcmdto_one(&me, CMD_END_OF_BURST, cptr, "");
  return 0;
}

