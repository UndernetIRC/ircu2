/*
 * IRC - Internet Relay Chat, ircd/client.c
 * Copyright (C) 1990 Darren Reed
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
#include "client.h"
#include "class.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "list.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

#include <assert.h>

#define BAD_PING                ((unsigned int)-2)

/*
 * client_get_ping
 * returns shortest ping time in attached server or client conf
 * classes or PINGFREQUENCY
 */
int client_get_ping(const struct Client* acptr)
{
  int     ping = 0;
  struct ConfItem* aconf;
  struct SLink*    link;

  for (link = cli_confs(acptr); link; link = link->next) {
    aconf = link->value.aconf;
    if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
      int tmp = get_conf_ping(aconf);
      if (0 < tmp && (ping > tmp || !ping))
        ping = tmp;
    }
  }
  if (0 == ping)
    ping = PINGFREQUENCY;

  Debug((DEBUG_DEBUG, "Client %s Ping %d", cli_name(acptr), ping));
  return ping;
}

/*
 * client_drop_sendq
 * removes the client's connection from the list of connections with
 * queued data
 */
void client_drop_sendq(struct Connection* con)
{
  if (con_prev_p(con)) { /* on the queued data list... */
    if (con_next(con))
      con_prev_p(con_next(con)) = con_prev_p(con);
    *(con_prev_p(con)) = con_next(con);

    con_next(con) = 0;
    con_prev_p(con) = 0;
  }
}

/*
 * client_add_sendq
 * adds the client's connection to the list of connections with
 * queued data
 */
void client_add_sendq(struct Connection* con, struct Connection** con_p)
{
  if (!con_prev_p(con)) { /* not on the queued data list yet... */
    con_prev_p(con) = con_p;
    con_next(con) = *con_p;

    if (*con_p)
      con_prev_p(*con_p) = &(con_next(con));
    *con_p = con;
  }
}

/* client_set_privs(struct Client* client)
 *
 * Sets the privileges for opers.
 */
void
client_set_privs(struct Client* client)
{
  unsigned int privs = 0;
  unsigned int antiprivs = 0;

  if (!IsAnOper(client)) {
    cli_privs(client) = 0; /* clear privilege mask */
    return;
  } else if (!MyConnect(client)) {
    cli_privs(client) = ~(PRIV_SET); /* everything but set... */
    return;
  }

  /* This sequence is temporary until the .conf is carefully rewritten */

  privs |= (PRIV_WHOX | PRIV_DISPLAY);
  if (feature_bool(FEAT_OPER_NO_CHAN_LIMIT))
    privs |= PRIV_CHAN_LIMIT;
  if (feature_bool(FEAT_OPER_MODE_LCHAN))
    privs |= (PRIV_MODE_LCHAN | PRIV_LOCAL_OPMODE);
  if (feature_bool(FEAT_OPER_WALK_THROUGH_LMODES))
    privs |= PRIV_WALK_LCHAN;
  if (feature_bool(FEAT_NO_OPER_DEOP_LCHAN))
    privs |= PRIV_DEOP_LCHAN;
  if (feature_bool(FEAT_SHOW_INVISIBLE_USERS))
    privs |= PRIV_SHOW_INVIS;
  if (feature_bool(FEAT_SHOW_ALL_INVISIBLE_USERS))
    privs |= PRIV_SHOW_ALL_INVIS;
  if (feature_bool(FEAT_UNLIMIT_OPER_QUERY))
    privs |= PRIV_UNLIMIT_QUERY;
  if (feature_bool(FEAT_LOCAL_KILL_ONLY))
    antiprivs |= PRIV_KILL;
  if (!feature_bool(FEAT_CONFIG_OPERCMDS))
    antiprivs |= (PRIV_GLINE | PRIV_JUPE | PRIV_OPMODE | PRIV_BADCHAN);

  if (IsOper(client)) {
    privs |= (PRIV_SET | PRIV_PROPAGATE | PRIV_SEE_OPERS);
    if (feature_bool(FEAT_OPER_KILL))
      privs |= (PRIV_KILL | PRIV_LOCAL_KILL);
    if (feature_bool(FEAT_OPER_REHASH))
      privs |= PRIV_REHASH;
    if (feature_bool(FEAT_OPER_RESTART))
      privs |= PRIV_RESTART;
    if (feature_bool(FEAT_OPER_DIE))
      privs |= PRIV_DIE;
    if (feature_bool(FEAT_OPER_GLINE))
      privs |= PRIV_GLINE;
    if (feature_bool(FEAT_OPER_LGLINE))
      privs |= PRIV_LOCAL_GLINE;
    if (feature_bool(FEAT_OPER_JUPE))
      privs |= PRIV_JUPE;
    if (feature_bool(FEAT_OPER_LJUPE))
      privs |= PRIV_LOCAL_JUPE;
    if (feature_bool(FEAT_OPER_OPMODE))
      privs |= PRIV_OPMODE;
    if (feature_bool(FEAT_OPER_LOPMODE))
      privs |= PRIV_LOCAL_OPMODE;
    if (feature_bool(FEAT_OPER_BADCHAN))
      privs |= PRIV_BADCHAN;
    if (feature_bool(FEAT_OPER_LBADCHAN))
      privs |= PRIV_LOCAL_BADCHAN;
    if (feature_bool(FEAT_OPERS_SEE_IN_SECRET_CHANNELS))
      privs |= PRIV_SEE_CHAN;
  } else { /* is a local operator */
    if (feature_bool(FEAT_LOCOP_KILL))
      privs |= PRIV_LOCAL_KILL;
    if (feature_bool(FEAT_LOCOP_REHASH))
      privs |= PRIV_REHASH;
    if (feature_bool(FEAT_LOCOP_RESTART))
      privs |= PRIV_RESTART;
    if (feature_bool(FEAT_LOCOP_DIE))
      privs |= PRIV_DIE;
    if (feature_bool(FEAT_LOCOP_LGLINE))
      privs |= PRIV_LOCAL_GLINE;
    if (feature_bool(FEAT_LOCOP_LJUPE))
      privs |= PRIV_LOCAL_JUPE;
    if (feature_bool(FEAT_LOCOP_LOPMODE))
      privs |= PRIV_LOCAL_OPMODE;
    if (feature_bool(FEAT_LOCOP_LBADCHAN))
      privs |= PRIV_LOCAL_BADCHAN;
    if (feature_bool(FEAT_LOCOP_SEE_IN_SECRET_CHANNELS))
      privs |= PRIV_SEE_CHAN;
  }

  /* This is the end of the gross section */

  if (privs & PRIV_PROPAGATE)
    privs |= PRIV_DISPLAY;
  else
    antiprivs |= (PRIV_KILL | PRIV_GLINE | PRIV_JUPE | PRIV_OPMODE |
		  PRIV_BADCHAN);

  cli_privs(client) = privs & ~antiprivs;
}
