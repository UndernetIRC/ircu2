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
#include "config.h"

#include "client.h"
#include "class.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "list.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

#include <assert.h>
#include <string.h>

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

  assert(cli_verify(acptr));

  verify_client_list();

  for (link = cli_confs(acptr); link; link = link->next) {
    aconf = link->value.aconf;
    if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
      int tmp = get_conf_ping(aconf);
      if (0 < tmp && (ping > tmp || !ping))
        ping = tmp;
    }
  }
  if (0 == ping)
    ping = feature_int(FEAT_PINGFREQUENCY);

  Debug((DEBUG_DEBUG, "Client %s Ping %d", cli_name(acptr), ping));

  verify_client_list();

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

static struct {
  unsigned int priv;
  enum Feature feat;
  unsigned int flag;
} feattab[] = {
  { PRIV_WHOX, FEAT_LAST_F, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_DISPLAY, FEAT_LAST_F, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_CHAN_LIMIT, FEAT_OPER_NO_CHAN_LIMIT, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_MODE_LCHAN, FEAT_OPER_MODE_LCHAN, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_LOCAL_OPMODE, FEAT_OPER_MODE_LCHAN, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_WALK_LCHAN, FEAT_OPER_WALK_THROUGH_LMODES,
    (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_DEOP_LCHAN, FEAT_NO_OPER_DEOP_LCHAN, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_SHOW_INVIS, FEAT_SHOW_INVISIBLE_USERS, (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_SHOW_ALL_INVIS, FEAT_SHOW_ALL_INVISIBLE_USERS,
    (FLAGS_OPER | FLAGS_LOCOP) },
  { PRIV_UNLIMIT_QUERY, FEAT_UNLIMIT_OPER_QUERY, (FLAGS_OPER | FLAGS_LOCOP) },

  { PRIV_KILL, FEAT_LOCAL_KILL_ONLY, 0 },
  { PRIV_GLINE, FEAT_CONFIG_OPERCMDS, ~0 },
  { PRIV_JUPE, FEAT_CONFIG_OPERCMDS, ~0 },
  { PRIV_OPMODE, FEAT_CONFIG_OPERCMDS, ~0 },
  { PRIV_BADCHAN, FEAT_CONFIG_OPERCMDS, ~0 },

  { PRIV_PROPAGATE, FEAT_LAST_F, FLAGS_OPER },
  { PRIV_SEE_OPERS, FEAT_LAST_F, FLAGS_OPER },
  { PRIV_KILL, FEAT_OPER_KILL, FLAGS_OPER },
  { PRIV_LOCAL_KILL, FEAT_OPER_KILL, FLAGS_OPER },
  { PRIV_REHASH, FEAT_OPER_REHASH, FLAGS_OPER },
  { PRIV_RESTART, FEAT_OPER_RESTART, FLAGS_OPER },
  { PRIV_DIE, FEAT_OPER_DIE, FLAGS_OPER },
  { PRIV_GLINE, FEAT_OPER_GLINE, FLAGS_OPER },
  { PRIV_LOCAL_GLINE, FEAT_OPER_LGLINE, FLAGS_OPER },
  { PRIV_JUPE, FEAT_OPER_JUPE, FLAGS_OPER },
  { PRIV_LOCAL_JUPE, FEAT_OPER_LJUPE, FLAGS_OPER },
  { PRIV_OPMODE, FEAT_OPER_OPMODE, FLAGS_OPER },
  { PRIV_LOCAL_OPMODE, FEAT_OPER_LOPMODE, FLAGS_OPER },
  { PRIV_BADCHAN, FEAT_OPER_BADCHAN, FLAGS_OPER },
  { PRIV_LOCAL_BADCHAN, FEAT_OPER_LBADCHAN, FLAGS_OPER },
  { PRIV_SET, FEAT_OPER_SET, FLAGS_OPER },
  { PRIV_SEE_CHAN, FEAT_OPERS_SEE_IN_SECRET_CHANNELS, FLAGS_OPER },
  { PRIV_WIDE_GLINE, FEAT_OPER_WIDE_GLINE, FLAGS_OPER },

  { PRIV_LOCAL_KILL, FEAT_LOCOP_KILL, FLAGS_LOCOP },
  { PRIV_REHASH, FEAT_LOCOP_REHASH, FLAGS_LOCOP },
  { PRIV_RESTART, FEAT_LOCOP_RESTART, FLAGS_LOCOP },
  { PRIV_DIE, FEAT_LOCOP_DIE, FLAGS_LOCOP },
  { PRIV_LOCAL_GLINE, FEAT_LOCOP_LGLINE, FLAGS_LOCOP },
  { PRIV_LOCAL_JUPE, FEAT_LOCOP_LJUPE, FLAGS_LOCOP },
  { PRIV_LOCAL_OPMODE, FEAT_LOCOP_LOPMODE, FLAGS_LOCOP },
  { PRIV_LOCAL_BADCHAN, FEAT_LOCOP_LBADCHAN, FLAGS_LOCOP },
  { PRIV_SET, FEAT_LOCOP_SET, FLAGS_LOCOP },
  { PRIV_SEE_CHAN, FEAT_LOCOP_SEE_IN_SECRET_CHANNELS, FLAGS_LOCOP },
  { PRIV_WIDE_GLINE, FEAT_LOCOP_WIDE_GLINE, FLAGS_LOCOP },
  { 0, FEAT_LAST_F, 0 }
};

/* client_set_privs(struct Client* client)
 *
 * Sets the privileges for opers.
 */
void
client_set_privs(struct Client* client)
{
  struct Privs privs;
  struct Privs antiprivs;
  int i;

  memset(&privs, 0, sizeof(struct Privs));
  memset(&antiprivs, 0, sizeof(struct Privs));

  if (!IsAnOper(client)) { /* clear privilege mask */
    memset(&(cli_privs(client)), 0, sizeof(struct Privs));
    return;
  } else if (!MyConnect(client)) {
    memset(&(cli_privs(client)), 255, sizeof(struct Privs));
    PrivClr(&(cli_privs(client)), PRIV_SET);
    return;
  }

  /* This sequence is temporary until the .conf is carefully rewritten */

  for (i = 0; feattab[i].priv; i++) {
    if (feattab[i].flag == 0) {
      if (feature_bool(feattab[i].feat))
	PrivSet(&antiprivs, feattab[i].priv);
    } else if (feattab[i].flag == ~0) {
      if (!feature_bool(feattab[i].feat))
	PrivSet(&antiprivs, feattab[i].priv);
    } else if (cli_flags(client) & feattab[i].flag) {
      if (feattab[i].feat == FEAT_LAST_F ||
	  feature_bool(feattab[i].feat))
	PrivSet(&privs, feattab[i].priv);
    }
  }

  /* This is the end of the gross section */

  if (PrivHas(&privs, PRIV_PROPAGATE))
    PrivSet(&privs, PRIV_DISPLAY); /* force propagating opers to display */
  else { /* if they don't propagate oper status, prevent desyncs */
    PrivSet(&antiprivs, PRIV_KILL);
    PrivSet(&antiprivs, PRIV_GLINE);
    PrivSet(&antiprivs, PRIV_JUPE);
    PrivSet(&antiprivs, PRIV_OPMODE);
    PrivSet(&antiprivs, PRIV_BADCHAN);
  }

  for (i = 0; i <= _PRIV_IDX(PRIV_LAST_PRIV); i++)
    privs.priv_mask[i] &= ~antiprivs.priv_mask[i];

  cli_privs(client) = privs;
}

static struct {
  char        *name;
  unsigned int priv;
} privtab[] = {
#define P(priv)		{ #priv, PRIV_ ## priv }
  P(CHAN_LIMIT),     P(MODE_LCHAN),     P(WALK_LCHAN),    P(DEOP_LCHAN),
  P(SHOW_INVIS),     P(SHOW_ALL_INVIS), P(UNLIMIT_QUERY), P(KILL),
  P(LOCAL_KILL),     P(REHASH),         P(RESTART),       P(DIE),
  P(GLINE),          P(LOCAL_GLINE),    P(JUPE),          P(LOCAL_JUPE),
  P(OPMODE),         P(LOCAL_OPMODE),   P(SET),           P(WHOX),
  P(BADCHAN),        P(LOCAL_BADCHAN),  P(SEE_CHAN),      P(PROPAGATE),
  P(DISPLAY),        P(SEE_OPERS),      P(WIDE_GLINE),
#undef P
  { 0, 0 }
};

/* client_report_privs(struct Client *to, struct Client *client)
 *
 * Sends a summary of the oper's privileges to the oper.
 */
int
client_report_privs(struct Client *to, struct Client *client)
{
  struct MsgBuf *mb;
  int found1 = 0;
  int i;

  mb = msgq_make(to, rpl_str(RPL_PRIVS), cli_name(&me), cli_name(to),
		 cli_name(client));

  for (i = 0; privtab[i].name; i++)
    if (HasPriv(client, privtab[i].priv))
      msgq_append(0, mb, "%s%s", found1++ ? " " : "", privtab[i].name);

  send_buffer(to, mb, 0); /* send response */
  msgq_clean(mb);

  return 0;
}
