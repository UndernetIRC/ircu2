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
  enum Priv priv;
  enum Feature feat;
  enum {
    FEATFLAG_DISABLES_PRIV,
    FEATFLAG_ENABLES_PRIV,
    FEATFLAG_GLOBAL_OPERS,
    FEATFLAG_LOCAL_OPERS,
    FEATFLAG_ALL_OPERS
  } flag;
} feattab[] = {
  { PRIV_WHOX, FEAT_LAST_F, FEATFLAG_ALL_OPERS },
  { PRIV_DISPLAY, FEAT_LAST_F, FEATFLAG_ALL_OPERS },
  { PRIV_CHAN_LIMIT, FEAT_OPER_NO_CHAN_LIMIT, FEATFLAG_ALL_OPERS },
  { PRIV_MODE_LCHAN, FEAT_OPER_MODE_LCHAN, FEATFLAG_ALL_OPERS },
  { PRIV_LOCAL_OPMODE, FEAT_OPER_MODE_LCHAN, FEATFLAG_ALL_OPERS },
  { PRIV_WALK_LCHAN, FEAT_OPER_WALK_THROUGH_LMODES, FEATFLAG_ALL_OPERS },
  { PRIV_DEOP_LCHAN, FEAT_NO_OPER_DEOP_LCHAN, FEATFLAG_ALL_OPERS },
  { PRIV_SHOW_INVIS, FEAT_SHOW_INVISIBLE_USERS, FEATFLAG_ALL_OPERS },
  { PRIV_SHOW_ALL_INVIS, FEAT_SHOW_ALL_INVISIBLE_USERS, FEATFLAG_ALL_OPERS },
  { PRIV_UNLIMIT_QUERY, FEAT_UNLIMIT_OPER_QUERY, FEATFLAG_ALL_OPERS },

  { PRIV_KILL, FEAT_LOCAL_KILL_ONLY, FEATFLAG_DISABLES_PRIV },
  { PRIV_GLINE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_JUPE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_OPMODE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_BADCHAN, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },

  { PRIV_PROPAGATE, FEAT_LAST_F, FEATFLAG_GLOBAL_OPERS },
  { PRIV_SEE_OPERS, FEAT_LAST_F, FEATFLAG_GLOBAL_OPERS },
  { PRIV_KILL, FEAT_OPER_KILL, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_KILL, FEAT_OPER_KILL, FEATFLAG_GLOBAL_OPERS },
  { PRIV_REHASH, FEAT_OPER_REHASH, FEATFLAG_GLOBAL_OPERS },
  { PRIV_RESTART, FEAT_OPER_RESTART, FEATFLAG_GLOBAL_OPERS },
  { PRIV_DIE, FEAT_OPER_DIE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_GLINE, FEAT_OPER_GLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_GLINE, FEAT_OPER_LGLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_JUPE, FEAT_OPER_JUPE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_JUPE, FEAT_OPER_LJUPE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_OPMODE, FEAT_OPER_OPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_OPMODE, FEAT_OPER_LOPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_FORCE_OPMODE, FEAT_OPER_FORCE_OPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_FORCE_LOCAL_OPMODE, FEAT_OPER_FORCE_LOPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_BADCHAN, FEAT_OPER_BADCHAN, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_BADCHAN, FEAT_OPER_LBADCHAN, FEATFLAG_GLOBAL_OPERS },
  { PRIV_SET, FEAT_OPER_SET, FEATFLAG_GLOBAL_OPERS },
  { PRIV_SEE_CHAN, FEAT_OPERS_SEE_IN_SECRET_CHANNELS, FEATFLAG_GLOBAL_OPERS },
  { PRIV_WIDE_GLINE, FEAT_OPER_WIDE_GLINE, FEATFLAG_GLOBAL_OPERS },

  { PRIV_LOCAL_KILL, FEAT_LOCOP_KILL, FEATFLAG_LOCAL_OPERS },
  { PRIV_REHASH, FEAT_LOCOP_REHASH, FEATFLAG_LOCAL_OPERS },
  { PRIV_RESTART, FEAT_LOCOP_RESTART, FEATFLAG_LOCAL_OPERS },
  { PRIV_DIE, FEAT_LOCOP_DIE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_GLINE, FEAT_LOCOP_LGLINE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_JUPE, FEAT_LOCOP_LJUPE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_OPMODE, FEAT_LOCOP_LOPMODE, FEATFLAG_LOCAL_OPERS },
  { PRIV_FORCE_LOCAL_OPMODE, FEAT_LOCOP_FORCE_LOPMODE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_BADCHAN, FEAT_LOCOP_LBADCHAN, FEATFLAG_LOCAL_OPERS },
  { PRIV_SET, FEAT_LOCOP_SET, FEATFLAG_LOCAL_OPERS },
  { PRIV_SEE_CHAN, FEAT_LOCOP_SEE_IN_SECRET_CHANNELS, FEATFLAG_LOCAL_OPERS },
  { PRIV_WIDE_GLINE, FEAT_LOCOP_WIDE_GLINE, FEATFLAG_LOCAL_OPERS },

  { PRIV_LAST_PRIV, FEAT_LAST_F, 0 }
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

  for (i = 0; feattab[i].priv != PRIV_LAST_PRIV; i++) {
    if (feattab[i].flag == FEATFLAG_ENABLES_PRIV) {
      if (!feature_bool(feattab[i].feat))
	PrivSet(&antiprivs, feattab[i].priv);
    } else if (feattab[i].feat == FEAT_LAST_F || feature_bool(feattab[i].feat)) {
      if (feattab[i].flag == FEATFLAG_DISABLES_PRIV) {
	PrivSet(&antiprivs, feattab[i].priv);
      } else if (feattab[i].flag == FEATFLAG_ALL_OPERS) {
	if (IsAnOper(client))
	  PrivSet(&privs, feattab[i].priv);
      } else if (feattab[i].flag == FEATFLAG_GLOBAL_OPERS) {
	if (IsOper(client))
	  PrivSet(&privs, feattab[i].priv);
      } else if (feattab[i].flag == FEATFLAG_LOCAL_OPERS) {
	if (IsLocOp(client))
	  PrivSet(&privs, feattab[i].priv);
      }
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
  P(DISPLAY),        P(SEE_OPERS),      P(WIDE_GLINE),    P(FORCE_OPMODE),
  P(FORCE_LOCAL_OPMODE),
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
