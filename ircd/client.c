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
 * client_get_default_umode
 * returns default usermode in attached client connection class
 */
const char* client_get_default_umode(const struct Client* sptr)
{
  struct ConfItem* aconf;
  struct SLink* link;

  assert(cli_verify(sptr));

  for (link = cli_confs(sptr); link; link = link->next) {
    aconf = link->value.aconf;
    if ((aconf->status & CONF_CLIENT) && ConfUmode(aconf))
      return ConfUmode(aconf);
  }
  return NULL;
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

static struct Privs privs_global;
static struct Privs privs_local;
static int privs_defaults_set;

/* client_set_privs(struct Client* client)
 *
 * Sets the privileges for opers.
 */
void
client_set_privs(struct Client *client, struct ConfItem *oper)
{
  struct Privs *source, *defaults;
  enum Priv priv;

  if (!privs_defaults_set)
  {
    memset(&privs_global, -1, sizeof(privs_global));
    memset(&privs_local, 0, sizeof(privs_local));
    PrivSet(&privs_local, PRIV_CHAN_LIMIT);
    PrivSet(&privs_local, PRIV_MODE_LCHAN);
    PrivSet(&privs_local, PRIV_SHOW_INVIS);
    PrivSet(&privs_local, PRIV_SHOW_ALL_INVIS);
    PrivSet(&privs_local, PRIV_LOCAL_KILL);
    PrivSet(&privs_local, PRIV_REHASH);
    PrivSet(&privs_local, PRIV_LOCAL_GLINE);
    PrivSet(&privs_local, PRIV_LOCAL_JUPE);
    PrivSet(&privs_local, PRIV_LOCAL_OPMODE);
    PrivSet(&privs_local, PRIV_WHOX);
    PrivSet(&privs_local, PRIV_DISPLAY);
    PrivSet(&privs_local, PRIV_FORCE_LOCAL_OPMODE);
    privs_defaults_set = 1;
  }
  memset(&(cli_privs(client)), 0, sizeof(struct Privs));

  if (!IsAnOper(client))
    return;
  else if (!MyConnect(client))
  {
    memset(&(cli_privs(client)), 255, sizeof(struct Privs));
    PrivClr(&(cli_privs(client)), PRIV_SET);
    return;
  }
  else if (oper == NULL)
    return;

  /* Clear out client's privileges. */
  memset(&cli_privs(client), 0, sizeof(struct Privs));

  /* Decide whether to use global or local oper defaults. */
  if (PrivHas(&oper->privs_dirty, PRIV_PROPAGATE))
    defaults = PrivHas(&oper->privs, PRIV_PROPAGATE) ? &privs_global : &privs_local;
  else if (PrivHas(&oper->conn_class->privs_dirty, PRIV_PROPAGATE))
    defaults = PrivHas(&oper->conn_class->privs, PRIV_PROPAGATE) ? &privs_global : &privs_local;
  else {
    assert(0 && "Oper has no propagation and neither does connection class");
    return;
  }

  /* For each feature, figure out whether it comes from the operator
   * conf, the connection class conf, or the defaults, then apply it.
   */
  for (priv = 0; priv < PRIV_LAST_PRIV; ++priv)
  {
    /* Figure out most applicable definition for the privilege. */
    if (PrivHas(&oper->privs_dirty, priv))
      source = &oper->privs;
    else if (PrivHas(&oper->conn_class->privs_dirty, priv))
      source = &oper->conn_class->privs;
    else
      source = defaults;

    /* Set it if necessary (privileges were already cleared). */
    if (PrivHas(source, priv))
      PrivSet(&cli_privs(client), priv);
  }

  /* This should be handled in the config, but lets be sure... */
  if (PrivHas(&cli_privs(client), PRIV_PROPAGATE))
  {
    /* force propagating opers to display */
    PrivSet(&cli_privs(client), PRIV_DISPLAY);
  }
  else
  {
    /* if they don't propagate oper status, prevent desyncs */
    PrivClr(&cli_privs(client), PRIV_KILL);
    PrivClr(&cli_privs(client), PRIV_GLINE);
    PrivClr(&cli_privs(client), PRIV_JUPE);
    PrivClr(&cli_privs(client), PRIV_OPMODE);
    PrivClr(&cli_privs(client), PRIV_BADCHAN);
  }
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
  P(DISPLAY),        P(SEE_OPERS),      P(FORCE_OPMODE),  P(FORCE_LOCAL_OPMODE),
  P(WIDE_GLINE),
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
