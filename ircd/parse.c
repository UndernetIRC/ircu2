/*
 * IRC - Internet Relay Chat, common/parse.c
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
 *
 * $Id$
 */
#include "config.h"

#include "parse.h"
#include "client.h"
#include "channel.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "querycmds.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_numeric.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "whocmds.h"
#include "whowas.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>



struct MessageTree {
  char *final;
  struct Message *msg;
  struct MessageTree *pointers[26];
};


struct Message msgtab[] = {
  {
    MSG_PRIVATE,
    TOK_PRIVATE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_privmsg, ms_privmsg, mo_privmsg, m_ignore }
  },
  {
    MSG_NICK,
    TOK_NICK,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_nick, m_nick, ms_nick, m_nick, m_ignore }
  },
  {
    MSG_NOTICE,
    TOK_NOTICE,
    0, MAXPARA, MFLG_SLOW | MFLG_IGNORE, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_notice, ms_notice, mo_notice, m_ignore }
  },
  {
    MSG_WALLCHOPS,
    TOK_WALLCHOPS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_wallchops, ms_wallchops, m_wallchops, m_ignore }
  },
  {
    MSG_WALLVOICES,
    TOK_WALLVOICES,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_wallvoices, ms_wallvoices, m_wallvoices, m_ignore }
  },
  {
    MSG_CPRIVMSG,
    TOK_CPRIVMSG,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_cprivmsg, m_ignore, m_cprivmsg, m_ignore }
  },
  {
    MSG_CNOTICE,
    TOK_CNOTICE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_cnotice, m_ignore, m_cnotice, m_ignore }
  },
  {
    MSG_JOIN,
    TOK_JOIN,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_join, ms_join, m_join, m_ignore }
  },
  {
    MSG_MODE,
    TOK_MODE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_mode, ms_mode, m_mode, m_ignore }
  },
  {
    MSG_BURST,
    TOK_BURST,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_burst, m_ignore, m_ignore }
  },
  {
    MSG_CREATE,
    TOK_CREATE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_create, m_ignore, m_ignore }
  },
  {
    MSG_DESTRUCT,
    TOK_DESTRUCT,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_destruct, m_ignore, m_ignore }
  },
  {
    MSG_QUIT,
    TOK_QUIT,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_quit, m_quit, ms_quit, m_quit, m_ignore }
  },
  {
    MSG_PART,
    TOK_PART,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_part, ms_part, m_part, m_ignore }
  },
  {
    MSG_TOPIC,
    TOK_TOPIC,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_topic, ms_topic, m_topic, m_ignore }
  },
  {
    MSG_INVITE,
    TOK_INVITE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_invite, ms_invite, m_invite, m_ignore }
  },
  {
    MSG_KICK,
    TOK_KICK,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_kick, ms_kick, m_kick, m_ignore }
  },
  {
    MSG_WALLOPS,
    TOK_WALLOPS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_wallops, mo_wallops, m_ignore }
  },
  {
    MSG_WALLUSERS,
    TOK_WALLUSERS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_wallusers, mo_wallusers, m_ignore }
  },
  {
    MSG_DESYNCH,
    TOK_DESYNCH,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_desynch, m_ignore, m_ignore }
  },
  {
    MSG_PING,
    TOK_PING,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_ping, ms_ping, mo_ping, m_ignore }
  },
  {
    MSG_PONG,
    TOK_PONG,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { mr_pong, m_pong, ms_pong, m_pong, m_ignore }
  },
  {
    MSG_ERROR,
    TOK_ERROR,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { mr_error, m_ignore, ms_error, m_ignore, m_ignore }
  },
  {
    MSG_KILL,
    TOK_KILL,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_kill, mo_kill, m_ignore }
  },
  {
    MSG_USER,
    TOK_USER,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_user, m_registered, m_ignore, m_registered, m_ignore }
  },
  {
    MSG_AWAY,
    TOK_AWAY,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_away, ms_away, m_away, m_ignore }
  },
  {
    MSG_ISON,
    TOK_ISON,
    0, 1, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_ison, m_ignore, m_ison, m_ignore }
  },
  {
    MSG_SERVER,
    TOK_SERVER,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { mr_server, m_registered, ms_server, m_registered, m_ignore }
  },
  {
    MSG_SQUIT,
    TOK_SQUIT,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_squit, mo_squit, m_ignore }
  },
  {
    MSG_WHOIS,
    TOK_WHOIS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_whois, ms_whois, m_whois, m_ignore }
  },
  {
    MSG_WHO,
    TOK_WHO,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_who, m_ignore, m_who, m_ignore }
  },
  {
    MSG_WHOWAS,
    TOK_WHOWAS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_whowas, m_whowas, m_whowas, m_ignore }
  },
  {
    MSG_LIST,
    TOK_LIST,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_list, m_ignore, m_list, m_ignore }
  },
  {
    MSG_NAMES,
    TOK_NAMES,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_names, ms_names, m_names, m_ignore }
  },
  {
    MSG_USERHOST,
    TOK_USERHOST,
    0, 1, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_userhost, m_ignore, m_userhost, m_ignore }
  },
  {
    MSG_USERIP,
    TOK_USERIP,
    0, 1, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_userip, m_ignore, m_userip, m_ignore }
  },
  {
    MSG_TRACE,
    TOK_TRACE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_trace, ms_trace, mo_trace, m_ignore }
  },
  {
    MSG_PASS,
    TOK_PASS,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { mr_pass, m_registered, m_ignore, m_registered, m_ignore }
  },
  {
    MSG_LUSERS,
    TOK_LUSERS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_lusers, ms_lusers, m_lusers, m_ignore }
  },
  {
    MSG_TIME,
    TOK_TIME,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_time, m_time, m_time, m_ignore }
  },
  {
    MSG_SETTIME,
    TOK_SETTIME,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_ignore, ms_settime, mo_settime, m_ignore }
  },
  {
    MSG_RPING,
    TOK_RPING,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_rping, mo_rping, m_ignore }
  },
  {
    MSG_RPONG,
    TOK_RPONG,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_ignore, ms_rpong, m_ignore, m_ignore }
  },
  {
    MSG_OPER,
    TOK_OPER,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_oper, ms_oper, mo_oper, m_ignore }
  },
  {
    MSG_CONNECT,
    TOK_CONNECT,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_connect, mo_connect, m_ignore }
  },
  {
    MSG_MAP,
    TOK_MAP,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_map, m_ignore, m_map, m_ignore }
  },
  {
    MSG_VERSION,
    TOK_VERSION,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_version, m_version, ms_version, mo_version, m_ignore }
  },
  {
    MSG_STATS,
    TOK_STATS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_stats, m_stats, m_stats, m_ignore }
  },
  {
    MSG_LINKS,
    TOK_LINKS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_links, ms_links, m_links, m_ignore }
  },
  {
    MSG_ADMIN,
    TOK_ADMIN,
    0, MAXPARA, MFLG_SLOW | MFLG_UNREG, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_admin, m_admin, ms_admin, mo_admin, m_ignore }
  },
  {
    MSG_HELP,
    TOK_HELP,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_help, m_ignore, m_help, m_ignore }
  },
  {
    MSG_INFO,
    TOK_INFO,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_info, ms_info, mo_info, m_ignore }
  },
  {
    MSG_MOTD,
    TOK_MOTD,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_motd, m_motd, m_motd, m_ignore }
  },
  {
    MSG_CLOSE,
    TOK_CLOSE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_close, m_ignore }
  },
  {
    MSG_SILENCE,
    TOK_SILENCE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_silence, ms_silence, m_silence, m_ignore }
  },
  {
    MSG_GLINE,
    TOK_GLINE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_gline, ms_gline, mo_gline, m_ignore }
  },
  {
    MSG_JUPE,
    TOK_JUPE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_jupe, ms_jupe, mo_jupe, m_ignore }
  },
  {
    MSG_OPMODE,
    TOK_OPMODE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_opmode, mo_opmode, m_ignore }
  },
  {
    MSG_CLEARMODE,
    TOK_CLEARMODE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_clearmode, mo_clearmode, m_ignore }
  },
  {
    MSG_UPING,
    TOK_UPING,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, ms_uping, mo_uping, m_ignore }
  },
  {
    MSG_END_OF_BURST,
    TOK_END_OF_BURST,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_end_of_burst, m_ignore, m_ignore }
  },
  {
    MSG_END_OF_BURST_ACK,
    TOK_END_OF_BURST_ACK,
    0, MAXPARA, 1, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_end_of_burst_ack, m_ignore, m_ignore }
  },
  {
    MSG_HASH,
    TOK_HASH,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_hash, m_hash, m_hash, m_ignore }
  },
  {
    MSG_DNS,
    TOK_DNS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_dns, m_dns, m_dns, m_ignore }
  },
  {
    MSG_REHASH,
    TOK_REHASH,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_rehash, m_ignore }
  },
  {
    MSG_RESTART,
    TOK_RESTART,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_restart, m_ignore }
  },
  {
    MSG_DIE,
    TOK_DIE,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_die, m_ignore }
  },
  {
    MSG_PROTO,
    TOK_PROTO,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_proto, m_proto, m_proto, m_proto, m_ignore }
  },
  {
    MSG_SET,
    TOK_SET,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_set, m_ignore }
  },
  {
    MSG_RESET,
    TOK_RESET,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_reset, m_ignore }
  },
  {
    MSG_GET,
    TOK_GET,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_get, m_ignore }
  },
  {
    MSG_PRIVS,
    TOK_PRIVS,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_unregistered, m_not_oper, m_ignore, mo_privs, m_ignore }
  },
  {
    MSG_ACCOUNT,
    TOK_ACCOUNT,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_ignore, ms_account, m_ignore, m_ignore }
  },
  {
    MSG_ASLL,
    TOK_ASLL,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_ignore, m_not_oper, ms_asll, mo_asll, m_ignore }
  },
  /* This command is an alias for QUIT during the unregistered part of
   * of the server.  This is because someone jumping via a broken web
   * proxy will send a 'POST' as their first command - which we will
   * obviously disconnect them immediately for, stopping people abusing
   * open gateways
   */
  {
    MSG_POST,
    TOK_POST,
    0, MAXPARA, MFLG_SLOW, 0,
    /* UNREG, CLIENT, SERVER, OPER, SERVICE */
    { m_quit, m_ignore, m_ignore, m_ignore, m_ignore }
  },
  { 0 }
};


static char *para[MAXPARA + 2]; /* leave room for prefix and null */

/*
 * Message Tree stuff mostly written by orabidoo, with changes by Dianora.
 * Adapted to Undernet, adding token support, etc by comstud 10/06/97
 */

static struct MessageTree msg_tree_cmd;
static struct MessageTree msg_tree_tok;

/*
 * Guts of making the token tree...
 */
static struct Message **do_msg_tree_tok(struct MessageTree *mtree, char *prefix,
    struct Message **mptr)
{
  char newprefix[64];           /* Must be longer than every command name */
  int c, c2, lp;
  struct MessageTree *mtree1;

  lp = strlen(prefix);
  if (!lp || !strncmp((*mptr)->tok, prefix, lp))
  {
    if (!mptr[1] || (lp && strncmp(mptr[1]->tok, prefix, lp)))
    {
      /* last command in the message struct or last command in this prefix */
      mtree->final = (*mptr)->tok + lp;
      mtree->msg = *mptr;
      for (c = 0; c < 26; ++c)
        mtree->pointers[c] = NULL;
      return mptr + 1;
    }
    /* command in this prefix */
    if (0 == ircd_strcmp((*mptr)->tok, prefix))
    {
      mtree->final = "";
      mtree->msg = *mptr++;
    }
    else
      mtree->final = NULL;

    for (c = 'A'; c <= 'Z'; ++c)
    {
      if ((*mptr)->tok[lp] == c)
      {
        mtree1 = (struct MessageTree *)MyMalloc(sizeof(struct MessageTree));
        mtree1->final = NULL;
        mtree->pointers[c - 'A'] = mtree1;
        strcpy(newprefix, prefix);
        newprefix[lp] = c;
        newprefix[lp + 1] = '\0';
        mptr = do_msg_tree_tok(mtree1, newprefix, mptr);
        if (!*mptr || strncmp((*mptr)->tok, prefix, lp))
        {
          for (c2 = c + 1 - 'A'; c2 < 26; ++c2)
            mtree->pointers[c2] = NULL;
          return mptr;
        }
      }
      else
        mtree->pointers[c - 'A'] = NULL;
    }
    return mptr;
  }
  /*
   * XXX - should never be here, quick hack, this can be done better
   */
  assert(0);
  exit(1);
}

/*
 * Guts of making the command tree...
 */
static struct Message *do_msg_tree_cmd(struct MessageTree *mtree, char *prefix,
    struct Message *mptr)
{
  char newprefix[64];           /* Must be longer than every command name */
  int c, c2, lp;
  struct MessageTree *mtree1;

  lp = strlen(prefix);
  if (!lp || !strncmp(mptr->cmd, prefix, lp))
  {
    if (!mptr[1].cmd || (lp && strncmp(mptr[1].cmd, prefix, lp)))
    {
      /* last command in the message struct or last command in this prefix */
      mtree->final = mptr->cmd + lp;
      mtree->msg = mptr;
      for (c = 0; c < 26; ++c)
        mtree->pointers[c] = NULL;
      return mptr + 1;
    }
    /* command in this prefix */
    if (0 == ircd_strcmp(mptr->cmd, prefix))
    {
      mtree->final = "";
      mtree->msg = mptr++;
    }
    else
      mtree->final = NULL;

    for (c = 'A'; c <= 'Z'; ++c)
    {
      if (mptr->cmd[lp] == c)
      {
        mtree1 = (struct MessageTree *)MyMalloc(sizeof(struct MessageTree));
        mtree1->final = NULL;
        mtree->pointers[c - 'A'] = mtree1;
        strcpy(newprefix, prefix);
        newprefix[lp] = c;
        newprefix[lp + 1] = '\0';
        mptr = do_msg_tree_cmd(mtree1, newprefix, mptr);
        if (!mptr->cmd || strncmp(mptr->cmd, prefix, lp))
        {
          for (c2 = c + 1 - 'A'; c2 < 26; ++c2)
            mtree->pointers[c2] = NULL;
          return mptr;
        }
      }
      else
        mtree->pointers[c - 'A'] = NULL;
    }
    return mptr;
  }
  /*
   * This should never happen
   */
  assert(0);
  exit(1);
}

static int mcmdcmp(const struct Message *m1, const struct Message *m2)
{
  return strcmp(m1->cmd, m2->cmd);
}

static int mtokcmp(const struct Message **m1, const struct Message **m2)
{
  return strcmp((*m1)->tok, (*m2)->tok);
}

/*
 * Sort the command names.
 * Create table of pointers into msgtab for tokens.
 * Create trees for ->cmd and ->tok and free the token pointers.
 */
void initmsgtree(void)
{
  int i;
  struct Message *msg = msgtab;
  int ii;
  struct Message **msgtab_tok;
  struct Message **msgtok;

  for (i = 0; msg->cmd; ++i, ++msg)
    continue;
  qsort(msgtab, i, sizeof(struct Message),
      (int (*)(const void *, const void *))mcmdcmp);
  msgtab_tok = (struct Message **)MyMalloc((i + 1) * sizeof(struct Message *));
  for (ii = 0; ii < i; ++ii)
    msgtab_tok[ii] = msgtab + ii;
  msgtab_tok[i] = NULL;         /* Needed by `do_msg_tree_tok' */
  qsort(msgtab_tok, i, sizeof(struct Message *),
      (int (*)(const void *, const void *))mtokcmp);
  msg = do_msg_tree_cmd(&msg_tree_cmd, "", msgtab);
  msgtok = do_msg_tree_tok(&msg_tree_tok, "", msgtab_tok);
  MyFree(msgtab_tok);
}

/*
 * Generic tree parser which works for both commands and tokens.
 * Optimized by Run.
 */
static struct Message *msg_tree_parse(char *cmd, struct MessageTree *root)
{
  struct MessageTree *mtree;
  unsigned char r = (0xdf & (unsigned char)*cmd) - 'A';
  if (r > 25 || !(mtree = root->pointers[r]))
    return NULL;
  for (;;)
  {
    r = 0xdf & (unsigned char)*++cmd;
    if (mtree->final && *mtree->final == r)
      return mtree->msg;
    if ((r -= 'A') > 25 || !(mtree = mtree->pointers[r]))
      return NULL;
  }
}

/*
 * This one is identical to the one above, but it is slower because it
 * makes sure that `cmd' matches the _full_ command, exactly.
 * This is to avoid confusion with commands like /quake on clients
 * that send unknown commands directly to the server.
 */
static struct Message *msg_tree_parse_client(char *cmd,
    struct MessageTree *root)
{
  struct MessageTree *mtree;
  unsigned char q = (0xdf & (unsigned char)*cmd) - 'A';
  if (q > 25 || !(mtree = root->pointers[q]))
    return NULL;
  for (;;)
  {
    q = 0xdf & (unsigned char)*++cmd;
    if (mtree->final && 0 == ircd_strcmp(mtree->final, cmd))
      return mtree->msg;
    if ((q -= 'A') > 25 || !(mtree = mtree->pointers[q]))
      return NULL;
  }
}

/*
 * parse a buffer.
 *
 * NOTE: parse_*() should not be called recusively by any other fucntions!
 */
int parse_client(struct Client *cptr, char *buffer, char *bufend)
{
  struct Client*  from = cptr;
  char*           ch;
  char*           s;
  int             i;
  int             paramcount;
  int             noprefix = 0;
  struct Message* mptr;
  MessageHandler  handler = 0;

  Debug((DEBUG_DEBUG, "Client Parsing: %s", buffer));

  if (IsDead(cptr))
    return 0;

  para[0] = cli_name(from);
  for (ch = buffer; *ch == ' '; ch++);  /* Eat leading spaces */
  if (*ch == ':')               /* Is any client doing this ? */
  {
    for (++ch; *ch && *ch != ' '; ++ch)
      ; /* Ignore sender prefix from client */
    while (*ch == ' ')
      ch++;                     /* Advance to command */
  }
  else
    noprefix = 1;
  if (*ch == '\0')
  {
    ServerStats->is_empt++;
    Debug((DEBUG_NOTICE, "Empty message from host %s:%s",
        cli_name(cptr), cli_name(from)));
    return (-1);
  }

  if ((s = strchr(ch, ' ')))
    *s++ = '\0';

  /*
   * This is a client/unregistered entity.
   * Check long command list only.
   */
  if (!(mptr = msg_tree_parse_client(ch, &msg_tree_cmd)))
  {
    /*
     * Note: Give error message *only* to recognized
     * persons. It's a nightmare situation to have
     * two programs sending "Unknown command"'s or
     * equivalent to each other at full blast....
     * If it has got to person state, it at least
     * seems to be well behaving. Perhaps this message
     * should never be generated, though...  --msa
     * Hm, when is the buffer empty -- if a command
     * code has been found ?? -Armin
     */
    if (buffer[0] != '\0')
    {
      if (IsUser(from))
	send_reply(from, ERR_UNKNOWNCOMMAND, ch);
      Debug((DEBUG_ERROR, "Unknown (%s) from %s",
            ch, get_client_name(cptr, HIDE_IP)));
    }
    ServerStats->is_unco++;
    return (-1);
  }

  paramcount = mptr->parameters;
  i = bufend - ((s) ? s : ch);
  mptr->bytes += i;
  if ((mptr->flags & MFLG_SLOW))
    cli_since(cptr) += (2 + i / 120);
  /*
   * Allow only 1 msg per 2 seconds
   * (on average) to prevent dumping.
   * to keep the response rate up,
   * bursts of up to 5 msgs are allowed
   * -SRB
   */

  /*
   * Must the following loop really be so devious? On
   * surface it splits the message to parameters from
   * blank spaces. But, if paramcount has been reached,
   * the rest of the message goes into this last parameter
   * (about same effect as ":" has...) --msa
   */

  /* Note initially true: s==NULL || *(s-1) == '\0' !! */

  i = 0;
  if (s)
  {
    if (paramcount > MAXPARA)
      paramcount = MAXPARA;
    for (;;)
    {
      /*
       * Never "FRANCE " again!! ;-) Clean
       * out *all* blanks.. --msa
       */
      while (*s == ' ')
        *s++ = '\0';

      if (*s == '\0')
        break;
      if (*s == ':')
      {
        /*
         * The rest is single parameter--can
         * include blanks also.
         */
        para[++i] = s + 1;
        break;
      }
      para[++i] = s;
      if (i >= paramcount)
        break;
      for (; *s != ' ' && *s; s++);
    }
  }
  para[++i] = NULL;
  ++mptr->count;

  handler = mptr->handlers[cli_handler(cptr)];
  assert(0 != handler);

  if (!feature_bool(FEAT_IDLE_FROM_MSG) && IsUser(cptr) &&
      handler != m_ping && handler != m_ignore)
    cli_user(from)->last = CurrentTime;

  return (*handler) (cptr, from, i, para);
}

int parse_server(struct Client *cptr, char *buffer, char *bufend)
{
  struct Client*  from = cptr;
  char*           ch = buffer;
  char*           s;
  int             len;
  int             i;
  int             numeric = 0;
  int             paramcount;
  struct Message* mptr;

  Debug((DEBUG_DEBUG, "Server Parsing: %s", buffer));

  if (IsDead(cptr))
    return 0;

  para[0] = cli_name(from);

  /*
   * A server ALWAYS sends a prefix. When it starts with a ':' it's the
   * protocol 9 prefix: a nick or a server name. Otherwise it's a numeric
   * nick or server
   */
  if (*ch == ':')
  {
    /* Let para[0] point to the name of the sender */
    para[0] = ch + 1;
    if (!(ch = strchr(ch, ' ')))
      return -1;
    *ch++ = '\0';

    /* And let `from' point to its client structure,
       opps.. a server is _also_ a client --Nem */
    from = FindClient(para[0]);

    /*
     * If the client corresponding to the
     * prefix is not found. We must ignore it,
     * it is simply a lagged message travelling
     * upstream a SQUIT that removed the client
     * --Run
     */
    if (!from)
    {
      Debug((DEBUG_NOTICE, "Unknown prefix (%s)(%s) from (%s)",
          para[0], buffer, cli_name(cptr)));
      ++ServerStats->is_unpf;
      while (*ch == ' ')
        ch++;
      /*
       * However, the only thing that MUST be
       * allowed to travel upstream against an
       * squit, is an SQUIT itself (the timestamp
       * protects us from being used wrong)
       */
      if (ch[1] == 'Q')
      {
        para[0] = cli_name(cptr);
        from = cptr;
      }
      else
        return 0;
    }
    else if (cli_from(from) != cptr)
    {
      ++ServerStats->is_wrdi;
      Debug((DEBUG_NOTICE, "Fake direction: Message (%s) coming from (%s)",
          buffer, cli_name(cptr)));
      return 0;
    }
  }
  else {
    char numeric_prefix[6];
    int  i;
    for (i = 0; i < 5; ++i) {
      if ('\0' == ch[i] || ' ' == (numeric_prefix[i] = ch[i])) {
        break;
      }
    }
    numeric_prefix[i] = '\0';

    /*
     * We got a numeric nick as prefix
     * 1 or 2 character prefixes are from servers
     * 3 or 5 chars are from clients
     */
    if (0 == i) {
      protocol_violation(cptr,"Missing Prefix");
      from = cptr;
    }
    else if (' ' == ch[1] || ' ' == ch[2])
      from = FindNServer(numeric_prefix);
    else
      from = findNUser(numeric_prefix);

    do
    {
      ++ch;
    }
    while (*ch != ' ' && *ch);

    /*
     * If the client corresponding to the
     * prefix is not found. We must ignore it,
     * it is simply a lagged message travelling
     * upstream a SQUIT that removed the client
     * --Run
     * There turned out to be other reasons that
     * a prefix is unknown, needing an upstream
     * KILL.  Also, next to an SQUIT we better
     * allow a KILL to pass too.
     * --Run
     */
    if (!from)
    {
      ServerStats->is_unpf++;
      while (*ch == ' ')
        ch++;
      if (*ch == 'N' && (ch[1] == ' ' || ch[1] == 'I'))
        /* Only sent a KILL for a nick change */
      {
        struct Client *server;
        /* Kill the unknown numeric prefix upstream if
         * it's server still exists: */
        if ((server = FindNServer(numeric_prefix)) && cli_from(server) == cptr)
	  sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (Unknown numeric nick)",
			numeric_prefix, cli_name(&me));
      }
      /*
       * Things that must be allowed to travel
       * upstream against an squit:
       */
      if (ch[1] == 'Q' || (*ch == 'D' && ch[1] == ' ') ||
          (*ch == 'K' && ch[2] == 'L'))
        from = cptr;
      else
        return 0;
    }

    /* Let para[0] point to the name of the sender */
    para[0] = cli_name(from);

    if (cli_from(from) != cptr)
    {
      ServerStats->is_wrdi++;
      Debug((DEBUG_NOTICE, "Fake direction: Message (%s) coming from (%s)",
          buffer, cli_name(cptr)));
      return 0;
    }
  }

  while (*ch == ' ')
    ch++;
  if (*ch == '\0')
  {
    ServerStats->is_empt++;
    Debug((DEBUG_NOTICE, "Empty message from host %s:%s",
        cli_name(cptr), cli_name(from)));
    return (-1);
  }

  /*
   * Extract the command code from the packet.   Point s to the end
   * of the command code and calculate the length using pointer
   * arithmetic.  Note: only need length for numerics and *all*
   * numerics must have parameters and thus a space after the command
   * code. -avalon
   */
  s = strchr(ch, ' ');          /* s -> End of the command code */
  len = (s) ? (s - ch) : 0;
  if (len == 3 && IsDigit(*ch))
  {
    numeric = (*ch - '0') * 100 + (*(ch + 1) - '0') * 10 + (*(ch + 2) - '0');
    paramcount = 2; /* destination, and the rest of it */
    ServerStats->is_num++;
    mptr = NULL;                /* Init. to avoid stupid compiler warning :/ */
  }
  else
  {
    if (s)
      *s++ = '\0';

    /* Version      Receive         Send
     * 2.9          Long            Long
     * 2.10.0       Tkn/Long        Long
     * 2.10.10      Tkn/Long        Tkn
     * 2.10.20      Tkn             Tkn
     *
     * Clients/unreg servers always receive/
     * send long commands   -record
     */

    /*
     * This is a server. Check the token command list.
     * -record!jegelhof@cloud9.net
     */
    mptr = msg_tree_parse(ch, &msg_tree_tok);

#if 1                           /* for 2.10.0/2.10.10 */
    /*
     * This code supports 2.9 and 2.10.0 sending long commands.
     * It makes more calls to ircd_strcmp() than the above
     * so it will be somewhat slower.
     */
    if (!mptr)
      mptr = msg_tree_parse(ch, &msg_tree_cmd);
#endif /* 1 */

    if (!mptr)
    {
      /*
       * Note: Give error message *only* to recognized
       * persons. It's a nightmare situation to have
       * two programs sending "Unknown command"'s or
       * equivalent to each other at full blast....
       * If it has got to person state, it at least
       * seems to be well behaving. Perhaps this message
       * should never be generated, though...   --msa
       * Hm, when is the buffer empty -- if a command
       * code has been found ?? -Armin
       */
#ifdef DEBUGMODE
      if (buffer[0] != '\0')
      {
        Debug((DEBUG_ERROR, "Unknown (%s) from %s",
              ch, get_client_name(cptr, HIDE_IP)));
      }
#endif
      ServerStats->is_unco++;
      return (-1);
    }

    paramcount = mptr->parameters;
    i = bufend - ((s) ? s : ch);
    mptr->bytes += i;
  }
  /*
   * Must the following loop really be so devious? On
   * surface it splits the message to parameters from
   * blank spaces. But, if paramcount has been reached,
   * the rest of the message goes into this last parameter
   * (about same effect as ":" has...) --msa
   */

  /* Note initially true: s==NULL || *(s-1) == '\0' !! */

  i = 0;
  if (s)
  {
    if (paramcount > MAXPARA)
      paramcount = MAXPARA;
    for (;;)
    {
      /*
       * Never "FRANCE " again!! ;-) Clean
       * out *all* blanks.. --msa
       */
      while (*s == ' ')
        *s++ = '\0';

      if (*s == '\0')
        break;
      if (*s == ':')
      {
        /*
         * The rest is single parameter--can
         * include blanks also.
         */
	if (numeric)
	  para[++i] = s; /* preserve the colon to make do_numeric happy */
	else
	  para[++i] = s + 1;
        break;
      }
      para[++i] = s;
      if (i >= paramcount)
        break;
      for (; *s != ' ' && *s; s++);
    }
  }
  para[++i] = NULL;
  if (numeric)
    return (do_numeric(numeric, (*buffer != ':'), cptr, from, i, para));
  mptr->count++;

  return (*mptr->handlers[cli_handler(cptr)]) (cptr, from, i, para);
}
