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
 */

#include "sys.h"
#include "h.h"
#include "struct.h"
#include "s_serv.h"
#include "send.h"
#include "parse.h"
#include "common.h"
#include "s_bsd.h"
#include "msg.h"
#include "s_user.h"
#include "s_serv.h"
#include "channel.h"
#include "whowas.h"
#include "s_ping.h"
#include "s_conf.h"
#include "res.h"
#include "map.h"
#include "hash.h"
#include "numeric.h"
#include "ircd.h"
#include "s_misc.h"
#include "common.h"
#include "s_numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "querycmds.h"
#include "whocmds.h"

RCSTAG_CC("$Id$");

/* *INDENT-OFF* */

aMessage msgtab[] = {
    {CLASS_PRIVATE,	MSG_PRIVATE,	TOK_PRIVATE,	m_private,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_NICK,	MSG_NICK,	TOK_NICK,	m_nick,		0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_NOTICE,	MSG_NOTICE,	TOK_NOTICE,	m_notice,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_WALLCHOPS,	MSG_WALLCHOPS,	TOK_WALLCHOPS,	m_wallchops,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_CPRIVMSG,	MSG_CPRIVMSG,	TOK_CPRIVMSG,	m_cprivmsg,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_CNOTICE,	MSG_CNOTICE,	TOK_CNOTICE,	m_cnotice,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_JOIN,	MSG_JOIN,	TOK_JOIN,	m_join,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_MODE,	MSG_MODE,	TOK_MODE,	m_mode,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_BURST,	MSG_BURST,	TOK_BURST,	m_burst,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_CREATE,	MSG_CREATE,	TOK_CREATE,	m_create,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_DESTRUCT,	MSG_DESTRUCT,	TOK_DESTRUCT,	m_destruct,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_QUIT,	MSG_QUIT,	TOK_QUIT,	m_quit,		0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_PART,	MSG_PART,	TOK_PART,	m_part,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_TOPIC,	MSG_TOPIC,	TOK_TOPIC,	m_topic,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_INVITE,	MSG_INVITE,	TOK_INVITE,	m_invite,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_KICK,	MSG_KICK,	TOK_KICK,	m_kick,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_WALLOPS,	MSG_WALLOPS,	TOK_WALLOPS,	m_wallops,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_DESYNCH,     MSG_DESYNCH,    TOK_DESYNCH,    m_desynch,      0, MAXPARA,     MFLG_SLOW,      0L},
    {CLASS_PING,	MSG_PING,	TOK_PING,	m_ping,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_PONG,	MSG_PONG,	TOK_PONG,	m_pong,		0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_ERROR,	MSG_ERROR,	TOK_ERROR,	m_error,	0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_KILL,	MSG_KILL,	TOK_KILL,	m_kill,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_USER,	MSG_USER,	TOK_USER,	m_user,		0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_AWAY,	MSG_AWAY,	TOK_AWAY,	m_away,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_ISON,	MSG_ISON,	TOK_ISON,	m_ison,		0, 1,		MFLG_SLOW,	0L},
    {CLASS_SERVER,	MSG_SERVER,	TOK_SERVER,	m_server,	0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_SQUIT,	MSG_SQUIT,	TOK_SQUIT,	m_squit,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_WHOIS,	MSG_WHOIS,	TOK_WHOIS,	m_whois,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_WHO,		MSG_WHO,	TOK_WHO,	m_who,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_WHOWAS,	MSG_WHOWAS,	TOK_WHOWAS,	m_whowas,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_LIST,	MSG_LIST,	TOK_LIST,	m_list,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_NAMES,	MSG_NAMES,	TOK_NAMES,	m_names,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_USERHOST,	MSG_USERHOST,	TOK_USERHOST,	m_userhost,	0, 1,		MFLG_SLOW,	0L},
    {CLASS_USERIP,	MSG_USERIP,	TOK_USERIP,	m_userip,	0, 1,		MFLG_SLOW,	0L},
    {CLASS_TRACE,	MSG_TRACE,	TOK_TRACE,	m_trace,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_PASS,	MSG_PASS,	TOK_PASS,	m_pass,		0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_LUSERS,	MSG_LUSERS,	TOK_LUSERS,	m_lusers,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_TIME,	MSG_TIME,	TOK_TIME,	m_time,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_SETTIME,	MSG_SETTIME,	TOK_SETTIME,	m_settime,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_RPING,	MSG_RPING,	TOK_RPING,	m_rping,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_RPONG,	MSG_RPONG,	TOK_RPONG,	m_rpong,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_OPER,	MSG_OPER,	TOK_OPER,	m_oper,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_CONNECT,	MSG_CONNECT,	TOK_CONNECT,	m_connect,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_UPING,	MSG_UPING,	TOK_UPING,	m_uping,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_MAP,		MSG_MAP,	TOK_MAP,	m_map,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_VERSION,	MSG_VERSION,	TOK_VERSION,	m_version,	0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_STATS,	MSG_STATS,	TOK_STATS,	m_stats,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_LINKS,	MSG_LINKS,	TOK_LINKS,	m_links,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_ADMIN,	MSG_ADMIN,	TOK_ADMIN,	m_admin,	0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_HELP,	MSG_HELP,	TOK_HELP,	m_help,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_INFO,	MSG_INFO,	TOK_INFO,	m_info,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_MOTD,	MSG_MOTD,	TOK_MOTD,	m_motd,		0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_CLOSE,	MSG_CLOSE,	TOK_CLOSE,	m_close,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_SILENCE,	MSG_SILENCE,	TOK_SILENCE,	m_silence,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_GLINE,	MSG_GLINE,	TOK_GLINE,	m_gline,	0, MAXPARA,	MFLG_SLOW,	0L},
    {CLASS_END_OF_BURST, MSG_END_OF_BURST, TOK_END_OF_BURST, m_end_of_burst, 0, MAXPARA, MFLG_SLOW,	0L},
    {CLASS_END_OF_BURST_ACK, MSG_END_OF_BURST_ACK, TOK_END_OF_BURST_ACK, m_end_of_burst_ack, 0, MAXPARA, 1, 0L},
    {CLASS_HASH,	MSG_HASH,	TOK_HASH,	m_hash,		0, MAXPARA,	MFLG_SLOW|MFLG_UNREG,	0L},
    {CLASS_DNS,		MSG_DNS,	TOK_DNS,	m_dns,		0, MAXPARA,	MFLG_SLOW,	0L},
#if defined(OPER_REHASH) || defined(LOCOP_REHASH)
    {CLASS_REHASH,	MSG_REHASH,	TOK_REHASH,	m_rehash,	0, MAXPARA,	MFLG_SLOW,	0L},
#endif
#if defined(OPER_RESTART) || defined(LOCOP_RESTART)
    {CLASS_RESTART,	MSG_RESTART,	TOK_RESTART,	m_restart,	0, MAXPARA,	MFLG_SLOW,	0L},
#endif
#if defined(OPER_DIE) || defined(LOCOP_DIE)
    {CLASS_DIE,		MSG_DIE,	TOK_DIE,	m_die,		0, MAXPARA,	MFLG_SLOW,	0L},
#endif
    {0, (char *)0, (char *)0, (int (*)(aClient *, aClient *, int, char **))0,	0, 0, 0, 0L}
}                                                                                                                                   ;
/* *INDENT-ON* */

#ifdef GODMODE
extern int sdbflag;
#endif /* GODMODE */

static char *para[MAXPARA + 2];	/* leave room for prefix and null */

/*
 * Message Tree stuff mostly written by orabidoo, with changes by Dianora.
 * Adapted to Undernet, adding token support, etc by comstud 10/06/97
 */

static aMessageTree msg_tree_cmd;
static aMessageTree msg_tree_tok;

/*
 * Guts of making the token tree...
 */
static aMessage **do_msg_tree_tok(aMessageTree *mtree, char *prefix,
    aMessage **mptr)
{
  char newprefix[64];		/* Must be longer than every command name */
  int c, c2, lp;
  aMessageTree *mtree1;

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
    if (!strCasediff((*mptr)->tok, prefix))
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
	mtree1 = (aMessageTree *)RunMalloc(sizeof(aMessageTree));
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
  MyCoreDump;			/* This should never happen */
  exit(1);
}

/*
 * Guts of making the command tree...
 */
static aMessage *do_msg_tree_cmd(aMessageTree *mtree, char *prefix,
    aMessage *mptr)
{
  char newprefix[64];		/* Must be longer than every command name */
  int c, c2, lp;
  aMessageTree *mtree1;

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
    if (!strCasediff(mptr->cmd, prefix))
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
	mtree1 = (aMessageTree *)RunMalloc(sizeof(aMessageTree));
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
  MyCoreDump;			/* This should never happen */
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
  Reg1 int i;
  Reg2 aMessage *msg = msgtab;
  Reg3 int ii;
  aMessage **msgtab_tok;
  aMessage **msgtok;

  for (i = 0; msg->cmd; ++i, ++msg)
    continue;
  qsort(msgtab, i, sizeof(aMessage),
      (int (*)(const void *, const void *))mcmdcmp);
  msgtab_tok = (aMessage **)RunMalloc((i + 1) * sizeof(aMessage *));
  for (ii = 0; ii < i; ++ii)
    msgtab_tok[ii] = msgtab + ii;
  msgtab_tok[i] = NULL;		/* Needed by `do_msg_tree_tok' */
  qsort(msgtab_tok, i, sizeof(aMessage *),
      (int (*)(const void *, const void *))mtokcmp);
  msg = do_msg_tree_cmd(&msg_tree_cmd, "", msgtab);
  msgtok = do_msg_tree_tok(&msg_tree_tok, "", msgtab_tok);
  RunFree(msgtab_tok);
}

/*
 * Generic tree parser which works for both commands and tokens.
 * Optimized by Run.
 */
static struct Message *msg_tree_parse(register char *cmd, aMessageTree *root)
{
  register aMessageTree *mtree;
  register unsigned char r = (0xdf & (unsigned char)*cmd) - 'A';
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
static struct Message *msg_tree_parse_client(register char *cmd,
    aMessageTree *root)
{
  register aMessageTree *mtree;
  register unsigned char q = (0xdf & (unsigned char)*cmd) - 'A';
  if (q > 25 || !(mtree = root->pointers[q]))
    return NULL;
  for (;;)
  {
    q = 0xdf & (unsigned char)*++cmd;
    if (mtree->final && !strCasediff(mtree->final, cmd))
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
int parse_client(aClient *cptr, char *buffer, char *bufend)
{
  Reg1 aClient *from = cptr;
  Reg2 char *ch, *s;
  Reg3 int i, paramcount, noprefix = 0;
  aMessage *mptr;

  Debug((DEBUG_DEBUG, "Parsing: %s", buffer));
  StoreBuffer((buffer, cptr));	/* Store the buffer now, before
				   we start working on it */

  if (IsDead(cptr))
    return 0;

  para[0] = from->name;
  for (ch = buffer; *ch == ' '; ch++);	/* Eat leading spaces */
  if (*ch == ':')		/* Is any client doing this ? */
  {
    for (++ch; *ch && *ch != ' '; ++ch);	/* Ignore sender prefix from client */
    while (*ch == ' ')
      ch++;			/* Advance to command */
  }
  else
    noprefix = 1;
  if (*ch == '\0')
  {
    ircstp->is_empt++;
    Debug((DEBUG_NOTICE, "Empty message from host %s:%s",
	cptr->name, from->name));
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
	sendto_one(from, ":%s %d %s %s :Unknown command",
	    me.name, ERR_UNKNOWNCOMMAND, from->name, ch);
      Debug((DEBUG_ERROR, "Unknown (%s) from %s",
	  ch, get_client_name(cptr, TRUE)));
    }
    ircstp->is_unco++;
    return (-1);
  }
  LogMessage((cptr, mptr->msgclass));

  paramcount = mptr->parameters;
  i = bufend - ((s) ? s : ch);
  mptr->bytes += i;
  if ((mptr->flags & MFLG_SLOW))
    cptr->since += (2 + i / 120);
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
  mptr->count++;
  /* The "unregistered command check" was ugly and mildly inefficient.
   * I fixed it. :)  --Shadow
   */
  if (!IsUser(cptr) && !(mptr->flags & MFLG_UNREG))
  {
    sendto_one(from, ":%s %d * %s :Register first.",
	me.name, ERR_NOTREGISTERED, ch);
    return -1;
  }
  if (IsUser(cptr) &&
#ifdef	IDLE_FROM_MSG
      mptr->func == m_private)
#else
      mptr->func != m_ping && mptr->func != m_pong)
#endif
      from->user->last = now;

  return (*mptr->func) (cptr, from, i, para);
}

int parse_server(aClient *cptr, char *buffer, char *bufend)
{
  Reg1 aClient *from = cptr;
  Reg2 char *ch = buffer, *s;
  Reg3 int len, i, numeric = 0, paramcount;
  aMessage *mptr;

  Debug((DEBUG_DEBUG, "Parsing: %s", buffer));
  StoreBuffer((buffer, cptr));	/* Store the buffer now, before
				 * we start working on it. */

#ifdef GODMODE
  len = strlen(buffer);
  sdbflag = 1;
  if (len > 402)
  {
    char c = buffer[200];
    buffer[200] = 0;
    sendto_ops("RCV:%-8.8s(%.4d): \"%s...%s\"",
	cptr->name, len, buffer, &buffer[len - 200]);
    buffer[200] = c;
  }
  else
    sendto_ops("RCV:%-8.8s(%.4d): \"%s\"", cptr->name, len, buffer);
  sdbflag = 0;
#endif /* GODMODE */

  if (IsDead(cptr))
    return 0;

  para[0] = from->name;

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
	  para[0], buffer, cptr->name));
      ircstp->is_unpf++;
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
	para[0] = cptr->name;
	from = cptr;
      }
      else
	return 0;
    }
    else if (from->from != cptr)
    {
      ircstp->is_wrdi++;
      Debug((DEBUG_NOTICE, "Fake direction: Message (%s) coming from (%s)",
	  buffer, cptr->name));
      return 0;
    }
  }
  else if (Protocol(cptr) > 9)	/* Well, not ALWAYS, 2.9 can send no prefix */
  {
    char numeric_prefix[6];
    int i;
    for (i = 0; i < 5; ++i)
    {
      if ('\0' == ch[i] || ' ' == (numeric_prefix[i] = ch[i]))
      {
	break;
      }
    }
    numeric_prefix[i] = '\0';
    /*
     * We got a numeric nick as prefix
     * 1 or 2 character prefixes are from servers
     * 3 or 5 chars are from clients
     */
    if (' ' == ch[1] || ' ' == ch[2])
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
      ircstp->is_unpf++;
      while (*ch == ' ')
	ch++;
      if (*ch == 'N' && (ch[1] == ' ' || ch[1] == 'I'))
	/* Only sent a KILL for a nick change */
      {
	aClient *server;
	/* Kill the unknown numeric prefix upstream if
	 * it's server still exists: */
	if ((server = FindNServer(numeric_prefix)) && server->from == cptr)
	  sendto_one(cptr, "%s KILL %s :%s (Unknown numeric nick)",
	      NumServ(&me), numeric_prefix, me.name);
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
    para[0] = from->name;

    if (from->from != cptr)
    {
      ircstp->is_wrdi++;
      Debug((DEBUG_NOTICE, "Fake direction: Message (%s) coming from (%s)",
	  buffer, cptr->name));
      return 0;
    }
  }

  while (*ch == ' ')
    ch++;
  if (*ch == '\0')
  {
    ircstp->is_empt++;
    Debug((DEBUG_NOTICE, "Empty message from host %s:%s",
	cptr->name, from->name));
    return (-1);
  }

  /*
   * Extract the command code from the packet.   Point s to the end
   * of the command code and calculate the length using pointer
   * arithmetic.  Note: only need length for numerics and *all*
   * numerics must have parameters and thus a space after the command
   * code. -avalon
   */
  s = strchr(ch, ' ');		/* s -> End of the command code */
  len = (s) ? (s - ch) : 0;
  if (len == 3 && isDigit(*ch))
  {
    numeric = (*ch - '0') * 100 + (*(ch + 1) - '0') * 10 + (*(ch + 2) - '0');
    paramcount = MAXPARA;
    ircstp->is_num++;
    mptr = NULL;		/* Init. to avoid stupid compiler warning :/ */
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

#if 1				/* for 2.10.0/2.10.10 */
    /*
     * This code supports 2.9 and 2.10.0 sending long commands.
     * It makes more calls to strCasediff() than the above
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
	    ch, get_client_name(cptr, TRUE)));
      }
#endif
      ircstp->is_unco++;
      return (-1);
    }
    LogMessage((cptr, mptr->msgclass));

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

  return (*mptr->func) (cptr, from, i, para);
}
