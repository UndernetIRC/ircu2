/*
 * IRC - Internet Relay Chat, ircd/channel.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Co Center
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
#include <stdlib.h>
#include "h.h"
#include "struct.h"
#include "channel.h"
#include "parse.h"
#include "whowas.h"
#include "send.h"
#include "s_err.h"
#include "numeric.h"
#include "ircd.h"
#include "common.h"
#include "match.h"
#include "list.h"
#include "hash.h"
#include "s_misc.h"
#include "s_user.h"
#include "s_conf.h"
#include "s_bsd.h"
#include "msg.h"
#include "common.h"
#include "s_serv.h"
#include "channel.h"
#include "support.h"
#include "numnicks.h"
#include "sprintf_irc.h"
#include "querycmds.h"

RCSTAG_CC("$Id$");

aChannel *channel = NullChn;

static void sendmodeto_one(aClient *cptr, char *from, char *name,
    char *mode, char *param, time_t creationtime);
static void add_invite(aClient *, aChannel *);
static int add_banid(aClient *, aChannel *, char *, int, int);
static Link *next_overlapped_ban(void);
static Link *next_removed_overlapped_ban(void);
static int can_join(aClient *, aChannel *, char *);
static void channel_modes(aClient *, char *, char *, aChannel *);
static int del_banid(aChannel *, char *, int);
static int is_banned(aClient *, aChannel *, Link *);
static int number_of_zombies(aChannel *);
static int is_deopped(aClient *, aChannel *);
static int set_mode(aClient *, aClient *, aChannel *, int,
    char **, char *, char *, char *, int *);
static void sub1_from_channel(aChannel *);
static void send_hack_notice(aClient *, aClient *, int, char *[], int, int);
static void clean_channelname(char *);

void del_invite(aClient *, aChannel *);

static char *PartFmt1 = ":%s PART %s";
static char *PartFmt2 = ":%s PART %s :%s";
/*
 * some buffers for rebuilding channel/nick lists with ,'s
 */
static char nickbuf[BUFSIZE], buf[BUFSIZE];
static char modebuf[MODEBUFLEN], parabuf[MODEBUFLEN];
static char nparabuf[MODEBUFLEN];

/*
 * Maximum acceptable lag time in seconds: A channel younger than
 * this is not protected against hacking admins.
 * Mainly here to check if the TS clocks really sync (otherwise this
 * will start causing HACK notices.
 * This value must be the same on all servers.
 *
 * This value has been increased to 1 day in order to distinguish this
 * "normal" type of HACK wallops / desyncs, from possiblity still
 * existing bugs.
 */
#define TS_LAG_TIME ((time_t)86400)

/*
 * A Magic TS that is used for channels that are created by JOIN,
 * a channel with this TS accepts all TS without complaining that
 * it might receive later via MODE or CREATE.
 */
#define MAGIC_REMOTE_JOIN_TS 1270080000

/*
 * return the length (>=0) of a chain of links.
 */
static int list_length(Link *lp)
{
  Reg2 int count = 0;

  for (; lp; lp = lp->next)
    count++;
  return count;
}

/*
 * find_chasing
 *
 * Find the client structure for a nick name (user) using history
 * mechanism if necessary. If the client is not found, an error
 * message (NO SUCH NICK) is generated. If the client was found
 * through the history, chasing will be 1 and otherwise 0.
 */
static aClient *find_chasing(aClient *sptr, char *user, int *chasing)
{
  Reg2 aClient *who = FindClient(user);

  if (chasing)
    *chasing = 0;
  if (who)
    return who;
  if (!(who = get_history(user, (long)KILLCHASETIMELIMIT)))
  {
    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, sptr->name, user);
    return NULL;
  }
  if (chasing)
    *chasing = 1;
  return who;
}

/*
 * Create a string of form "foo!bar@fubar" given foo, bar and fubar
 * as the parameters.  If NULL, they become "*".
 */
static char *make_nick_user_host(char *nick, char *name, char *host)
{
  static char namebuf[NICKLEN + USERLEN + HOSTLEN + 3];
  sprintf_irc(namebuf, "%s!%s@%s", nick, name, host);
  return namebuf;
}

/*
 * Create a string of form "foo!bar@123.456.789.123" given foo, bar and the
 * IP-number as the parameters.  If NULL, they become "*".
 */
static char *make_nick_user_ip(char *nick, char *name, struct in_addr ip)
{
  static char ipbuf[NICKLEN + USERLEN + 16 + 3];
  sprintf_irc(ipbuf, "%s!%s@%s", nick, name, inetntoa(ip));
  return ipbuf;
}

/*
 * add_banid
 *
 * `cptr' must be the client adding the ban.
 *
 * If `change' is true then add `banid' to channel `chptr'.
 * Returns 0 if the ban was added.
 * Returns -2 if the ban already existed and was marked CHFL_BURST_BAN_WIPEOUT.
 * Return -1 otherwise.
 *
 * Those bans that overlapped with `banid' are flagged with CHFL_BAN_OVERLAPPED
 * when `change' is false, otherwise they will be removed from the banlist.
 * Subsequently calls to next_overlapped_ban() or next_removed_overlapped_ban()
 * respectively will return these bans until NULL is returned.
 *
 * If `firsttime' is true, the ban list as returned by next_overlapped_ban()
 * is reset (unless a non-zero value is returned, in which case the
 * CHFL_BAN_OVERLAPPED flag might not have been reset!).
 *
 * --Run
 */
static Link *next_ban, *prev_ban, *removed_bans_list;

static int add_banid(aClient *cptr, aChannel *chptr, char *banid,
    int change, int firsttime)
{
  Reg1 Link *ban, **banp;
  Reg2 int cnt = 0, removed_bans = 0, len = strlen(banid);

  if (firsttime)
  {
    next_ban = NULL;
    if (prev_ban || removed_bans_list)
      MyCoreDump;		/* Memory leak */
  }
  if (MyUser(cptr))
    collapse(banid);
  for (banp = &chptr->banlist; *banp;)
  {
    len += strlen((*banp)->value.ban.banstr);
    ++cnt;
    if (((*banp)->flags & CHFL_BURST_BAN_WIPEOUT))
    {
      if (!strcmp((*banp)->value.ban.banstr, banid))
      {
	(*banp)->flags &= ~CHFL_BURST_BAN_WIPEOUT;
	return -2;
      }
    }
    else if (!mmatch((*banp)->value.ban.banstr, banid))
      return -1;
    if (!mmatch(banid, (*banp)->value.ban.banstr))
    {
      Link *tmp = *banp;
      if (change)
      {
	if (MyUser(cptr))
	{
	  cnt--;
	  len -= strlen(tmp->value.ban.banstr);
	}
	*banp = tmp->next;
#if 0
	/* Silently remove overlapping bans */
	RunFree(tmp->value.ban.banstr);
	RunFree(tmp->value.ban.who);
	free_link(tmp);
#else
	/* These will be sent to the user later as -b */
	tmp->next = removed_bans_list;
	removed_bans_list = tmp;
	removed_bans = 1;
#endif
      }
      else if (!(tmp->flags & CHFL_BURST_BAN_WIPEOUT))
      {
	tmp->flags |= CHFL_BAN_OVERLAPPED;
	if (!next_ban)
	  next_ban = tmp;
	banp = &tmp->next;
      }
      else
	banp = &tmp->next;
    }
    else
    {
      if (firsttime)
	(*banp)->flags &= ~CHFL_BAN_OVERLAPPED;
      banp = &(*banp)->next;
    }
  }
  if (MyUser(cptr) && !removed_bans && (len > MAXBANLENGTH || (cnt >= MAXBANS)))
  {
    sendto_one(cptr, err_str(ERR_BANLISTFULL), me.name, cptr->name,
	chptr->chname, banid);
    return -1;
  }
  if (change)
  {
    char *ip_start;
    ban = make_link();
    ban->next = chptr->banlist;
    ban->value.ban.banstr = (char *)RunMalloc(strlen(banid) + 1);
    strcpy(ban->value.ban.banstr, banid);
    ban->value.ban.who = (char *)RunMalloc(strlen(cptr->name) + 1);
    strcpy(ban->value.ban.who, cptr->name);
    ban->value.ban.when = now;
    ban->flags = CHFL_BAN;	/* This bit is never used I think... */
    if ((ip_start = strrchr(banid, '@')) && check_if_ipmask(ip_start + 1))
      ban->flags |= CHFL_BAN_IPMASK;
    chptr->banlist = ban;
    /* Erase ban-valid-bit */
    for (ban = chptr->members; ban; ban = ban->next)
      ban->flags &= ~CHFL_BANVALID;	/* `ban' == channel member ! */
  }
  return 0;
}

static Link *next_overlapped_ban(void)
{
  Reg1 Link *tmp = next_ban;
  if (tmp)
  {
    Reg2 Link *ban;
    for (ban = tmp->next; ban; ban = ban->next)
      if ((ban->flags & CHFL_BAN_OVERLAPPED))
	break;
    next_ban = ban;
  }
  return tmp;
}

static Link *next_removed_overlapped_ban(void)
{
  Reg1 Link *tmp = removed_bans_list;
  if (prev_ban)
  {
    if (prev_ban->value.ban.banstr)	/* Can be set to NULL in set_mode() */
      RunFree(prev_ban->value.ban.banstr);
    RunFree(prev_ban->value.ban.who);
    free_link(prev_ban);
  }
  if (tmp)
    removed_bans_list = removed_bans_list->next;
  prev_ban = tmp;
  return tmp;
}

/*
 * del_banid
 *
 * If `change' is true, delete `banid' from channel `chptr'.
 * Returns `false' if removal was (or would have been) successful.
 */
static int del_banid(aChannel *chptr, char *banid, int change)
{
  Reg1 Link **ban;
  Reg2 Link *tmp;

  if (!banid)
    return -1;
  for (ban = &(chptr->banlist); *ban; ban = &((*ban)->next))
    if (strCasediff(banid, (*ban)->value.ban.banstr) == 0)
    {
      tmp = *ban;
      if (change)
      {
	*ban = tmp->next;
	RunFree(tmp->value.ban.banstr);
	RunFree(tmp->value.ban.who);
	free_link(tmp);
	/* Erase ban-valid-bit, for channel members that are banned */
	for (tmp = chptr->members; tmp; tmp = tmp->next)
	  if ((tmp->flags & (CHFL_BANNED | CHFL_BANVALID)) ==
	      (CHFL_BANNED | CHFL_BANVALID))
	    tmp->flags &= ~CHFL_BANVALID;	/* `tmp' == channel member */
      }
      return 0;
    }
  return -1;
}

/*
 * IsMember - returns Link * if a person is joined and not a zombie
 */
Link *IsMember(aClient *cptr, aChannel *chptr)
{
  Link *lp;
  return (((lp = find_user_link(chptr->members, cptr)) &&
      !(lp->flags & CHFL_ZOMBIE)) ? lp : NULL);
}

/*
 * is_banned - a non-zero value if banned else 0.
 */
static int is_banned(aClient *cptr, aChannel *chptr, Link *member)
{
  Reg1 Link *tmp;
  char *s, *ip_s = NULL;

  if (!IsUser(cptr))
    return 0;

  if (member)
  {
    if ((member->flags & CHFL_BANVALID))
      return (member->flags & CHFL_BANNED);
  }

  s = make_nick_user_host(cptr->name, cptr->user->username, cptr->user->host);

  for (tmp = chptr->banlist; tmp; tmp = tmp->next)
  {
    if ((tmp->flags & CHFL_BAN_IPMASK))
    {
      if (!ip_s)
	ip_s = make_nick_user_ip(cptr->name, cptr->user->username, cptr->ip);
      if (match(tmp->value.ban.banstr, ip_s) == 0)
	break;
    }
    else if (match(tmp->value.ban.banstr, s) == 0)
      break;
  }

  if (member)
  {
    member->flags |= CHFL_BANVALID;
    if (tmp)
    {
      member->flags |= CHFL_BANNED;
      return 1;
    }
    else
    {
      member->flags &= ~CHFL_BANNED;
      return 0;
    }
  }

  return (tmp != NULL);
}

/*
 * adds a user to a channel by adding another link to the channels member
 * chain.
 */
static void add_user_to_channel(aChannel *chptr, aClient *who, int flags)
{
  Reg1 Link *ptr;

  if (who->user)
  {
    ptr = make_link();
    ptr->value.cptr = who;
    ptr->flags = flags;
    ptr->next = chptr->members;
    chptr->members = ptr;
    chptr->users++;

    ptr = make_link();
    ptr->value.chptr = chptr;
    ptr->next = who->user->channel;
    who->user->channel = ptr;
    who->user->joined++;
  }
}

void remove_user_from_channel(aClient *sptr, aChannel *chptr)
{
  Reg1 Link **curr;
  Reg2 Link *tmp;
  Reg3 Link *lp = chptr->members;

  for (; lp && (lp->flags & CHFL_ZOMBIE || lp->value.cptr == sptr);
      lp = lp->next);
  for (;;)
  {
    for (curr = &chptr->members; (tmp = *curr); curr = &tmp->next)
      if (tmp->value.cptr == sptr)
      {
	*curr = tmp->next;
	free_link(tmp);
	break;
      }
    for (curr = &sptr->user->channel; (tmp = *curr); curr = &tmp->next)
      if (tmp->value.chptr == chptr)
      {
	*curr = tmp->next;
	free_link(tmp);
	break;
      }
    sptr->user->joined--;
    if (lp)
      break;
    if (chptr->members)
      sptr = chptr->members->value.cptr;
    else
      break;
    sub1_from_channel(chptr);
  }
  sub1_from_channel(chptr);
}

int is_chan_op(aClient *cptr, aChannel *chptr)
{
  Reg1 Link *lp;

  if (chptr)
    if ((lp = find_user_link(chptr->members, cptr)) &&
	!(lp->flags & CHFL_ZOMBIE))
      return (lp->flags & CHFL_CHANOP);

  return 0;
}

static int is_deopped(aClient *cptr, aChannel *chptr)
{
  Reg1 Link *lp;

  if (chptr)
    if ((lp = find_user_link(chptr->members, cptr)))
      return (lp->flags & CHFL_DEOPPED);

  return (IsUser(cptr) ? 1 : 0);
}

int is_zombie(aClient *cptr, aChannel *chptr)
{
  Reg1 Link *lp;

  if (chptr)
    if ((lp = find_user_link(chptr->members, cptr)))
      return (lp->flags & CHFL_ZOMBIE);

  return 0;
}

int has_voice(aClient *cptr, aChannel *chptr)
{
  Reg1 Link *lp;

  if (chptr)
    if ((lp = find_user_link(chptr->members, cptr)) &&
	!(lp->flags & CHFL_ZOMBIE))
      return (lp->flags & CHFL_VOICE);

  return 0;
}

int can_send(aClient *cptr, aChannel *chptr)
{
  Reg1 Link *lp;

  lp = IsMember(cptr, chptr);

  if ((!lp || !(lp->flags & (CHFL_CHANOP | CHFL_VOICE)) ||
      (lp->flags & CHFL_ZOMBIE)) && MyUser(cptr) && is_banned(cptr, chptr, lp))
    return (MODE_BAN);

  if (chptr->mode.mode & MODE_MODERATED &&
      (!lp || !(lp->flags & (CHFL_CHANOP | CHFL_VOICE)) ||
      (lp->flags & CHFL_ZOMBIE)))
    return (MODE_MODERATED);

  if (!lp && ((chptr->mode.mode & MODE_NOPRIVMSGS) ||
      IsModelessChannel(chptr->chname)))
    return (MODE_NOPRIVMSGS);

  return 0;
}

/*
 * write the "simple" list of channel modes for channel chptr onto buffer mbuf
 * with the parameters in pbuf.
 */
static void channel_modes(aClient *cptr, char *mbuf, char *pbuf,
    aChannel *chptr)
{
  *mbuf++ = '+';
  if (chptr->mode.mode & MODE_SECRET)
    *mbuf++ = 's';
  else if (chptr->mode.mode & MODE_PRIVATE)
    *mbuf++ = 'p';
  if (chptr->mode.mode & MODE_MODERATED)
    *mbuf++ = 'm';
  if (chptr->mode.mode & MODE_TOPICLIMIT)
    *mbuf++ = 't';
  if (chptr->mode.mode & MODE_INVITEONLY)
    *mbuf++ = 'i';
  if (chptr->mode.mode & MODE_NOPRIVMSGS)
    *mbuf++ = 'n';
  if (chptr->mode.limit)
  {
    *mbuf++ = 'l';
    sprintf_irc(pbuf, "%d", chptr->mode.limit);
  }
  if (*chptr->mode.key)
  {
    *mbuf++ = 'k';
    if (is_chan_op(cptr, chptr) || IsServer(cptr))
    {
      if (chptr->mode.limit)
	strcat(pbuf, " ");
      strcat(pbuf, chptr->mode.key);
    }
  }
  *mbuf = '\0';
  return;
}

static int send_mode_list(aClient *cptr, char *chname, time_t creationtime,
    Link *top, int mask, char flag)
{
  Reg1 Link *lp;
  Reg2 char *cp, *name;
  int count = 0, send = 0, sent = 0;

  cp = modebuf + strlen(modebuf);
  if (*parabuf)			/* mode +l or +k xx */
    count = 1;
  for (lp = top; lp; lp = lp->next)
  {
    if (!(lp->flags & mask))
      continue;
    if (mask == CHFL_BAN)
      name = lp->value.ban.banstr;
    else
      name = lp->value.cptr->name;
    if (strlen(parabuf) + strlen(name) + 11 < (size_t)MODEBUFLEN)
    {
      strcat(parabuf, " ");
      strcat(parabuf, name);
      count++;
      *cp++ = flag;
      *cp = '\0';
    }
    else if (*parabuf)
      send = 1;
    if (count == 6)
      send = 1;
    if (send)
    {
      /* cptr is always a server! So we send creationtimes */
      sendmodeto_one(cptr, me.name, chname, modebuf, parabuf, creationtime);
      sent = 1;
      send = 0;
      *parabuf = '\0';
      cp = modebuf;
      *cp++ = '+';
      if (count != 6)
      {
	strcpy(parabuf, name);
	*cp++ = flag;
      }
      count = 0;
      *cp = '\0';
    }
  }
  return sent;
}

/*
 * send "cptr" a full list of the modes for channel chptr.
 */
void send_channel_modes(aClient *cptr, aChannel *chptr)
{
  int sent;
  if (IsLocalChannel(chptr->chname))
    return;

  *modebuf = *parabuf = '\0';
  channel_modes(cptr, modebuf, parabuf, chptr);

  if (Protocol(cptr) < 10)
  {
    sent = send_mode_list(cptr, chptr->chname, chptr->creationtime,
	chptr->members, CHFL_CHANOP, 'o');
    if (!sent && chptr->creationtime)
      sendto_one(cptr, ":%s MODE %s %s %s " TIME_T_FMT, me.name,
	  chptr->chname, modebuf, parabuf, chptr->creationtime);
    else if (modebuf[1] || *parabuf)
      sendmodeto_one(cptr, me.name,
	  chptr->chname, modebuf, parabuf, chptr->creationtime);

    *parabuf = '\0';
    *modebuf = '+';
    modebuf[1] = '\0';
    send_mode_list(cptr, chptr->chname, chptr->creationtime,
	chptr->banlist, CHFL_BAN, 'b');
    if (modebuf[1] || *parabuf)
      sendmodeto_one(cptr, me.name, chptr->chname, modebuf,
	  parabuf, chptr->creationtime);

    *parabuf = '\0';
    *modebuf = '+';
    modebuf[1] = '\0';
    send_mode_list(cptr, chptr->chname, chptr->creationtime,
	chptr->members, CHFL_VOICE, 'v');
    if (modebuf[1] || *parabuf)
      sendmodeto_one(cptr, me.name, chptr->chname, modebuf,
	  parabuf, chptr->creationtime);
  }
  else
  {
    static unsigned int current_flags[4] =
	{ 0, CHFL_CHANOP | CHFL_VOICE, CHFL_VOICE, CHFL_CHANOP };
    int first = 1, full = 1, flag_cnt = 0, new_mode = 0;
    size_t len, sblen;
    Link *lp1 = chptr->members;
    Link *lp2 = chptr->banlist;
    for (first = 1; full; first = 0)	/* Loop for multiple messages */
    {
      full = 0;			/* Assume by default we get it
				   all in one message */

      /* (Continued) prefix: "<Y> BURST <channel> <TS>" */
      sprintf_irc(sendbuf, "%s BURST %s " TIME_T_FMT, NumServ(&me),
	  chptr->chname, chptr->creationtime);
      sblen = strlen(sendbuf);

      if (first && modebuf[1])	/* Add simple modes (iklmnpst)
				   if first message */
      {
	/* prefix: "<Y> BURST <channel> <TS>[ <modes>[ <params>]]" */
	sendbuf[sblen++] = ' ';
	strcpy(sendbuf + sblen, modebuf);
	sblen += strlen(modebuf);
	if (*parabuf)
	{
	  sendbuf[sblen++] = ' ';
	  strcpy(sendbuf + sblen, parabuf);
	  sblen += strlen(parabuf);
	}
      }

      /* Attach nicks, comma seperated " nick[:modes],nick[:modes],..." */
      /* Run 4 times over all members, to group the members with the
       * same mode together */
      for (first = 1; flag_cnt < 4;
	  lp1 = chptr->members, new_mode = 1, flag_cnt++)
      {
	for (; lp1; lp1 = lp1->next)
	{
	  if ((lp1->flags & (CHFL_CHANOP | CHFL_VOICE)) !=
	      current_flags[flag_cnt])
	    continue;		/* Skip members with different flags */
	  if (sblen + NUMNICKLEN + 4 > BUFSIZE - 3)
	    /* The 4 is a possible ",:ov"
	       The -3 is for the "\r\n\0" that is added in send.c */
	  {
	    full = 1;		/* Make sure we continue after
				   sending it so far */
	    break;		/* Do not add this member to this message */
	  }
	  sendbuf[sblen++] = first ? ' ' : ',';
	  first = 0;		/* From now on, us comma's to add new nicks */

	  sprintf_irc(sendbuf + sblen, "%s%s", NumNick(lp1->value.cptr));
	  sblen += strlen(sendbuf + sblen);

	  if (new_mode)		/* Do we have a nick with a new mode ? */
	  {
	    new_mode = 0;
	    sendbuf[sblen++] = ':';
	    if (lp1->flags & CHFL_CHANOP)
	      sendbuf[sblen++] = 'o';
	    if (lp1->flags & CHFL_VOICE)
	      sendbuf[sblen++] = 'v';
	  }
	}
	if (full)
	  break;
      }

      if (!full)
      {
	/* Attach all bans, space seperated " :%ban ban ..." */
	for (first = 2; lp2; lp2 = lp2->next)
	{
	  len = strlen(lp2->value.ban.banstr);
	  if (sblen + len + 1 + first > BUFSIZE - 3)
	    /* The +1 stands for the added ' '.
	     * The +first stands for the added ":%".
	     * The -3 is for the "\r\n\0" that is added in send.c
	     */
	  {
	    full = 1;
	    break;
	  }
	  if (first)
	  {
	    first = 0;
	    sendbuf[sblen++] = ' ';
	    sendbuf[sblen++] = ':';	/* Will be last parameter */
	    sendbuf[sblen++] = '%';	/* To tell bans apart */
	  }
	  else
	    sendbuf[sblen++] = ' ';
	  strcpy(sendbuf + sblen, lp2->value.ban.banstr);
	  sblen += len;
	}
      }

      sendbuf[sblen] = '\0';
      sendbufto_one(cptr);	/* Send this message */
    }				/* Continue when there was something
				   that didn't fit (full==1) */
  }
}

/*
 * m_mode
 * parv[0] - sender
 * parv[1] - channel
 */

int m_mode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  int badop, sendts;
  aChannel *chptr;

  /* Now, try to find the channel in question */
  if (parc > 1)
  {
    chptr = FindChannel(parv[1]);
    if (chptr == NullChn)
      return m_umode(cptr, sptr, parc, parv);
  }
  else
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "MODE");
    return 0;
  }

  sptr->flags &= ~FLAGS_TS8;

  if (MyUser(sptr))
    clean_channelname(parv[1]);
  else if (IsLocalChannel(parv[1]))
    return 0;

  /* sending an error wasnt good, lets just send an empty mode reply..  poptix */
  if (IsModelessChannel(chptr->chname))
  {
    if (IsUser(sptr))
      sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
	  chptr->chname, "+nt", "");
    return 0;
  }

  if (parc < 3)
  {
    *modebuf = *parabuf = '\0';
    modebuf[1] = '\0';
    channel_modes(sptr, modebuf, parabuf, chptr);
    sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
	chptr->chname, modebuf, parabuf);
    sendto_one(sptr, rpl_str(RPL_CREATIONTIME), me.name, parv[0],
	chptr->chname, chptr->creationtime);
    return 0;
  }

  if (!(sendts = set_mode(cptr, sptr, chptr, parc - 2, parv + 2,
      modebuf, parabuf, nparabuf, &badop)))
  {
    sendto_one(sptr, err_str(IsMember(sptr, chptr) ? ERR_CHANOPRIVSNEEDED :
	ERR_NOTONCHANNEL), me.name, parv[0], chptr->chname);
    return 0;
  }

  if (badop >= 2)
    send_hack_notice(cptr, sptr, parc, parv, badop, 1);

  if (strlen(modebuf) > (size_t)1 || sendts > 0)
  {
    if (badop != 2 && strlen(modebuf) > (size_t)1)
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s %s",
	  parv[0], chptr->chname, modebuf, parabuf);
    if (IsLocalChannel(chptr->chname))
      return 0;
    /* We send a creationtime of 0, to mark it as a hack --Run */
    if (IsServer(sptr) && (badop == 2 || sendts > 0))
    {
      if (*modebuf == '\0')
	strcpy(modebuf, "+");
      if (badop != 2)
      {
	sendto_lowprot_butone(cptr, 9, ":%s MODE %s %s %s " TIME_T_FMT,
	    parv[0], chptr->chname, modebuf, parabuf,
	    (badop == 4) ? (time_t) 0 : chptr->creationtime);
	sendto_highprot_butone(cptr, 10, ":%s MODE %s %s %s " TIME_T_FMT,
	    parv[0], chptr->chname, modebuf, nparabuf,
	    (badop == 4) ? (time_t) 0 : chptr->creationtime);
      }
    }
    else
    {
      sendto_lowprot_butone(cptr, 9, ":%s MODE %s %s %s",
	  parv[0], chptr->chname, modebuf, parabuf);
      sendto_highprot_butone(cptr, 10, ":%s MODE %s %s %s",
	  parv[0], chptr->chname, modebuf, nparabuf);
    }
  }
  return 0;
}

static int DoesOp(char *modebuf)
{
  modebuf--;			/* Is it possible that a mode
				   starts with o and not +o ? */
  while (*++modebuf)
    if (*modebuf == 'o' || *modebuf == 'v')
      return (1);
  return 0;
}

/* This function should be removed when all servers are 2.10 */
static void sendmodeto_one(aClient *cptr, char *from, char *name,
    char *mode, char *param, time_t creationtime)
{
  if (IsServer(cptr) && DoesOp(mode) && creationtime)
    sendto_one(cptr, ":%s MODE %s %s %s " TIME_T_FMT,
	from, name, mode, param, creationtime);
  else
    sendto_one(cptr, ":%s MODE %s %s %s", from, name, mode, param);
}

/*
 * pretty_mask
 *
 * by Carlo Wood (Run), 05 Oct 1998.
 *
 * Canonify a mask.
 *
 * When the nick is longer then NICKLEN, it is cut off (its an error of course).
 * When the user name or host name are too long (USERLEN and HOSTLEN
 * respectively) then they are cut off at the start with a '*'.
 *
 * The following transformations are made:
 *
 * 1)   xxx             -> nick!*@*
 * 2)   xxx.xxx         -> *!*@host
 * 3)   xxx!yyy         -> nick!user@*
 * 4)   xxx@yyy         -> *!user@host
 * 5)   xxx!yyy@zzz     -> nick!user@host
 */
char *pretty_mask(char *mask)
{
  static char star[2] = { '*', 0 };
  char *last_dot = NULL;
  char *ptr;

  /* Case 1: default */
  char *nick = mask;
  char *user = star;
  char *host = star;

  /* Do a _single_ pass through the characters of the mask: */
  for (ptr = mask; *ptr; ++ptr)
  {
    if (*ptr == '!')
    {
      /* Case 3 or 5: Found first '!' (without finding a '@' yet) */
      user = ++ptr;
      host = star;
    }
    else if (*ptr == '@')
    {
      /* Case 4: Found last '@' (without finding a '!' yet) */
      nick = star;
      user = mask;
      host = ++ptr;
    }
    else if (*ptr == '.')
    {
      /* Case 2: Found last '.' (without finding a '!' or '@' yet) */
      last_dot = ptr;
      continue;
    }
    else
      continue;
    for (; *ptr; ++ptr)
    {
      if (*ptr == '@')
      {
	/* Case 4 or 5: Found last '@' */
	host = ptr + 1;
      }
    }
    break;
  }
  if (user == star && last_dot)
  {
    /* Case 2: */
    nick = star;
    user = star;
    host = mask;
  }
  /* Check lengths */
  if (nick != star)
  {
    char *nick_end = (user != star) ? user - 1 : ptr;
    if (nick_end - nick > NICKLEN)
      nick[NICKLEN] = 0;
    *nick_end = 0;
  }
  if (user != star)
  {
    char *user_end = (host != star) ? host - 1 : ptr;
    if (user_end - user > USERLEN)
    {
      user = user_end - USERLEN;
      *user = '*';
    }
    *user_end = 0;
  }
  if (host != star && ptr - host > HOSTLEN)
  {
    host = ptr - HOSTLEN;
    *host = '*';
  }
  return make_nick_user_host(nick, user, host);
}

static char bmodebuf[MODEBUFLEN], bparambuf[MODEBUFLEN];
static char nbparambuf[MODEBUFLEN];	/* "Numeric" Bounce Parameter Buffer */

/*
 * Check and try to apply the channel modes passed in the parv array for
 * the client ccptr to channel chptr.  The resultant changes are printed
 * into mbuf and pbuf (if any) and applied to the channel.
 */
static int set_mode(aClient *cptr, aClient *sptr, aChannel *chptr, int parc,
    char *parv[], char *mbuf, char *pbuf, char *npbuf, int *badop)
{
  static Link chops[MAXPARA - 2];	/* This size is only needed when a broken
					   server sends more then MAXMODEPARAMS
					   parameters */
  static int flags[] = {
    MODE_PRIVATE, 'p', MODE_SECRET, 's',
    MODE_MODERATED, 'm', MODE_NOPRIVMSGS, 'n',
    MODE_TOPICLIMIT, 't', MODE_INVITEONLY, 'i',
    MODE_VOICE, 'v', MODE_KEY, 'k',
    0x0, 0x0
  };

  Reg1 Link *lp;
  Reg2 char *curr = parv[0], *cp = NULL;
  Reg3 int *ip;
  Link *member, *tmp = NULL;
  unsigned int whatt = MODE_ADD, bwhatt = 0;
  int limitset = 0, bounce, add_banid_called = 0;
  size_t len, nlen, blen, nblen;
  int keychange = 0;
  unsigned int nusers = 0, newmode;
  int opcnt = 0, banlsent = 0;
  int doesdeop = 0, doesop = 0, hacknotice = 0, change, gotts = 0;
  aClient *who;
  Mode *mode, oldm;
  static char numeric[16];
  char *bmbuf = bmodebuf, *bpbuf = bparambuf, *nbpbuf = nbparambuf;
  time_t newtime = (time_t) 0;
  aConfItem *aconf;

  *mbuf = *pbuf = *npbuf = *bmbuf = *bpbuf = *nbpbuf = '\0';
  *badop = 0;
  if (parc < 1)
    return 0;

  mode = &(chptr->mode);
  memcpy(&oldm, mode, sizeof(Mode));
  /*
   * Mode is accepted when sptr is a channel operator
   * but also when the mode is received from a server.
   * At this point, let any member pass, so they are allowed
   * to see the bans.
   */
  if (!(IsServer(cptr) || (tmp = IsMember(sptr, chptr))))
    return 0;

  newmode = mode->mode;

  while (curr && *curr)
  {
    switch (*curr)
    {
      case '+':
	whatt = MODE_ADD;
	break;
      case '-':
	whatt = MODE_DEL;
	break;
      case 'o':
      case 'v':
	if (--parc <= 0)
	  break;
	parv++;
	if (MyUser(sptr) && opcnt >= MAXMODEPARAMS)
	  break;
	/*
	 * Check for nickname changes and try to follow these
	 * to make sure the right client is affected by the
	 * mode change.
	 * Even if we find a nick with find_chasing() there
	 * is still a reason to ignore in a special case.
	 * We need to ignore the mode when:
	 * - It is part of a net.burst (from a server and
	 *   a MODE_ADD). Ofcourse we don't ignore mode
	 *   changes from Uworld.
	 * - The found nick is not on the right side off
	 *   the net.junction.
	 * This fixes the bug that when someone (tries to)
	 * ride a net.break and does so with the nick of
	 * someone on the otherside, that he is nick collided
	 * (killed) but his +o still ops the other person.
	 */
	if (MyUser(sptr) || Protocol(cptr) < 10)
	{
	  if (!(who = find_chasing(sptr, parv[0], NULL)))
	    break;
	}
	else
	{
	  if (!(who = findNUser(parv[0])))
	    break;
	}
	if (whatt == MODE_ADD && IsServer(sptr) && who->from != sptr->from &&
	    !find_conf_host(cptr->confs, sptr->name, CONF_UWORLD))
	  break;
	if (!(member = find_user_link(chptr->members, who)) ||
	    (MyUser(sptr) && (member->flags & CHFL_ZOMBIE)))
	{
	  sendto_one(cptr, err_str(ERR_USERNOTINCHANNEL),
	      me.name, cptr->name, who->name, chptr->chname);
	  break;
	}
	/* if the user is +k, prevent a deop from local user */
	if (whatt == MODE_DEL && IsChannelService(who) &&
	    MyUser(cptr) && *curr == 'o')
	{
	  sendto_one(cptr, err_str(ERR_ISCHANSERVICE), me.name,
	      cptr->name, parv[0], chptr->chname);
	  break;
	}
	if (whatt == MODE_ADD)
	{
	  lp = &chops[opcnt++];
	  lp->value.cptr = who;
	  if (IsServer(sptr) && (!(who->flags & FLAGS_TS8) || ((*curr == 'o') &&
	      !(member->flags & (CHFL_SERVOPOK | CHFL_CHANOP)))))
	    *badop = ((member->flags & CHFL_DEOPPED) && (*curr == 'o')) ? 2 : 3;
	  lp->flags = (*curr == 'o') ? MODE_CHANOP : MODE_VOICE;
	  lp->flags |= MODE_ADD;
	}
	else if (whatt == MODE_DEL)
	{
	  lp = &chops[opcnt++];
	  lp->value.cptr = who;
	  doesdeop = 1;		/* Also when -v */
	  lp->flags = (*curr == 'o') ? MODE_CHANOP : MODE_VOICE;
	  lp->flags |= MODE_DEL;
	}
	if (*curr == 'o')
	  doesop = 1;
	break;
      case 'k':
	if (--parc <= 0)
	  break;
	parv++;
	/* check now so we eat the parameter if present */
	if (keychange)
	  break;
	else
	{
	  char *s = &(*parv)[-1];
	  unsigned short count = KEYLEN + 1;

	  while (*++s > ' ' && *s != ':' && --count);
	  *s = '\0';
	  if (!**parv)		/* nothing left in key */
	    break;
	}
	if (MyUser(sptr) && opcnt >= MAXMODEPARAMS)
	  break;
	if (whatt == MODE_ADD)
	{
	  if (*mode->key && !IsServer(cptr))
	    sendto_one(cptr, err_str(ERR_KEYSET),
		me.name, cptr->name, chptr->chname);
	  else if (!*mode->key || IsServer(cptr))
	  {
	    lp = &chops[opcnt++];
	    lp->value.cp = *parv;
	    if (strlen(lp->value.cp) > (size_t)KEYLEN)
	      lp->value.cp[KEYLEN] = '\0';
	    lp->flags = MODE_KEY | MODE_ADD;
	    keychange = 1;
	  }
	}
	else if (whatt == MODE_DEL)
	{
	  if (strCasediff(mode->key, *parv) == 0 || IsServer(cptr))
	  {
	    lp = &chops[opcnt++];
	    lp->value.cp = mode->key;
	    lp->flags = MODE_KEY | MODE_DEL;
	    keychange = 1;
	  }
	}
	break;
      case 'b':
	if (--parc <= 0)
	{
	  if (banlsent)		/* Only send it once */
	    break;
	  for (lp = chptr->banlist; lp; lp = lp->next)
	    sendto_one(cptr, rpl_str(RPL_BANLIST), me.name, cptr->name,
		chptr->chname, lp->value.ban.banstr, lp->value.ban.who,
		lp->value.ban.when);
	  sendto_one(cptr, rpl_str(RPL_ENDOFBANLIST), me.name, cptr->name,
	      chptr->chname);
	  banlsent = 1;
	  break;
	}
	parv++;
	if (BadPtr(*parv))
	  break;
	if (MyUser(sptr))
	{
	  if ((cp = strchr(*parv, ' ')))
	    *cp = 0;
	  if (opcnt >= MAXMODEPARAMS || **parv == ':' || **parv == '\0')
	    break;
	}
	if (whatt == MODE_ADD)
	{
	  lp = &chops[opcnt++];
	  lp->value.cp = *parv;
	  lp->flags = MODE_ADD | MODE_BAN;
	}
	else if (whatt == MODE_DEL)
	{
	  lp = &chops[opcnt++];
	  lp->value.cp = *parv;
	  lp->flags = MODE_DEL | MODE_BAN;
	}
	break;
      case 'l':
	/*
	 * limit 'l' to only *1* change per mode command but
	 * eat up others.
	 */
	if (limitset)
	{
	  if (whatt == MODE_ADD && --parc > 0)
	    parv++;
	  break;
	}
	if (whatt == MODE_DEL)
	{
	  limitset = 1;
	  nusers = 0;
	  break;
	}
	if (--parc > 0)
	{
	  if (BadPtr(*parv))
	    break;
	  if (MyUser(sptr) && opcnt >= MAXMODEPARAMS)
	    break;
	  if (!(nusers = atoi(*++parv)))
	    continue;
	  lp = &chops[opcnt++];
	  lp->flags = MODE_ADD | MODE_LIMIT;
	  limitset = 1;
	  break;
	}
	sendto_one(cptr, err_str(ERR_NEEDMOREPARAMS),
	    me.name, cptr->name, "MODE +l");
	break;
      case 'i':		/* falls through for default case */
	if (whatt == MODE_DEL)
	  while ((lp = chptr->invites))
	    del_invite(lp->value.cptr, chptr);
      default:
	for (ip = flags; *ip; ip += 2)
	  if (*(ip + 1) == *curr)
	    break;

	if (*ip)
	{
	  if (whatt == MODE_ADD)
	  {
	    if (*ip == MODE_PRIVATE)
	      newmode &= ~MODE_SECRET;
	    else if (*ip == MODE_SECRET)
	      newmode &= ~MODE_PRIVATE;
	    newmode |= *ip;
	  }
	  else
	    newmode &= ~*ip;
	}
	else if (!IsServer(cptr))
	  sendto_one(cptr, err_str(ERR_UNKNOWNMODE),
	      me.name, cptr->name, *curr);
	break;
    }
    curr++;
    /*
     * Make sure mode strings such as "+m +t +p +i" are parsed
     * fully.
     */
    if (!*curr && parc > 0)
    {
      curr = *++parv;
      parc--;
      /* If this was from a server, and it is the last
       * parameter and it starts with a digit, it must
       * be the creationtime.  --Run
       */
      if (IsServer(sptr))
      {
	if (parc == 1 && isDigit(*curr))
	{
	  newtime = atoi(curr);
	  if (newtime && chptr->creationtime == MAGIC_REMOTE_JOIN_TS)
	  {
	    chptr->creationtime = newtime;
	    *badop = 0;
	  }
	  gotts = 1;
	  if (newtime == 0)
	  {
	    *badop = 2;
	    hacknotice = 1;
	  }
	  else if (newtime > chptr->creationtime)
	  {			/* It is a net-break ride if we have ops.
				   bounce modes if we have ops.  --Run */
	    if (doesdeop)
	      *badop = 2;
	    else if (chptr->creationtime == 0)
	    {
	      if (chptr->creationtime == 0 || doesop)
		chptr->creationtime = newtime;
	      *badop = 0;
	    }
	    /* Bounce: */
	    else
	      *badop = 1;
	  }
	  /*
	   * A legal *badop can occur when two
	   * people join simultaneously a channel,
	   * Allow for 10 min of lag (and thus hacking
	   * on channels younger then 10 min) --Run
	   */
	  else if (*badop == 0 ||
	      chptr->creationtime > (TStime() - TS_LAG_TIME))
	  {
	    if (newtime < chptr->creationtime)
	      chptr->creationtime = newtime;
	    *badop = 0;
	  }
	  break;
	}
      }
      else
	*badop = 0;
    }
  }				/* end of while loop for MODE processing */

  /* Now reject non chan ops */
  if (!IsServer(cptr) && (!tmp || !(tmp->flags & CHFL_CHANOP)))
  {
    *badop = 0;
    return (opcnt || newmode != mode->mode || limitset || keychange) ? 0 : -1;
  }

  if (doesop && newtime == 0 && IsServer(sptr))
    *badop = 2;

  if (*badop >= 2 &&
      (aconf = find_conf_host(cptr->confs, sptr->name, CONF_UWORLD)))
    *badop = 4;

  bounce = (*badop == 1 || *badop == 2 || is_deopped(sptr, chptr)) ? 1 : 0;

  whatt = 0;
  for (ip = flags; *ip; ip += 2)
    if ((*ip & newmode) && !(*ip & oldm.mode))
    {
      if (bounce)
      {
	if (bwhatt != MODE_DEL)
	{
	  *bmbuf++ = '-';
	  bwhatt = MODE_DEL;
	}
	*bmbuf++ = *(ip + 1);
      }
      else
      {
	if (whatt != MODE_ADD)
	{
	  *mbuf++ = '+';
	  whatt = MODE_ADD;
	}
	mode->mode |= *ip;
	*mbuf++ = *(ip + 1);
      }
    }

  for (ip = flags; *ip; ip += 2)
    if ((*ip & oldm.mode) && !(*ip & newmode))
    {
      if (bounce)
      {
	if (bwhatt != MODE_ADD)
	{
	  *bmbuf++ = '+';
	  bwhatt = MODE_ADD;
	}
	*bmbuf++ = *(ip + 1);
      }
      else
      {
	if (whatt != MODE_DEL)
	{
	  *mbuf++ = '-';
	  whatt = MODE_DEL;
	}
	mode->mode &= ~*ip;
	*mbuf++ = *(ip + 1);
      }
    }

  blen = nblen = 0;
  if (limitset && !nusers && mode->limit)
  {
    if (bounce)
    {
      if (bwhatt != MODE_ADD)
      {
	*bmbuf++ = '+';
	bwhatt = MODE_ADD;
      }
      *bmbuf++ = 'l';
      sprintf(numeric, "%-15d", mode->limit);
      if ((cp = strchr(numeric, ' ')))
	*cp = '\0';
      strcat(bpbuf, numeric);
      blen += strlen(numeric);
      strcat(bpbuf, " ");
      strcat(nbpbuf, numeric);
      nblen += strlen(numeric);
      strcat(nbpbuf, " ");
    }
    else
    {
      if (whatt != MODE_DEL)
      {
	*mbuf++ = '-';
	whatt = MODE_DEL;
      }
      mode->mode &= ~MODE_LIMIT;
      mode->limit = 0;
      *mbuf++ = 'l';
    }
  }
  /*
   * Reconstruct "+bkov" chain.
   */
  if (opcnt)
  {
    Reg1 int i = 0;
    Reg2 char c = 0;
    unsigned int prev_whatt = 0;

    for (; i < opcnt; i++)
    {
      lp = &chops[i];
      /*
       * make sure we have correct mode change sign
       */
      if (whatt != (lp->flags & (MODE_ADD | MODE_DEL)))
      {
	if (lp->flags & MODE_ADD)
	{
	  *mbuf++ = '+';
	  prev_whatt = whatt;
	  whatt = MODE_ADD;
	}
	else
	{
	  *mbuf++ = '-';
	  prev_whatt = whatt;
	  whatt = MODE_DEL;
	}
      }
      len = strlen(pbuf);
      nlen = strlen(npbuf);
      /*
       * get c as the mode char and tmp as a pointer to
       * the parameter for this mode change.
       */
      switch (lp->flags & MODE_WPARAS)
      {
	case MODE_CHANOP:
	  c = 'o';
	  cp = lp->value.cptr->name;
	  break;
	case MODE_VOICE:
	  c = 'v';
	  cp = lp->value.cptr->name;
	  break;
	case MODE_BAN:
	  /*
	   * I made this a bit more user-friendly (tm):
	   * nick = nick!*@*
	   * nick!user = nick!user@*
	   * user@host = *!user@host
	   * host.name = *!*@host.name    --Run
	   */
	  c = 'b';
	  cp = pretty_mask(lp->value.cp);
	  break;
	case MODE_KEY:
	  c = 'k';
	  cp = lp->value.cp;
	  break;
	case MODE_LIMIT:
	  c = 'l';
	  sprintf(numeric, "%-15d", nusers);
	  if ((cp = strchr(numeric, ' ')))
	    *cp = '\0';
	  cp = numeric;
	  break;
      }

      /* What could be added: cp+' '+' '+<TS>+'\0' */
      if (len + strlen(cp) + 13 > (size_t)MODEBUFLEN ||
	  nlen + strlen(cp) + NUMNICKLEN + 12 > (size_t)MODEBUFLEN)
	break;

      switch (lp->flags & MODE_WPARAS)
      {
	case MODE_KEY:
	  if (strlen(cp) > (size_t)KEYLEN)
	    *(cp + KEYLEN) = '\0';
	  if ((whatt == MODE_ADD && (*mode->key == '\0' ||
	      strCasediff(mode->key, cp) != 0)) ||
	      (whatt == MODE_DEL && (*mode->key != '\0')))
	  {
	    if (bounce)
	    {
	      if (*mode->key == '\0')
	      {
		if (bwhatt != MODE_DEL)
		{
		  *bmbuf++ = '-';
		  bwhatt = MODE_DEL;
		}
		strcat(bpbuf, cp);
		blen += strlen(cp);
		strcat(bpbuf, " ");
		blen++;
		strcat(nbpbuf, cp);
		nblen += strlen(cp);
		strcat(nbpbuf, " ");
		nblen++;
	      }
	      else
	      {
		if (bwhatt != MODE_ADD)
		{
		  *bmbuf++ = '+';
		  bwhatt = MODE_ADD;
		}
		strcat(bpbuf, mode->key);
		blen += strlen(mode->key);
		strcat(bpbuf, " ");
		blen++;
		strcat(nbpbuf, mode->key);
		nblen += strlen(mode->key);
		strcat(nbpbuf, " ");
		nblen++;
	      }
	      *bmbuf++ = c;
	      mbuf--;
	      if (*mbuf != '+' && *mbuf != '-')
		mbuf++;
	      else
		whatt = prev_whatt;
	    }
	    else
	    {
	      *mbuf++ = c;
	      strcat(pbuf, cp);
	      len += strlen(cp);
	      strcat(pbuf, " ");
	      len++;
	      strcat(npbuf, cp);
	      nlen += strlen(cp);
	      strcat(npbuf, " ");
	      nlen++;
	      if (whatt == MODE_ADD)
		strncpy(mode->key, cp, KEYLEN);
	      else
		*mode->key = '\0';
	    }
	  }
	  break;
	case MODE_LIMIT:
	  if (nusers && nusers != mode->limit)
	  {
	    if (bounce)
	    {
	      if (mode->limit == 0)
	      {
		if (bwhatt != MODE_DEL)
		{
		  *bmbuf++ = '-';
		  bwhatt = MODE_DEL;
		}
	      }
	      else
	      {
		if (bwhatt != MODE_ADD)
		{
		  *bmbuf++ = '+';
		  bwhatt = MODE_ADD;
		}
		sprintf(numeric, "%-15d", mode->limit);
		if ((cp = strchr(numeric, ' ')))
		  *cp = '\0';
		strcat(bpbuf, numeric);
		blen += strlen(numeric);
		strcat(bpbuf, " ");
		blen++;
		strcat(nbpbuf, numeric);
		nblen += strlen(numeric);
		strcat(nbpbuf, " ");
		nblen++;
	      }
	      *bmbuf++ = c;
	      mbuf--;
	      if (*mbuf != '+' && *mbuf != '-')
		mbuf++;
	      else
		whatt = prev_whatt;
	    }
	    else
	    {
	      *mbuf++ = c;
	      strcat(pbuf, cp);
	      len += strlen(cp);
	      strcat(pbuf, " ");
	      len++;
	      strcat(npbuf, cp);
	      nlen += strlen(cp);
	      strcat(npbuf, " ");
	      nlen++;
	      mode->limit = nusers;
	    }
	  }
	  break;
	case MODE_CHANOP:
	case MODE_VOICE:
	  tmp = find_user_link(chptr->members, lp->value.cptr);
	  if (lp->flags & MODE_ADD)
	  {
	    change = (~tmp->flags) & CHFL_OVERLAP & lp->flags;
	    if (change && bounce)
	    {
	      if (lp->flags & MODE_CHANOP)
		tmp->flags |= CHFL_DEOPPED;
	      if (bwhatt != MODE_DEL)
	      {
		*bmbuf++ = '-';
		bwhatt = MODE_DEL;
	      }
	      *bmbuf++ = c;
	      strcat(bpbuf, lp->value.cptr->name);
	      blen += strlen(lp->value.cptr->name);
	      strcat(bpbuf, " ");
	      blen++;
	      sprintf_irc(nbpbuf + nblen, "%s%s ", NumNick(lp->value.cptr));
	      nblen += strlen(nbpbuf + nblen);
	      change = 0;
	    }
	    else if (change)
	    {
	      tmp->flags |= lp->flags & CHFL_OVERLAP;
	      if (lp->flags & MODE_CHANOP)
	      {
		tmp->flags &= ~CHFL_DEOPPED;
		if (IsServer(sptr))
		  tmp->flags &= ~CHFL_SERVOPOK;
	      }
	    }
	  }
	  else
	  {
	    change = tmp->flags & CHFL_OVERLAP & lp->flags;
	    if (change && bounce)
	    {
	      if (lp->flags & MODE_CHANOP)
		tmp->flags &= ~CHFL_DEOPPED;
	      if (bwhatt != MODE_ADD)
	      {
		*bmbuf++ = '+';
		bwhatt = MODE_ADD;
	      }
	      *bmbuf++ = c;
	      strcat(bpbuf, lp->value.cptr->name);
	      blen += strlen(lp->value.cptr->name);
	      strcat(bpbuf, " ");
	      blen++;
	      sprintf_irc(nbpbuf + nblen, "%s%s ", NumNick(lp->value.cptr));
	      blen += strlen(bpbuf + blen);
	      change = 0;
	    }
	    else
	    {
	      tmp->flags &= ~change;
	      if ((change & MODE_CHANOP) && IsServer(sptr))
		tmp->flags |= CHFL_DEOPPED;
	    }
	  }
	  if (change || *badop == 2 || *badop == 4)
	  {
	    *mbuf++ = c;
	    strcat(pbuf, cp);
	    len += strlen(cp);
	    strcat(pbuf, " ");
	    len++;
	    sprintf_irc(npbuf + nlen, "%s%s ", NumNick(lp->value.cptr));
	    nlen += strlen(npbuf + nlen);
	    npbuf[nlen++] = ' ';
	    npbuf[nlen] = 0;
	  }
	  else
	  {
	    mbuf--;
	    if (*mbuf != '+' && *mbuf != '-')
	      mbuf++;
	    else
	      whatt = prev_whatt;
	  }
	  break;
	case MODE_BAN:
/*
 * Only bans aren't bounced, it makes no sense to bounce last second
 * bans while propagating bans done before the net.rejoin. The reason
 * why I don't bounce net.rejoin bans is because it is too much
 * work to take care of too long strings adding the necessary TS to
 * net.burst bans -- RunLazy
 * We do have to check for *badop==2 now, we don't want HACKs to take
 * effect.
 *
 * Since BURST - I *did* implement net.rejoin ban bouncing. So now it
 * certainly makes sense to also bounce 'last second' bans (bans done
 * after the net.junction). -- RunHardWorker
 */
	  if ((change = (whatt & MODE_ADD) &&
	      !add_banid(sptr, chptr, cp, !bounce, !add_banid_called)))
	    add_banid_called = 1;
	  else
	    change = (whatt & MODE_DEL) && !del_banid(chptr, cp, !bounce);

	  if (bounce && change)
	  {
	    change = 0;
	    if ((whatt & MODE_ADD))
	    {
	      if (bwhatt != MODE_DEL)
	      {
		*bmbuf++ = '-';
		bwhatt = MODE_DEL;
	      }
	    }
	    else if ((whatt & MODE_DEL))
	    {
	      if (bwhatt != MODE_ADD)
	      {
		*bmbuf++ = '+';
		bwhatt = MODE_ADD;
	      }
	    }
	    *bmbuf++ = c;
	    strcat(bpbuf, cp);
	    blen += strlen(cp);
	    strcat(bpbuf, " ");
	    blen++;
	    strcat(nbpbuf, cp);
	    nblen += strlen(cp);
	    strcat(nbpbuf, " ");
	    nblen++;
	  }
	  if (change)
	  {
	    *mbuf++ = c;
	    strcat(pbuf, cp);
	    len += strlen(cp);
	    strcat(pbuf, " ");
	    len++;
	    strcat(npbuf, cp);
	    nlen += strlen(cp);
	    strcat(npbuf, " ");
	    nlen++;
	  }
	  else
	  {
	    mbuf--;
	    if (*mbuf != '+' && *mbuf != '-')
	      mbuf++;
	    else
	      whatt = prev_whatt;
	  }
	  break;
      }
    }				/* for (; i < opcnt; i++) */
  }				/* if (opcnt) */

  *mbuf++ = '\0';
  *bmbuf++ = '\0';

  /* Bounce here */
  if (!hacknotice && *bmodebuf && chptr->creationtime)
  {
    if (Protocol(cptr) < 10)
      sendto_one(cptr, ":%s MODE %s %s %s " TIME_T_FMT,
	  me.name, chptr->chname, bmodebuf, bparambuf,
	  *badop == 2 ? (time_t) 0 : chptr->creationtime);
    else
      sendto_one(cptr, "%s MODE %s %s %s " TIME_T_FMT,
	  NumServ(&me), chptr->chname, bmodebuf, nbparambuf,
	  *badop == 2 ? (time_t) 0 : chptr->creationtime);
  }
  /* If there are possibly bans to re-add, bounce them now */
  if (add_banid_called && bounce)
  {
    Link *ban[6];		/* Max 6 bans at a time */
    size_t len[6], sblen, total_len;
    int cnt, delayed = 0;
    while (delayed || (ban[0] = next_overlapped_ban()))
    {
      len[0] = strlen(ban[0]->value.ban.banstr);
      cnt = 1;			/* We already got one ban :) */
      sblen = sprintf_irc(sendbuf, ":%s MODE %s +b",
	  me.name, chptr->chname) - sendbuf;
      total_len = sblen + 1 + len[0];	/* 1 = ' ' */
      /* Find more bans: */
      delayed = 0;
      while (cnt < 6 && (ban[cnt] = next_overlapped_ban()))
      {
	len[cnt] = strlen(ban[cnt]->value.ban.banstr);
	if (total_len + 5 + len[cnt] > BUFSIZE)	/* 5 = "b \r\n\0" */
	{
	  delayed = cnt + 1;	/* != 0 */
	  break;		/* Flush */
	}
	sendbuf[sblen++] = 'b';
	total_len += 2 + len[cnt++];	/* 2 = "b " */
      }
      while (cnt--)
      {
	sendbuf[sblen++] = ' ';
	strcpy(sendbuf + sblen, ban[cnt]->value.ban.banstr);
	sblen += len[cnt];
      }
      sendbufto_one(cptr);	/* Send bounce to uplink */
      if (delayed)
	ban[0] = ban[delayed - 1];
    }
  }
  /* Send -b's of overlapped bans to clients to keep them synchronized */
  if (add_banid_called && !bounce)
  {
    Link *ban;
    char *banstr[6];		/* Max 6 bans at a time */
    size_t len[6], sblen, psblen, total_len;
    int cnt, delayed = 0;
    Link *lp;
    aClient *acptr;
    if (IsServer(sptr))
      psblen = sprintf_irc(sendbuf, ":%s MODE %s -b",
	  sptr->name, chptr->chname) - sendbuf;
    else			/* We rely on IsRegistered(sptr) being true for MODE */
      psblen = sprintf_irc(sendbuf, ":%s!%s@%s MODE %s -b", sptr->name,
	  sptr->user->username, sptr->user->host, chptr->chname) - sendbuf;
    while (delayed || (ban = next_removed_overlapped_ban()))
    {
      if (!delayed)
      {
	len[0] = strlen((banstr[0] = ban->value.ban.banstr));
	ban->value.ban.banstr = NULL;
      }
      cnt = 1;			/* We already got one ban :) */
      sblen = psblen;
      total_len = sblen + 1 + len[0];	/* 1 = ' ' */
      /* Find more bans: */
      delayed = 0;
      while (cnt < 6 && (ban = next_removed_overlapped_ban()))
      {
	len[cnt] = strlen((banstr[cnt] = ban->value.ban.banstr));
	ban->value.ban.banstr = NULL;
	if (total_len + 5 + len[cnt] > BUFSIZE)	/* 5 = "b \r\n\0" */
	{
	  delayed = cnt + 1;	/* != 0 */
	  break;		/* Flush */
	}
	sendbuf[sblen++] = 'b';
	total_len += 2 + len[cnt++];	/* 2 = "b " */
      }
      while (cnt--)
      {
	sendbuf[sblen++] = ' ';
	strcpy(sendbuf + sblen, banstr[cnt]);
	RunFree(banstr[cnt]);
	sblen += len[cnt];
      }
      for (lp = chptr->members; lp; lp = lp->next)
	if (MyConnect(acptr = lp->value.cptr) && !(lp->flags & CHFL_ZOMBIE))
	  sendbufto_one(acptr);
      if (delayed)
      {
	banstr[0] = banstr[delayed - 1];
	len[0] = len[delayed - 1];
      }
    }
  }

  return gotts ? 1 : -1;
}

/* We are now treating the <key> part of /join <channel list> <key> as a key
 * ring; that is, we try one key against the actual channel key, and if that
 * doesn't work, we try the next one, and so on. -Kev -Texaco
 * Returns: 0 on match, 1 otherwise
 * This version contributed by SeKs <intru@info.polymtl.ca>
 */
static int compall(char *key, char *keyring)
{
  register char *p1;

top:
  p1 = key;			/* point to the key... */
  while (*p1 && *p1 == *keyring)
  {				/* step through the key and ring until they
				   don't match... */
    p1++;
    keyring++;
  }

  if (!*p1 && (!*keyring || *keyring == ','))
    /* ok, if we're at the end of the and also at the end of one of the keys
       in the keyring, we have a match */
    return 0;

  if (!*keyring)		/* if we're at the end of the key ring, there
				   weren't any matches, so we return 1 */
    return 1;

  /* Not at the end of the key ring, so step
     through to the next key in the ring: */
  while (*keyring && *(keyring++) != ',');

  goto top;			/* and check it against the key */
}

static int can_join(aClient *sptr, aChannel *chptr, char *key)
{
  Reg1 Link *lp;

  /* Now a banned user CAN join if invited -- Nemesi */
  /* Now a user CAN escape channel limit if invited -- bfriendly */
  if ((chptr->mode.mode & MODE_INVITEONLY) || (is_banned(sptr, chptr, NULL)
      || (chptr->mode.limit && chptr->users >= chptr->mode.limit)))
  {
    for (lp = sptr->user->invited; lp; lp = lp->next)
      if (lp->value.chptr == chptr)
	break;
    if (!lp)
    {
      if (chptr->mode.limit && chptr->users >= chptr->mode.limit)
	return (ERR_CHANNELISFULL);
      /* This can return an "Invite only" msg instead of the "You are banned"
         if _both_ conditions are true, but who can say what is more
         appropriate ? checking again IsBanned would be _SO_ cpu-xpensive ! */
      return ((chptr->mode.mode & MODE_INVITEONLY) ?
	  ERR_INVITEONLYCHAN : ERR_BANNEDFROMCHAN);
    }
  }

  /* now using compall (above) to test against a whole key ring -Kev */
  if (*chptr->mode.key && (BadPtr(key) || compall(chptr->mode.key, key)))
    return (ERR_BADCHANNELKEY);

  return 0;
}

/*
 * Remove bells and commas from channel name
 */

static void clean_channelname(char *cn)
{
  for (; *cn; cn++)
  {
    if (!isIrcCh(*cn))
    {
      *cn = '\0';
      return;
    }
    if (isIrcCl(*cn))
#ifndef FIXME
    {
#endif
      *cn = toLower(*cn);
#ifndef FIXME
      /* Missed the Icelandic letter ETH last time: */
      if ((unsigned char)(*cn) == 0xd0)
	*cn = (char)0xf0;
    }
#endif
  }
}

/*
 *  Get Channel block for i (and allocate a new channel
 *  block, if it didn't exists before).
 */
static aChannel *get_channel(aClient *cptr, char *chname, int flag)
{
  Reg1 aChannel *chptr;
  int len;

  if (BadPtr(chname))
    return NULL;

  len = strlen(chname);
  if (MyUser(cptr) && len > CHANNELLEN)
  {
    len = CHANNELLEN;
    *(chname + CHANNELLEN) = '\0';
  }
  if ((chptr = FindChannel(chname)))
    return (chptr);
  if (flag == CREATE)
  {
    chptr = (aChannel *)RunMalloc(sizeof(aChannel) + len);
    ++nrof.channels;
    memset(chptr, 0, sizeof(aChannel));
    strcpy(chptr->chname, chname);
    if (channel)
      channel->prevch = chptr;
    chptr->prevch = NULL;
    chptr->nextch = channel;
    chptr->creationtime = MyUser(cptr) ? TStime() : (time_t) 0;
    channel = chptr;
    hAddChannel(chptr);
  }
  return chptr;
}

static void add_invite(aClient *cptr, aChannel *chptr)
{
  Reg1 Link *inv, **tmp;

  del_invite(cptr, chptr);
  /*
   * Delete last link in chain if the list is max length
   */
  if (list_length(cptr->user->invited) >= MAXCHANNELSPERUSER)
    del_invite(cptr, cptr->user->invited->value.chptr);
  /*
   * Add client to channel invite list
   */
  inv = make_link();
  inv->value.cptr = cptr;
  inv->next = chptr->invites;
  chptr->invites = inv;
  /*
   * Add channel to the end of the client invite list
   */
  for (tmp = &(cptr->user->invited); *tmp; tmp = &((*tmp)->next));
  inv = make_link();
  inv->value.chptr = chptr;
  inv->next = NULL;
  (*tmp) = inv;
}

/*
 * Delete Invite block from channel invite list and client invite list
 */
void del_invite(aClient *cptr, aChannel *chptr)
{
  Reg1 Link **inv, *tmp;

  for (inv = &(chptr->invites); (tmp = *inv); inv = &tmp->next)
    if (tmp->value.cptr == cptr)
    {
      *inv = tmp->next;
      free_link(tmp);
      break;
    }

  for (inv = &(cptr->user->invited); (tmp = *inv); inv = &tmp->next)
    if (tmp->value.chptr == chptr)
    {
      *inv = tmp->next;
      free_link(tmp);
      break;
    }
}

/* List and skip all channels that are listen */
void list_next_channels(aClient *cptr, int nr)
{
  aListingArgs *args = cptr->listing;
  aChannel *chptr = args->chptr;
  chptr->mode.mode &= ~MODE_LISTED;
  while (is_listed(chptr) || --nr >= 0)
  {
    for (; chptr; chptr = chptr->nextch)
    {
      if (!cptr->user || (SecretChannel(chptr) && !IsMember(cptr, chptr)))
	continue;
      if (chptr->users > args->min_users && chptr->users < args->max_users &&
	  chptr->creationtime > args->min_time &&
	  chptr->creationtime < args->max_time &&
	  (!args->topic_limits || (*chptr->topic &&
	  chptr->topic_time > args->min_topic_time &&
	  chptr->topic_time < args->max_topic_time)))
      {
	sendto_one(cptr, rpl_str(RPL_LIST), me.name, cptr->name,
	    ShowChannel(cptr, chptr) ? chptr->chname : "*",
	    chptr->users, ShowChannel(cptr, chptr) ? chptr->topic : "");
	chptr = chptr->nextch;
	break;
      }
    }
    if (!chptr)
    {
      RunFree(cptr->listing);
      cptr->listing = NULL;
      sendto_one(cptr, rpl_str(RPL_LISTEND), me.name, cptr->name);
      break;
    }
  }
  if (chptr)
  {
    cptr->listing->chptr = chptr;
    chptr->mode.mode |= MODE_LISTED;
  }
}

/*
 *  Subtract one user from channel i (and free channel
 *  block, if channel became empty).
 */
static void sub1_from_channel(aChannel *chptr)
{
  Reg2 Link *tmp;
  Link *obtmp;

  if (chptr->users > 1)		/* Can be 0, called for an empty channel too */
  {
    --chptr->users;
    return;
  }

  /* Channel became (or was) empty: Remove channel */
  if (is_listed(chptr))
  {
    int i;
    for (i = 0; i <= highest_fd; i++)
    {
      aClient *acptr;
      if ((acptr = loc_clients[i]) && acptr->listing &&
	  acptr->listing->chptr == chptr)
      {
	list_next_channels(acptr, 1);
	break;			/* Only one client can list a channel */
      }
    }
  }
  /*
   * Now, find all invite links from channel structure
   */
  while ((tmp = chptr->invites))
    del_invite(tmp->value.cptr, chptr);

  tmp = chptr->banlist;
  while (tmp)
  {
    obtmp = tmp;
    tmp = tmp->next;
    RunFree(obtmp->value.ban.banstr);
    RunFree(obtmp->value.ban.who);
    free_link(obtmp);
  }
  if (chptr->prevch)
    chptr->prevch->nextch = chptr->nextch;
  else
    channel = chptr->nextch;
  if (chptr->nextch)
    chptr->nextch->prevch = chptr->prevch;
  hRemChannel(chptr);
  --nrof.channels;
  RunFree((char *)chptr);
}

/*
 * m_join
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = channel keys (client), or channel TS (server)
 */
int m_join(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  static char jbuf[BUFSIZE], mbuf[BUFSIZE];
  Reg1 Link *lp;
  Reg3 aChannel *chptr;
  Reg4 char *name, *keysOrTS = NULL;
  int i = 0, zombie = 0, sendcreate = 0;
  unsigned int flags = 0;
  size_t jlen = 0, mlen = 0;
  size_t *buflen;
  char *p = NULL, *bufptr;

  if (parc < 2 || *parv[1] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "JOIN");
    return 0;
  }

  for (p = parv[1]; *p; p++)	/* find the last "JOIN 0" in the line -Kev */
    if (*p == '0'
	&& (*(p + 1) == ',' || *(p + 1) == '\0' || !isIrcCh(*(p + 1))))
    {
      /* If it's a single "0", remember the place; we will start parsing
         the channels after the last 0 in the line -Kev */
      parv[1] = p;
      if (!*(p + 1))
	break;
      p++;
    }
    else
    {				/* Step through to the next comma or until the
				   end of the line, in an attempt to save CPU
				   -Kev */
      while (*p != ',' && *p != '\0')
	p++;
      if (!*p)
	break;
    }

  keysOrTS = parv[2];		/* Remember where our keys are or the TS is;
				   parv[2] needs to be NULL for the call to
				   m_names below -Kev */
  parv[2] = p = NULL;

  *jbuf = *mbuf = '\0';		/* clear both join and mode buffers -Kev */
  /*
   *  Rebuild list of channels joined to be the actual result of the
   *  JOIN.  Note that "JOIN 0" is the destructive problem.
   */
  for (name = strtoken(&p, parv[1], ","); name; name = strtoken(&p, NULL, ","))
  {
    size_t len;
    if (MyConnect(sptr))
      clean_channelname(name);
    else if (IsLocalChannel(name))
      continue;
    if (*name == '0' && *(name + 1) == '\0')
    {
      /* Remove the user from all his channels -Kev */
      while ((lp = sptr->user->channel))
      {
	chptr = lp->value.chptr;
	if (!is_zombie(sptr, chptr))
	  sendto_channel_butserv(chptr, sptr, PartFmt2,
	      parv[0], chptr->chname, "Left all channels");
	remove_user_from_channel(sptr, chptr);
      }
      /* Just in case */
      *mbuf = *jbuf = '\0';
      mlen = jlen = 0;
    }
    else
    {				/* not a /join 0, so treat it as
				   a /join #channel -Kev */
      if (!IsChannelName(name))
      {
	if (MyUser(sptr))
	  sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
	continue;
      }

      if (MyConnect(sptr))
      {
	/*
	 * Local client is first to enter previously nonexistant
	 * channel so make them (rightfully) the Channel Operator.
	 * This looks kind of ugly because we try to avoid calling the strlen()
	 */
	if (ChannelExists(name))
	{
	  flags = CHFL_DEOPPED;
	  sendcreate = 0;
	}
	else if (strlen(name) > CHANNELLEN)
	{
	  *(name + CHANNELLEN) = '\0';
	  if (ChannelExists(name))
	  {
	    flags = CHFL_DEOPPED;
	    sendcreate = 0;
	  }
	  else
	  {
	    flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
	    sendcreate = 1;
	  }
	}
	else
	{
	  flags = IsModelessChannel(name) ? CHFL_DEOPPED : CHFL_CHANOP;
	  sendcreate = 1;
	}

	if (sptr->user->joined >= MAXCHANNELSPERUSER)
	{
	  chptr = get_channel(sptr, name, !CREATE);
	  sendto_one(sptr, err_str(ERR_TOOMANYCHANNELS),
	      me.name, parv[0], chptr ? chptr->chname : name);
	  break;		/* Can't return, else he won't get on ANY
				   channels!  Break out of the for loop instead.
				   -Kev */
	}
      }
      chptr = get_channel(sptr, name, CREATE);
      if (chptr && (lp = find_user_link(chptr->members, sptr)))
      {
	if (lp->flags & CHFL_ZOMBIE)
	{
	  zombie = 1;
	  flags = lp->flags & (CHFL_DEOPPED | CHFL_SERVOPOK);
	  remove_user_from_channel(sptr, chptr);
	  chptr = get_channel(sptr, name, CREATE);
	}
	else
	  continue;
      }
      name = chptr->chname;
      if (!chptr->creationtime)	/* A remote JOIN created this channel ? */
	chptr->creationtime = MAGIC_REMOTE_JOIN_TS;
      if (parc > 2)
      {
	if (chptr->creationtime == MAGIC_REMOTE_JOIN_TS)
	  chptr->creationtime = atoi(keysOrTS);
	else
	  parc = 2;		/* Don't pass it on */
      }
      if (!zombie)
      {
	if (!MyConnect(sptr))
	  flags = CHFL_DEOPPED;
	if (sptr->flags & FLAGS_TS8)
	  flags |= CHFL_SERVOPOK;
      }
      if (MyConnect(sptr))
      {
	int created = chptr->users == 0;
	if (check_target_limit(sptr, chptr, chptr->chname, created))
	{
	  if (created)		/* Did we create the channel? */
	    sub1_from_channel(chptr);	/* Remove it again! */
	  continue;
	}
	if ((i = can_join(sptr, chptr, keysOrTS)))
	{
	  sendto_one(sptr, err_str(i), me.name, parv[0], chptr->chname);
	  continue;
	}
      }
      /*
       * Complete user entry to the new channel (if any)
       */
      add_user_to_channel(chptr, sptr, flags);

      /*
       * Notify all other users on the new channel
       */
      sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);

      if (MyUser(sptr))
      {
	del_invite(sptr, chptr);
	if (chptr->topic[0] != '\0')
	{
	  sendto_one(sptr, rpl_str(RPL_TOPIC), me.name,
	      parv[0], name, chptr->topic);
	  sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0], name,
	      chptr->topic_nick, chptr->topic_time);
	}
	parv[1] = name;
	m_names(cptr, sptr, 2, parv);
      }
    }

    /* Select proper buffer; mbuf for creation, jbuf otherwise */

    if (*name == '&')
      continue;			/* Head off local channels at the pass */

    bufptr = (sendcreate == 0) ? jbuf : mbuf;
    buflen = (sendcreate == 0) ? &jlen : &mlen;
    len = strlen(name);
    if (*buflen < BUFSIZE - len - 2)
    {
      if (*bufptr)
      {
	strcat(bufptr, ",");	/* Add to join buf */
	*buflen += 1;
      }
      strncat(bufptr, name, BUFSIZE - *buflen - 1);
      *buflen += len;
    }
    sendcreate = 0;		/* Reset sendcreate */
  }

#ifndef NO_PROTOCOL9
  if (*jbuf || *mbuf)		/* Propagate joins to P09 servers */
    sendto_lowprot_butone(cptr, 9, (*jbuf && *mbuf) ? ":%s JOIN %s,%s" :
	":%s JOIN %s%s", parv[0], jbuf, mbuf);
#endif

  if (*jbuf)			/* Propgate joins to P10 servers */
#ifdef NO_PROTOCOL9
    sendto_serv_butone(cptr,
	parc > 2 ? ":%s JOIN %s %s" : ":%s JOIN %s", parv[0], jbuf, keysOrTS);
#else
    sendto_highprot_butone(cptr, 10,
	parc > 2 ? ":%s JOIN %s %s" : ":%s JOIN %s", parv[0], jbuf, keysOrTS);
#endif
  if (*mbuf)			/* and now creation events */
#ifdef NO_PROTOCOL9
    sendto_serv_butone(cptr, "%s%s CREATE %s " TIME_T_FMT,
	NumNick(sptr), mbuf, TStime());
#else
    sendto_highprot_butone(cptr, 10, "%s%s CREATE %s " TIME_T_FMT,
	NumNick(sptr), mbuf, TStime());
#endif

  if (MyUser(sptr))
  {				/* shouldn't ever set TS for remote JOIN's */
    if (*jbuf)
    {				/* check for channels that need TS's */
      p = NULL;
      for (name = strtoken(&p, jbuf, ","); name; name = strtoken(&p, NULL, ","))
      {
	chptr = get_channel(sptr, name, !CREATE);
	if (chptr && chptr->mode.mode & MODE_SENDTS)
	{			/* send a TS? */
	  sendto_serv_butone(cptr, ":%s MODE %s + " TIME_T_FMT, me.name,
	      chptr->chname, chptr->creationtime);	/* ok, send TS */
	  chptr->mode.mode &= ~MODE_SENDTS;	/* reset flag */
	}
      }
    }

    if (*mbuf)
    {				/* ok, send along modes for creation events to P9 */
      p = NULL;
      for (name = strtoken(&p, mbuf, ","); name; name = strtoken(&p, NULL, ","))
      {
	chptr = get_channel(sptr, name, !CREATE);
	sendto_lowprot_butone(cptr, 9, ":%s MODE %s +o %s " TIME_T_FMT,
	    me.name, chptr->chname, parv[0], chptr->creationtime);
      }
    }
  }
  return 0;
}

/*
 * m_destruct
 *
 * parv[0] = sender prefix
 * parv[1] = channel channelname
 * parv[2] = channel time stamp
 *
 * This function does nothing, it does passes DESTRUCT to the other servers.
 * In the future we will start to use this message.
 *
 */
int m_destruct(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  time_t chanTS;		/* Creation time of the channel */

  if (parc < 3 || *parv[2] == '\0')
    return 0;

#ifdef GODMODE
  /* Allow DESTRUCT from user */
  if (MyUser(sptr))
    sptr = &me;
  else
#endif

    /* sanity checks: Only accept DESTRUCT messages from servers */
  if (!IsServer(sptr))
    return 0;

  /* Don't pass on DESTRUCT messages for channels that exist */
  if (FindChannel(parv[1]))
    return 0;

  chanTS = atoi(parv[2]);

  /* Pass on DESTRUCT message */
  sendto_highprot_butone(cptr, 10, "%s DESTRUCT %s " TIME_T_FMT,
      NumServ(sptr), parv[1], chanTS);

  return 0;
}

/*
 * m_create
 *
 * parv[0] = sender prefix
 * parv[1] = channel names
 * parv[2] = channel time stamp
 */
int m_create(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  char cbuf[BUFSIZE];		/* Buffer for list with channels
				   that `sptr' really creates */
  time_t chanTS;		/* Creation time for all channels
				   in the comma seperated list */
  char *p, *name;
  Reg5 aChannel *chptr;
  int badop;

  /* sanity checks: Only accept CREATE messages from servers */
  if (!IsServer(cptr) || parc < 3 || *parv[2] == '\0')
    return 0;

  chanTS = atoi(parv[2]);

  *cbuf = '\0';			/* Start with empty buffer */

  /* For each channel in the comma seperated list: */
  for (name = strtoken(&p, parv[1], ","); name; name = strtoken(&p, NULL, ","))
  {
    badop = 0;			/* Default is to accept the op */
    if ((chptr = FindChannel(name)))
    {
      name = chptr->chname;
      if (TStime() - chanTS > TS_LAG_TIME)
      {
	/* A bounce would not be accepted anyway - if we get here something
	   is wrong with the TS clock syncing (or we have more then
	   TS_LAG_TIME lag, or an admin is hacking */
	badop = 2;
	/* This causes a HACK notice on all upstream servers: */
	if (Protocol(cptr) < 10)
	  sendto_one(cptr, ":%s MODE %s -o %s 0", me.name, name, sptr->name);
	else
	  sendto_one(cptr, ":%s MODE %s -o %s%s 0",
	      me.name, name, NumNick(sptr));
	/* This causes a WALLOPS on all downstream servers and a notice to our
	   own opers: */
	parv[1] = name;		/* Corrupt parv[1], it is not used anymore anyway */
	send_hack_notice(cptr, sptr, parc, parv, badop, 2);
      }
      else if (chptr->creationtime && chanTS > chptr->creationtime &&
	  chptr->creationtime != MAGIC_REMOTE_JOIN_TS)
      {
	/* We (try) to bounce the mode, because the CREATE is used on an older
	   channel, probably a net.ride */
	badop = 1;
	/* Send a deop upstream: */
	if (Protocol(cptr) < 10)
	  sendto_one(cptr, ":%s MODE %s -o %s " TIME_T_FMT, me.name,
	      name, sptr->name, chptr->creationtime);
	else
	  sendto_one(cptr, ":%s MODE %s -o %s%s " TIME_T_FMT, me.name,
	      name, NumNick(sptr), chptr->creationtime);
      }
    }
    else			/* Channel doesn't exist: create it */
      chptr = get_channel(sptr, name, CREATE);

    /* Add and mark ops */
    add_user_to_channel(chptr, sptr,
	(badop || IsModelessChannel(name)) ? CHFL_DEOPPED : CHFL_CHANOP);

    /* Send user join to the local clients (if any) */
    sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);

    if (badop)			/* handle badop: convert CREATE into JOIN */
      sendto_serv_butone(cptr, ":%s JOIN %s " TIME_T_FMT,
	  sptr->name, name, chptr->creationtime);
    else
    {
      /* Send the op to local clients:
         (if any; extremely unlikely, but it CAN happen) */
      if (!IsModelessChannel(name))
	sendto_channel_butserv(chptr, sptr, ":%s MODE %s +o %s",
	    sptr->user->server->name, name, parv[0]);

      /* Set/correct TS and add the channel to the
         buffer for accepted channels: */
      chptr->creationtime = chanTS;
      if (*cbuf)
	strcat(cbuf, ",");
      strcat(cbuf, name);
    }
  }

  if (*cbuf)			/* Any channel accepted with ops ? */
  {
#ifdef NO_PROTOCOL9
    sendto_serv_butone(cptr, "%s%s CREATE %s " TIME_T_FMT,
	NumNick(sptr), cbuf, chanTS);
#else
    /* send CREATEs to 2.10 servers */
    sendto_highprot_butone(cptr, 10, "%s%s CREATE %s " TIME_T_FMT,
	NumNick(sptr), cbuf, chanTS);

    /* And JOIN + MODE to 2.9 servers; following
       is not needed after all are 2.10 */
    sendto_lowprot_butone(cptr, 9, ":%s JOIN %s", parv[0], cbuf);
    p = NULL;
    for (name = strtoken(&p, cbuf, ","); name; name = strtoken(&p, NULL, ","))
      sendto_lowprot_butone(cptr, 9, ":%s MODE %s +o %s " TIME_T_FMT,
	  sptr->user->server->name, name, parv[0], chanTS);
#endif
  }

  return 0;
}

static size_t prefix_len;

static void add_token_to_sendbuf(char *token, size_t *sblenp, int *firstp,
    int *send_itp, char is_a_ban, int mode)
{
  int first = *firstp;

  /*
   * Heh - we do not need to test if it still fits in the buffer, because
   * this BURST message is reconstructed from another BURST message, and
   * it only can become smaller. --Run
   */

  if (*firstp)			/* First token in this parameter ? */
  {
    *firstp = 0;
    if (*send_itp == 0)
      *send_itp = 1;		/* Buffer contains data to be sent */
    sendbuf[(*sblenp)++] = ' ';
    if (is_a_ban)
    {
      sendbuf[(*sblenp)++] = ':';	/* Bans are always the last "parv" */
      sendbuf[(*sblenp)++] = is_a_ban;
    }
  }
  else				/* Of course, 'send_it' is already set here */
    /* Seperate banmasks with a space because
       they can contain commas themselfs: */
    sendbuf[(*sblenp)++] = is_a_ban ? ' ' : ',';
  strcpy(sendbuf + *sblenp, token);
  *sblenp += strlen(token);
  if (!is_a_ban)		/* nick list ? Need to take care
				   of modes for nicks: */
  {
    static int last_mode = 0;
    mode &= CHFL_CHANOP | CHFL_VOICE;
    if (first)
      last_mode = 0;
    if (last_mode != mode)	/* Append mode like ':ov' if changed */
    {
      last_mode = mode;
      sendbuf[(*sblenp)++] = ':';
      if (mode & CHFL_CHANOP)
	sendbuf[(*sblenp)++] = 'o';
      if (mode & CHFL_VOICE)
	sendbuf[(*sblenp)++] = 'v';
    }
    sendbuf[*sblenp] = '\0';
  }
}

static void cancel_mode(aClient *sptr, aChannel *chptr, char m,
    const char *param, int *count)
{
  static char *pb, *sbp, *sbpi;
  int paramdoesntfit = 0;
  if (*count == -1)		/* initialize ? */
  {
    sbp = sbpi =
	sprintf_irc(sendbuf, ":%s MODE %s -", sptr->name, chptr->chname);
    pb = parabuf;
    *count = 0;
  }
  /* m == 0 means flush */
  if (m)
  {
    if (param)
    {
      size_t nplen = strlen(param);
      if (pb - parabuf + nplen + 23 > MODEBUFLEN)
	paramdoesntfit = 1;
      else
      {
	*sbp++ = m;
	*pb++ = ' ';
	strcpy(pb, param);
	pb += nplen;
	++*count;
      }
    }
    else
      *sbp++ = m;
  }
  else if (*count == 0)
    return;
  if (*count == 6 || !m || paramdoesntfit)
  {
#ifndef NO_PROTOCOL9
    Dlink *lp;
    char *sbe;
#endif
    Link *member;
    strcpy(sbp, parabuf);
#ifndef NO_PROTOCOL9
    sbe = sbp + strlen(parabuf);
#endif
    for (member = chptr->members; member; member = member->next)
      if (MyUser(member->value.cptr))
	sendbufto_one(member->value.cptr);
#ifndef NO_PROTOCOL9
    sprintf_irc(sbe, " " TIME_T_FMT, chptr->creationtime);
    /* Send 'sendbuf' to all 2.9 downlinks: */
    for (lp = me.serv->down; lp; lp = lp->next)
      if (Protocol(lp->value.cptr) < 10)
	sendbufto_one(lp->value.cptr);
#endif
    sbp = sbpi;
    pb = parabuf;
    *count = 0;
  }
  if (paramdoesntfit)
  {
    *sbp++ = m;
    *pb++ = ' ';
    strcpy(pb, param);
    pb += strlen(param);
    ++*count;
  }
}

/*
 * m_burst  --  by Run carlo@runaway.xs4all.nl  december 1995 till march 1997
 *
 * parv[0] = sender prefix
 * parv[1] = channel name
 * parv[2] = channel timestamp
 * The meaning of the following parv[]'s depend on their first character:
 * If parv[n] starts with a '+':
 * Net burst, additive modes
 *   parv[n] = <mode>
 *   parv[n+1] = <param> (optional)
 *   parv[n+2] = <param> (optional)
 * If parv[n] starts with a '%', then n will be parc-1:
 *   parv[n] = %<ban> <ban> <ban> ...
 * If parv[n] starts with another character:
 *   parv[n] = <nick>[:<mode>],<nick>[:<mode>],...
 *   where <mode> is the channel mode (ov) of nick and all following nicks.
 *
 * Example:
 * "S BURST #channel 87654321 +ntkl key 123 AAA,AAB:o,BAA,BAB:ov :%ban1 ban2"
 *
 * Anti net.ride code.
 *
 * When the channel already exist, and its TS is larger then
 * the TS in the BURST message, then we cancel all existing modes.
 * If its is smaller then the received BURST message is ignored.
 * If it's equal, then the received modes are just added.
 */
int m_burst(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 aChannel *chptr;
  time_t timestamp;
  int netride = 0, wipeout = 0, n;
  int send_it = 0, add_banid_not_called = 1;
  Mode *current_mode;
  size_t sblen, mblen = 0;
  int mblen2, pblen2, cnt;
  int prev_mode;
  char prev_key[KEYLEN + 1];
  Link *lp;
#ifndef NO_PROTOCOL9
  int ts_sent = 0;
#endif

  /* BURST is only for servers and has at least 4 parameters */
  if (!IsServer(cptr) || parc < 4)
    return 0;

  if (!IsBurst(sptr))
  {
    int i;
    char *p;
    if (find_conf_host(cptr->confs, sptr->name, CONF_UWORLD))
    {
      p =
	  sprintf_irc(sendbuf,
	  ":%s NOTICE * :*** Notice -- HACK(4): %s BURST %s %s", me.name,
	  sptr->name, parv[1], parv[2]);
      for (i = 3; i < parc - 1; ++i)
	p = sprintf_irc(p, " %s", parv[i]);
      sprintf_irc(p, " :%s", parv[parc - 1]);
      sendbufto_op_mask(SNO_HACK4);
    }
    else
    {
#if 1				/* FIXME: This should be removed after all HUBs upgraded to ircu2.10.05 */
      SetBurst(sptr);
      if (MyConnect(sptr))
#endif
	return exit_client_msg(cptr, cptr, &me,
	    "HACK: BURST message outside net.burst from %s", sptr->name);
    }
  }

  /* Find the channel, or create it - note that the creation time
   * will be 0 if it has to be created */
  chptr = get_channel(sptr, parv[1], CREATE);
  current_mode = &chptr->mode;
  prev_mode = chptr->mode.mode;
  if (*chptr->mode.key)
  {
    prev_mode |= MODE_KEY;
    strcpy(prev_key, chptr->mode.key);
  }
  if (chptr->mode.limit)
    prev_mode |= MODE_LIMIT;

  timestamp = atoi(parv[2]);

  /* Copy the new TS when the received creationtime appears to be older */
  if (!chptr->creationtime || chptr->creationtime > timestamp)
  {
    /* Set the new timestamp */
    chptr->creationtime = timestamp;
    send_it = 1;		/* Make sure we pass on the different timestamp ! */
    /* Mark all bans as needed to be wiped out */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= CHFL_BURST_BAN_WIPEOUT;
    /*
     * Only the first BURST for this channel can have creationtime > timestamp,
     * so at this moment ALL members are on OUR side, and thus all net.riders:
     */
    wipeout = 1;
  }
  for (lp = chptr->members; lp; lp = lp->next)
    lp->flags &= ~CHFL_BURST_JOINED;	/* Set later for nicks in the BURST msg */
  /* If `wipeout' is set then these will be deopped later. */

  /* If the entering creationtime is younger, ignore the modes */
  if (chptr->creationtime < timestamp)
    netride = 1;		/* Only pass on the nicks (so they JOIN) */

  /* Prepare buffers to pass the message */
  *bparambuf = *bmodebuf = *parabuf = '\0';
  pblen2 = 0;
  *modebuf = '+';
  mblen2 = 1;
  cnt = 0;
  prefix_len = sblen = sprintf_irc(sendbuf, "%s BURST %s " TIME_T_FMT,
      NumServ(sptr), chptr->chname, chptr->creationtime) - sendbuf;

  /* Run over all remaining parameters */
  for (n = 3; n < parc; n++)
    switch (*parv[n])		/* What type is it ? mode, nicks or bans ? */
    {
      case '+':		/* modes */
      {
	char *p = parv[n];
	while (*(++p))		/* Run over all mode characters */
	{
	  switch (*p)		/* which mode ? */
	  {
	      /*
	       * The following cases all do the following:
	       * - In case wipeout needed, reset 'prev_mode' to indicate this
	       *   mode should not be cancelled.
	       * - If wipeout or (not netride and the new mode is a change),
	       *   add it to bmodebuf and bparabuf for propagation.
	       * - Else ignore it.
	       * - Add it to modebuf and parabuf for propagation to the
	       *   clients when not netride and the new mode is a change.
	       * Special cases:
	       * - If a +s is received, cancel a +p and sent a -p to the
	       *   clients too (if +p was set).
	       * - If a +p is received and +s is set, ignore the +p.
	       */
	    case 'i':
	    {
	      register int tmp;
	      prev_mode &= ~MODE_INVITEONLY;
	      if (!(tmp = netride ||
		  (current_mode->mode & MODE_INVITEONLY)) || wipeout)
	      {
		bmodebuf[mblen++] = 'i';
		current_mode->mode |= MODE_INVITEONLY;
	      }
	      if (!tmp)
		modebuf[mblen2++] = 'i';
	      break;
	    }
	    case 'k':
	    {
	      register int tmp;
	      char *param = parv[++n];
	      prev_mode &= ~MODE_KEY;
	      if (!(tmp = netride || (*current_mode->key &&
		  (!strcmp(current_mode->key, param) ||
		  (!wipeout && strcmp(current_mode->key, param) < 0)))) ||
		  wipeout)
	      {
		bmodebuf[mblen++] = 'k';
		strcat(bparambuf, " ");
		strcat(bparambuf, param);
		strncpy(current_mode->key, param, KEYLEN);
	      }
	      if (!tmp && !wipeout)
	      {
		modebuf[mblen2++] = 'k';
		parabuf[pblen2++] = ' ';
		strcpy(parabuf + pblen2, param);
		pblen2 += strlen(param);
		cnt++;
	      }
	      break;
	    }
	    case 'l':
	    {
	      register int tmp;
	      unsigned int param = atoi(parv[++n]);
	      prev_mode &= ~MODE_LIMIT;
	      if (!(tmp = netride || (current_mode->limit &&
		  (current_mode->limit == param ||
		  (!wipeout && current_mode->limit < param)))) || wipeout)
	      {
		bmodebuf[mblen++] = 'l';
		sprintf_irc(bparambuf + strlen(bparambuf), " %d", param);
		current_mode->limit = param;
	      }
	      if (!tmp)
	      {
		modebuf[mblen2++] = 'l';
		pblen2 = sprintf_irc(parabuf + pblen2, " %d", param) - parabuf;
		cnt++;
	      }
	      break;
	    }
	    case 'm':
	    {
	      register int tmp;
	      prev_mode &= ~MODE_MODERATED;
	      if (!(tmp = netride ||
		  (current_mode->mode & MODE_MODERATED)) || wipeout)
	      {
		bmodebuf[mblen++] = 'm';
		current_mode->mode |= MODE_MODERATED;
	      }
	      if (!tmp)
		modebuf[mblen2++] = 'm';
	      break;
	    }
	    case 'n':
	    {
	      register int tmp;
	      prev_mode &= ~MODE_NOPRIVMSGS;
	      if (!(tmp = netride ||
		  (current_mode->mode & MODE_NOPRIVMSGS)) || wipeout)
	      {
		bmodebuf[mblen++] = 'n';
		current_mode->mode |= MODE_NOPRIVMSGS;
	      }
	      if (!tmp)
		modebuf[mblen2++] = 'n';
	      break;
	    }
	    case 'p':
	    {
	      register int tmp;

	      /* Special case: */
	      if (!netride && !wipeout && (current_mode->mode & MODE_SECRET))
		break;

	      prev_mode &= ~MODE_PRIVATE;
	      if (!(tmp = netride ||
		  (current_mode->mode & MODE_PRIVATE)) || wipeout)
	      {
		bmodebuf[mblen++] = 'p';
		current_mode->mode |= MODE_PRIVATE;
	      }
	      if (!tmp)
		modebuf[mblen2++] = 'p';
	      break;
	    }
	    case 's':
	    {
	      register int tmp;
	      prev_mode &= ~MODE_SECRET;
	      if (!(tmp = netride ||
		  (current_mode->mode & MODE_SECRET)) || wipeout)
	      {
		bmodebuf[mblen++] = 's';
		current_mode->mode |= MODE_SECRET;
	      }
	      if (!tmp)
		modebuf[mblen2++] = 's';

	      /* Special case: */
	      if (!netride && !wipeout && (current_mode->mode & MODE_PRIVATE))
	      {
		int i;
		for (i = mblen2 - 1; i >= 0; --i)
		  modebuf[i + 2] = modebuf[i];
		modebuf[0] = '-';
		modebuf[1] = 'p';
		mblen2 += 2;
		current_mode->mode &= ~MODE_PRIVATE;
	      }

	      break;
	    }
	    case 't':
	    {
	      register int tmp;
	      prev_mode &= ~MODE_TOPICLIMIT;
	      if (!(tmp = netride ||
		  (current_mode->mode & MODE_TOPICLIMIT)) || wipeout)
	      {
		bmodebuf[mblen++] = 't';
		current_mode->mode |= MODE_TOPICLIMIT;
	      }
	      if (!tmp)
		modebuf[mblen2++] = 't';
	      break;
	    }
	  }
	}			/* <-- while over all modes */

	bmodebuf[mblen] = '\0';
	sendbuf[sblen] = '\0';
	if (mblen)		/* Anything to send at all ? */
	{
	  send_it = 1;
	  strcpy(sendbuf + sblen, " +");
	  sblen += 2;
	  strcpy(sendbuf + sblen, bmodebuf);
	  sblen += mblen;
	  strcpy(sendbuf + sblen, bparambuf);
	  sblen += strlen(bparambuf);
	}
	break;			/* Done mode part */
      }
      case '%':		/* bans */
      {
	char *pv, *p = NULL, *ban;
	int first = 1;
	if (netride)
	  break;		/* Ignore bans */
	/* Run over all bans */
	for (pv = parv[n] + 1; (ban = strtoken(&p, pv, " ")); pv = NULL)
	{
	  int ret;
	  /*
	   * The following part should do the following:
	   * - If the new (un)ban is not a _change_ it is ignored.
	   * - Else, add it to sendbuf for later use.
	   * - If sendbuf is full, send it, and prepare a new
	   *   message in sendbuf.
	   */
	  ret = add_banid(sptr, chptr, ban, 1, add_banid_not_called);
	  if (ret == 0)
	  {
	    add_banid_not_called = 0;
	    /* Mark this new ban so we can send it to the clients later */
	    chptr->banlist->flags |= CHFL_BURST_BAN;
	  }
	  if (ret != -1)
	    /* A new ban was added or an existing one needs to be passed on.
	     * Also add it to sendbuf: */
	    add_token_to_sendbuf(ban, &sblen, &first, &send_it, '%', 0);
	}
	break;			/* Done bans part */
      }
      default:			/* nicks */
      {
	char *pv, *p = NULL, *nick, *ptr;
	int first = 1;
	/* Default mode: */
	int default_mode = CHFL_DEOPPED;
	/* Run over all nicks */
	for (pv = parv[n]; (nick = strtoken(&p, pv, ",")); pv = NULL)
	{
	  aClient *acptr;
	  if ((ptr = strchr(nick, ':')))	/* New default mode ? */
	  {
	    *ptr = '\0';	/* Fix 'nick' */
	    acptr = findNUser(nick);
	    if (!netride)
	    {
	      /* Calculate new mode change: */
	      default_mode = CHFL_DEOPPED;
	      while (*(++ptr))
		if (*ptr == 'o')
		{
		  default_mode |= CHFL_CHANOP;
		  default_mode &= ~CHFL_DEOPPED;
		}
		else if (*ptr == 'v')
		  default_mode |= CHFL_VOICE;
		else
		  break;
	    }
	  }
	  else
	    acptr = findNUser(nick);
	  /*
	   * Note that at this point we already received a 'NICK' for any
	   * <nick> numeric that is joining (and possibly opped) here.
	   * Therefore we consider the following situations:
	   * - The <nick> numeric exists and is from the direction of cptr: ok
	   * - The <nick> numeric does not exist:
	   *   Apparently this previous <nick> numeric was killed (upstream)
	   *   or it collided with an existing <nick> name.
	   * - The <nick> numeric exists but is from another direction:
	   *   Apparently this previous <nick> numeric was killed,
	   *   and due to a reroute it signed on via another link (probably
	   *   a nick [numeric] collision).
	   * Note that it can't be a QUIT or SQUIT, because a QUIT would
	   * come from the same direction as the BURST (cptr) while an
	   * upstream SQUIT removes the source (server) and we would thus
	   * have this BURST ignored already.
	   * This means that if we find the nick and it is from the correct
	   * direction, it joins. If it doesn't exist or is from another
	   * direction, we have to ignore it. If all nicks are ignored, we
	   * remove the channel again when it is empty and don't propagate
	   * the BURST message.
	   */
	  if (acptr && acptr->from == cptr)
	  {
	    /*
	     * The following should do the following:
	     * - Add it to sendbuf for later use.
	     * - If sendbuf is full, send it, and prepare a new
	     *   message in sendbuf.
	     */
	    add_token_to_sendbuf(nick, &sblen, &first, &send_it, 0,
		default_mode);
	    /* Let is take effect: (Note that in the case of a netride
	     * 'default_mode' is always CHFL_DEOPPED here). */
	    add_user_to_channel(chptr, acptr, default_mode);
	    chptr->members->flags |= CHFL_BURST_JOINED;
	  }
	}			/* <-- Next nick */
	if (!chptr->members)	/* All nicks collided and channel is empty ? */
	{
	  sub1_from_channel(chptr);
	  return 0;		/* Forget about the (rest of the) message... */
	}
	break;			/* Done nicks part */
      }
    }				/* <-- Next parameter if any */
  if (!chptr->members)		/* This message only contained bans (then the previous
				   message only contained collided nicks, see above) */
  {
    sub1_from_channel(chptr);
    if (!add_banid_not_called)
      while (next_removed_overlapped_ban());
    return 0;			/* Forget about the (rest of the) message... */
  }

  /* The last (possibly only) message is always send here */
  if (send_it)			/* Anything (left) to send ? */
  {
    Dlink *lp;
    Link *member;

    /* send 'sendbuf' to all downlinks */
    for (lp = me.serv->down; lp; lp = lp->next)
    {
      if (lp->value.cptr == cptr)
	continue;
      if (Protocol(lp->value.cptr) > 9)
	sendbufto_one(lp->value.cptr);
    }

    /*
     * Now we finally can screw sendbuf again...
     * Send all changes to the local clients:
     *
     * First send all joins and op them, because 2.9 servers
     * would protest with a HACK if we first de-opped people.
     * However, we don't send the +b bans yes, because we
     * DO first want to -b the old bans (otherwise it's confusing).
     */

    /* Send all joins: */
    for (member = chptr->members; member; member = member->next)
      if (member->flags & CHFL_BURST_JOINED)
      {
	sendto_channel_butserv(chptr, member->value.cptr, ":%s JOIN :%s",
	    member->value.cptr->name, chptr->chname);
#ifndef NO_PROTOCOL9
	/* And to 2.9 servers: */
	sendto_lowprot_butone(cptr, 9, ":%s JOIN %s",
	    member->value.cptr->name, chptr->chname);
#endif
      }

    if (!netride)
    {
      /* Send all +o and +v modes: */
      for (member = chptr->members; member; member = member->next)
      {
	if ((member->flags & CHFL_BURST_JOINED))
	{
	  int mode = CHFL_CHANOP;
	  for (;;)
	  {
	    if ((member->flags & mode))
	    {
	      modebuf[mblen2++] = (mode == CHFL_CHANOP) ? 'o' : 'v';
	      parabuf[pblen2++] = ' ';
	      strcpy(parabuf + pblen2, member->value.cptr->name);
	      pblen2 += strlen(member->value.cptr->name);
	      if (6 == ++cnt)
	      {
		modebuf[mblen2] = 0;
		sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s",
		    parv[0], chptr->chname, modebuf, parabuf);
#ifndef NO_PROTOCOL9
		sendto_lowprot_butone(cptr, 9, ":%s MODE %s %s%s " TIME_T_FMT,
		    parv[0], chptr->chname, modebuf, parabuf,
		    chptr->creationtime);
		ts_sent = 1;
#endif
		*parabuf = 0;
		pblen2 = 0;
		mblen2 = 1;
		cnt = 0;
	      }
	    }
	    if (mode == CHFL_CHANOP)
	      mode = CHFL_VOICE;
	    else
	      break;
	  }
	}
      }
      /* Flush MODEs: */
      if (cnt > 0 || mblen2 > 1)
      {
	modebuf[mblen2] = 0;
	sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s",
	    parv[0], chptr->chname, modebuf, parabuf);
#ifndef NO_PROTOCOL9
	sendto_lowprot_butone(cptr, 9, ":%s MODE %s %s%s " TIME_T_FMT,
	    parv[0], chptr->chname, modebuf, parabuf, chptr->creationtime);
	ts_sent = 1;
#endif
      }
#ifndef NO_PROTOCOL9
      else if (send_it && !ts_sent)
      {
	sendto_lowprot_butone(cptr, 9, ":%s MODE %s + " TIME_T_FMT,
	    parv[0], chptr->chname, chptr->creationtime);
	ts_sent = 1;
      }
#endif
    }
  }

  if (wipeout)
  {
    Link *lp;
    Link **ban;
    int mode;
    char m;
    int count = -1;

    /* Now cancel all previous simple modes */
    if ((prev_mode & MODE_SECRET))
      cancel_mode(sptr, chptr, 's', NULL, &count);
    if ((prev_mode & MODE_PRIVATE))
      cancel_mode(sptr, chptr, 'p', NULL, &count);
    if ((prev_mode & MODE_MODERATED))
      cancel_mode(sptr, chptr, 'm', NULL, &count);
    if ((prev_mode & MODE_TOPICLIMIT))
      cancel_mode(sptr, chptr, 't', NULL, &count);
    if ((prev_mode & MODE_INVITEONLY))
      cancel_mode(sptr, chptr, 'i', NULL, &count);
    if ((prev_mode & MODE_NOPRIVMSGS))
      cancel_mode(sptr, chptr, 'n', NULL, &count);
    if ((prev_mode & MODE_LIMIT))
    {
      current_mode->limit = 0;
      cancel_mode(sptr, chptr, 'l', NULL, &count);
    }
    if ((prev_mode & MODE_KEY))
    {
      *current_mode->key = 0;
      cancel_mode(sptr, chptr, 'k', prev_key, &count);
    }
    current_mode->mode &= ~prev_mode;

    /* And deop and devoice all net.riders on my side */
    mode = CHFL_CHANOP;
    m = 'o';
    for (;;)
    {
      for (lp = chptr->members; lp; lp = lp->next)
      {
	if ((lp->flags & CHFL_BURST_JOINED))
	  continue;		/* This is not a net.rider from
				   this side of the net.junction */
	if ((lp->flags & mode))
	{
	  lp->flags &= ~mode;
	  if (mode == CHFL_CHANOP)
	    lp->flags |= CHFL_DEOPPED;
	  cancel_mode(sptr, chptr, m, lp->value.cptr->name, &count);
	}
      }
      if (mode == CHFL_VOICE)
	break;
      mode = CHFL_VOICE;
      m = 'v';
    }

    /* And finally wipeout all bans that are left */
    for (ban = &chptr->banlist; *ban;)
    {
      Link *tmp = *ban;
      if ((tmp->flags & CHFL_BURST_BAN_WIPEOUT))
      {
	cancel_mode(sptr, chptr, 'b', tmp->value.ban.banstr, &count);
	/* Copied from del_banid(): */
	*ban = tmp->next;
	RunFree(tmp->value.ban.banstr);
	RunFree(tmp->value.ban.who);
	free_link(tmp);
	/* Erase ban-valid-bit, for channel members that are banned */
	for (tmp = chptr->members; tmp; tmp = tmp->next)
	  if ((tmp->flags & (CHFL_BANNED | CHFL_BANVALID)) ==
	      (CHFL_BANNED | CHFL_BANVALID))
	    tmp->flags &= ~CHFL_BANVALID;	/* `tmp' == channel member */
      }
      else
	ban = &tmp->next;
    }
    /* Also wipeout overlapped bans */
    if (!add_banid_not_called)
    {
      Link *ban;
      while ((ban = next_removed_overlapped_ban()))
	cancel_mode(sptr, chptr, 'b', ban->value.ban.banstr, &count);
    }
    cancel_mode(sptr, chptr, 0, NULL, &count);	/* flush */
  }

  if (send_it && !netride)
  {
    Link *bl;
    int deban;

    if (add_banid_not_called || !(bl = next_removed_overlapped_ban()))
    {
      deban = 0;
      bl = chptr->banlist;
      *modebuf = '+';
    }
    else
    {
      deban = 1;
      *modebuf = '-';
    }

    mblen2 = 1;
    pblen2 = 0;
    cnt = 0;
    for (;;)
    {
      size_t nblen = 0;
      if (bl)
	nblen = strlen(bl->value.ban.banstr);
      if (cnt == 6 || (!bl && cnt) || pblen2 + nblen + 12 > MODEBUFLEN)	/* The last check is to make sure
									   that the receiving 2.9 will
									   still process this */
      {
	/* Time to send buffer */
	modebuf[mblen2] = 0;
	sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s",
	    parv[0], chptr->chname, modebuf, parabuf);
#ifndef NO_PROTOCOL9
	sendto_lowprot_butone(cptr, 9, ":%s MODE %s %s%s",
	    parv[0], chptr->chname, modebuf, parabuf);
#endif
	*modebuf = deban ? '-' : '+';
	mblen2 = 1;
	pblen2 = 0;
	cnt = 0;
      }
      if (!bl)			/* Done ? */
	break;
      if (deban || (bl->flags & CHFL_BURST_BAN))
      {
	/* Add ban to buffers and remove it */
	modebuf[mblen2++] = 'b';
	parabuf[pblen2++] = ' ';
	strcpy(parabuf + pblen2, bl->value.ban.banstr);
	pblen2 += nblen;
	cnt++;
	bl->flags &= ~CHFL_BURST_BAN;
      }
      if (deban)
      {
	if (!(bl = next_removed_overlapped_ban()))
	{
	  deban = 0;
	  modebuf[mblen2++] = '+';
	  bl = chptr->banlist;
	}
      }
      else
	bl = bl->next;
    }
    /* Flush MODE [-b]+b ...: */
    if (cnt > 0 || mblen2 > 1)
    {
      modebuf[mblen2] = 0;
      sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s%s",
	  parv[0], chptr->chname, modebuf, parabuf);
#ifndef NO_PROTOCOL9
      sendto_lowprot_butone(cptr, 9, ":%s MODE %s %s%s " TIME_T_FMT,
	  parv[0], chptr->chname, modebuf, parabuf, chptr->creationtime);
#endif
    }
#ifndef NO_PROTOCOL9
    else if (send_it && !ts_sent)
      sendto_lowprot_butone(cptr, 9, ":%s MODE %s + " TIME_T_FMT,
	  parv[0], chptr->chname, chptr->creationtime);
#endif
  }

  return 0;
}

/*
 * m_part
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[parc - 1] = comment
 */
int m_part(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 aChannel *chptr;
  Reg2 Link *lp;
  char *p = NULL, *name, pbuf[BUFSIZE];
  char *comment = (parc > 2 && !BadPtr(parv[parc - 1])) ? parv[parc - 1] : NULL;

  *pbuf = '\0';			/* Initialize the part buffer... -Kev */

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 2 || parv[1][0] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "PART");
    return 0;
  }

  for (; (name = strtoken(&p, parv[1], ",")); parv[1] = NULL)
  {
    chptr = get_channel(sptr, name, !CREATE);
    if (!chptr)
    {
      sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
      continue;
    }
    if (*name == '&' && !MyUser(sptr))
      continue;
    /* Do not use IsMember here: zombies must be able to part too */
    if (!(lp = find_user_link(chptr->members, sptr)))
    {
      /* Normal to get when our client did a kick
         for a remote client (who sends back a PART),
         so check for remote client or not --Run */
      if (MyUser(sptr))
	sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
	    chptr->chname);
      continue;
    }
    /* Recreate the /part list for sending to servers */
    if (*name != '&')
    {
      if (*pbuf)
	strcat(pbuf, ",");
      strcat(pbuf, name);
    }
    if (can_send(sptr, chptr) != 0)	/* Returns 0 if we CAN send */
      comment = NULL;
    /* Send part to all clients */
    if (!(lp->flags & CHFL_ZOMBIE))
    {
      if (comment)
	sendto_channel_butserv(chptr, sptr, PartFmt2, parv[0], chptr->chname,
	    comment);
      else
	sendto_channel_butserv(chptr, sptr, PartFmt1, parv[0], chptr->chname);
    }
    else if (MyUser(sptr))
    {
      if (comment)
	sendto_one(sptr, PartFmt2, parv[0], chptr->chname, comment);
      else
	sendto_one(sptr, PartFmt1, parv[0], chptr->chname);
    }
    remove_user_from_channel(sptr, chptr);
  }
  /* Send out the parts to all servers... -Kev */
  if (*pbuf)
  {
    if (comment)
      sendto_serv_butone(cptr, PartFmt2, parv[0], pbuf, comment);
    else
      sendto_serv_butone(cptr, PartFmt1, parv[0], pbuf);
  }
  return 0;
}

/*
 * m_kick
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[parc-1] = kick comment
 */
int m_kick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  aClient *who;
  aChannel *chptr;
  char *comment;
  Link *lp, *lp2;

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 3 || *parv[1] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "KICK");
    return 0;
  }

  if (IsServer(sptr))
    send_hack_notice(cptr, sptr, parc, parv, 1, 3);

  comment = (BadPtr(parv[parc - 1])) ? parv[0] : parv[parc - 1];
  if (strlen(comment) > (size_t)TOPICLEN)
    comment[TOPICLEN] = '\0';

  *nickbuf = *buf = '\0';

  chptr = get_channel(sptr, parv[1], !CREATE);
  if (!chptr)
  {
    sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], parv[1]);
    return 0;
  }
  if (IsLocalChannel(parv[1]) && !MyUser(sptr))
    return 0;
  if (IsModelessChannel(parv[1]))
  {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
	chptr->chname);
    return 0;
  }
  if (!IsServer(cptr) && !is_chan_op(sptr, chptr))
  {
    sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
	me.name, parv[0], chptr->chname);
    return 0;
  }

  lp2 = find_user_link(chptr->members, sptr);
  if (MyUser(sptr) || Protocol(cptr) < 10)
  {
    if (!(who = find_chasing(sptr, parv[2], NULL)))
      return 0;			/* No such user left! */
  }
  else if (!(who = findNUser(parv[2])))
    return 0;			/* No such user left! */
  /* if the user is +k, prevent a kick from local user */
  if (IsChannelService(who) && MyUser(sptr))
  {
    sendto_one(sptr, err_str(ERR_ISCHANSERVICE), me.name,
	parv[0], who->name, chptr->chname);
    return 0;
  }
  if (((lp = find_user_link(chptr->members, who)) &&
      !(lp->flags & CHFL_ZOMBIE)) || IsServer(sptr))
  {
    if (who->from != cptr &&
	((lp2 && (lp2->flags & CHFL_DEOPPED)) || (!lp2 && IsUser(sptr))))
    {
      /*
       * Bounce here:
       * cptr must be a server (or cptr == sptr and
       * sptr->flags can't have DEOPPED set
       * when CHANOP is set).
       */
      sendto_one(cptr, ":%s JOIN %s", who->name, parv[1]);
      if (lp->flags & CHFL_CHANOP)
      {
	if (Protocol(cptr) < 10)
	  sendto_one(cptr, ":%s MODE %s +o %s " TIME_T_FMT,
	      me.name, parv[1], who->name, chptr->creationtime);
	else
	  sendto_one(cptr, "%s MODE %s +o %s%s " TIME_T_FMT,
	      NumServ(&me), parv[1], NumNick(who), chptr->creationtime);
      }
      if (lp->flags & CHFL_VOICE)
      {
	if (Protocol(cptr) < 10)
	  sendto_one(cptr, ":%s MODE %s +v %s " TIME_T_FMT,
	      me.name, chptr->chname, who->name, chptr->creationtime);
	else
	  sendto_one(cptr, "%s MODE %s +v %s%s " TIME_T_FMT,
	      NumServ(&me), parv[1], NumNick(who), chptr->creationtime);
      }
    }
    else
    {
      if (lp)
	sendto_channel_butserv(chptr, sptr,
	    ":%s KICK %s %s :%s", parv[0], chptr->chname, who->name, comment);
      if (!IsLocalChannel(parv[1]))
      {
	sendto_lowprot_butone(cptr, 9, ":%s KICK %s %s :%s",
	    parv[0], chptr->chname, who->name, comment);
	sendto_highprot_butone(cptr, 10, ":%s KICK %s %s%s :%s",
	    parv[0], parv[1], NumNick(who), comment);
      }
      if (lp)
      {
/*
 * Consider:
 *
 *                     client
 *                       |
 *                       c
 *                       |
 *     X --a--> A --b--> B --d--> D
 *                       |
 *                      who
 *
 * Where `who' is being KICK-ed by a "KICK" message received by server 'A'
 * via 'a', or on server 'B' via either 'b' or 'c', or on server D via 'd'.
 *
 * a) On server A : set CHFL_ZOMBIE for `who' (lp) and pass on the KICK.
 *    Remove the user immedeately when no users are left on the channel.
 * b) On server B : remove the user (who/lp) from the channel, send a
 *    PART upstream (to A) and pass on the KICK.
 * c) KICKed by `client'; On server B : remove the user (who/lp) from the
 *    channel, and pass on the KICK.
 * d) On server D : remove the user (who/lp) from the channel, and pass on
 *    the KICK.
 *
 * Note:
 * - Setting the ZOMBIE flag never hurts, we either remove the
 *   client after that or we don't.
 * - The KICK message was already passed on, as should be in all cases.
 * - `who' is removed in all cases except case a) when users are left.
 * - A PART is only sent upstream in case b).
 *
 * 2 aug 97:
 *
 *              6
 *              |
 *  1 --- 2 --- 3 --- 4 --- 5
 *        |           |
 *      kicker       who
 *
 * We also need to turn 'who' into a zombie on servers 1 and 6,
 * because a KICK from 'who' (kicking someone else in that direction)
 * can arrive there afterwards - which should not be bounced itself.
 * Therefore case a) also applies for servers 1 and 6.
 *
 * --Run
 */
	/* Default for case a): */
	lp->flags |= CHFL_ZOMBIE;
	/* Case b) or c) ?: */
	if (MyUser(who))	/* server 4 */
	{
	  if (IsServer(cptr))	/* Case b) ? */
	    sendto_one(cptr, PartFmt1, who->name, parv[1]);
	  remove_user_from_channel(who, chptr);
	  return 0;
	}
	if (who->from == cptr)	/* True on servers 1, 5 and 6 */
	{
	  aClient *acptr = IsServer(sptr) ? sptr : sptr->user->server;
	  for (; acptr != &me; acptr = acptr->serv->up)
	    if (acptr == who->user->server)	/* Case d) (server 5) */
	    {
	      remove_user_from_channel(who, chptr);
	      return 0;
	    }
	}
	/* Case a) (servers 1, 2, 3 and 6) */
	for (lp = chptr->members; lp; lp = lp->next)
	  if (!(lp->flags & CHFL_ZOMBIE))
	    break;
	if (!lp)
	  remove_user_from_channel(who, chptr);
#ifdef GODMODE
	else
	  sendto_op_mask(SNO_HACK2, "%s is now a zombie on %s",
	      who->name, chptr->chname);
#endif
      }
    }
  }
  else if (MyUser(sptr))
    sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
	me.name, parv[0], who->name, chptr->chname);

  return 0;
}

/*
 * m_topic
 *
 * parv[0]        = sender prefix
 * parv[1]        = channel
 * parv[parc - 1] = topic (if parc > 2)
 */
int m_topic(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  aChannel *chptr;
  char *topic = NULL, *name, *p = NULL;

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "TOPIC");
    return 0;
  }

  if (parc > 2)
    topic = parv[parc - 1];

  for (; (name = strtoken(&p, parv[1], ",")); parv[1] = NULL)
  {
    chptr = NULL;
    if (!IsChannelName(name) || !(chptr = FindChannel(name)) ||
	((topic || SecretChannel(chptr)) && !IsMember(sptr, chptr)))
    {
      sendto_one(sptr, err_str(chptr ? ERR_NOTONCHANNEL : ERR_NOSUCHCHANNEL),
	  me.name, parv[0], chptr ? chptr->chname : name);
      continue;
    }
    if (IsModelessChannel(name))
    {
      sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
	  chptr->chname);
      continue;
    }
    if (IsLocalChannel(name) && !MyUser(sptr))
      continue;

    if (!topic)			/* only asking  for topic  */
    {
      if (chptr->topic[0] == '\0')
	sendto_one(sptr, rpl_str(RPL_NOTOPIC), me.name, parv[0], chptr->chname);
      else
      {
	sendto_one(sptr, rpl_str(RPL_TOPIC),
	    me.name, parv[0], chptr->chname, chptr->topic);
	sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME),
	    me.name, parv[0], chptr->chname,
	    chptr->topic_nick, chptr->topic_time);
      }
    }
    else if (((chptr->mode.mode & MODE_TOPICLIMIT) == 0 ||
	is_chan_op(sptr, chptr)) && topic)
    {
      /* setting a topic */
      strncpy(chptr->topic, topic, TOPICLEN);
      strncpy(chptr->topic_nick, sptr->name, NICKLEN);
      chptr->topic_time = now;
      sendto_serv_butone(cptr, ":%s TOPIC %s :%s",
	  parv[0], chptr->chname, chptr->topic);
      sendto_channel_butserv(chptr, sptr, ":%s TOPIC %s :%s",
	  parv[0], chptr->chname, chptr->topic);
    }
    else
      sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
	  me.name, parv[0], chptr->chname);
  }
  return 0;
}

/*
 * m_invite
 *   parv[0] - sender prefix
 *   parv[1] - user to invite
 *   parv[2] - channel name
 *
 * - INVITE now is accepted only if who does it is chanop (this of course
 *   implies that channel must exist and he must be on it).
 *
 * - On the other side it IS processed even if channel is NOT invite only
 *   leaving room for other enhancements like inviting banned ppl.  -- Nemesi
 *
 */
int m_invite(aClient *UNUSED(cptr), aClient *sptr, int parc, char *parv[])
{
  aClient *acptr;
  aChannel *chptr;

  if (parc < 3 || *parv[2] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "INVITE");
    return 0;
  }

  if (!(acptr = FindUser(parv[1])))
  {
    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
    return 0;
  }

  if (is_silenced(sptr, acptr))
    return 0;

  if (MyUser(sptr))
    clean_channelname(parv[2]);
  else if (IsLocalChannel(parv[2]))
    return 0;

  if (*parv[2] == '0' || !IsChannelName(parv[2]))
    return 0;

  if (!(chptr = FindChannel(parv[2])))
  {
    if (IsModelessChannel(parv[2]) || IsLocalChannel(parv[2]))
    {
      sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0], parv[2]);
      return 0;
    }

    /* Do not disallow to invite to non-existant #channels, otherwise they
       would simply first be created, causing only MORE bandwidth usage. */
    if (MyConnect(sptr))
    {
      if (check_target_limit(sptr, acptr, acptr->name, 0))
	return 0;

      sendto_one(sptr, rpl_str(RPL_INVITING), me.name, parv[0],
	  acptr->name, parv[2]);

      if (acptr->user->away)
	sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0],
	    acptr->name, acptr->user->away);
    }

    sendto_prefix_one(acptr, sptr, ":%s INVITE %s :%s", parv[0],
	acptr->name, parv[2]);

    return 0;
  }

  if (!IsMember(sptr, chptr))
  {
    sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
	chptr->chname);
    return 0;
  }

  if (IsMember(acptr, chptr))
  {
    sendto_one(sptr, err_str(ERR_USERONCHANNEL),
	me.name, parv[0], acptr->name, chptr->chname);
    return 0;
  }

  if (MyConnect(sptr))
  {
    if (!is_chan_op(sptr, chptr))
    {
      sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
	  me.name, parv[0], chptr->chname);
      return 0;
    }

    /* If we get here, it was a VALID and meaningful INVITE */

    if (check_target_limit(sptr, acptr, acptr->name, 0))
      return 0;

    sendto_one(sptr, rpl_str(RPL_INVITING), me.name, parv[0],
	acptr->name, chptr->chname);

    if (acptr->user->away)
      sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0],
	  acptr->name, acptr->user->away);
  }

  if (MyConnect(acptr))
    add_invite(acptr, chptr);

  sendto_prefix_one(acptr, sptr, ":%s INVITE %s :%s", parv[0],
      acptr->name, chptr->chname);

  return 0;
}

static int number_of_zombies(aChannel *chptr)
{
  Reg1 Link *lp;
  Reg2 int count = 0;
  for (lp = chptr->members; lp; lp = lp->next)
    if (lp->flags & CHFL_ZOMBIE)
      count++;
  return count;
}

/*
 * m_list
 *
 * parv[0] = sender prefix
 * parv[1] = channel list or user/time limit
 * parv[2...] = more user/time limits
 */
int m_list(aClient *UNUSED(cptr), aClient *sptr, int parc, char *parv[])
{
  aChannel *chptr;
  char *name, *p = NULL;
  int show_usage = 0, show_channels = 0, param;
  aListingArgs args = {
    2147483647,			/* max_time */
    0,				/* min_time */
    4294967295U,		/* max_users */
    0,				/* min_users */
    0,				/* topic_limits */
    2147483647,			/* max_topic_time */
    0,				/* min_topic_time */
    NULL			/* chptr */
  };

  if (sptr->listing)		/* Already listing ? */
  {
    sptr->listing->chptr->mode.mode &= ~MODE_LISTED;
    RunFree(sptr->listing);
    sptr->listing = NULL;
    sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, sptr->name);
    if (parc < 2)
      return 0;			/* Let LIST abort a listing. */
  }

  if (parc < 2)			/* No arguments given to /LIST ? */
  {
#ifdef DEFAULT_LIST_PARAM
    static char *defparv[MAXPARA + 1];
    static int defparc = 0;
    static char lp[] = DEFAULT_LIST_PARAM;
    int i;

    if (!defparc)
    {
      char *s = lp, *t;

      defparc = 1;
      defparv[defparc++] = t = strtok(s, " ");
      while (t && defparc < MAXPARA)
      {
	if ((t = strtok(NULL, " ")))
	  defparv[defparc++] = t;
      }
    }
    for (i = 1; i < defparc; i++)
      parv[i] = defparv[i];
    parv[i] = NULL;
    parc = defparc;
#endif /* DEFAULT_LIST_PARAM */
  }

  /* Decode command */
  for (param = 1; !show_usage && parv[param]; param++)
  {
    char *p = parv[param];
    do
    {
      int is_time = 0;
      switch (*p)
      {
	case 'T':
	case 't':
	  is_time++;
	  args.topic_limits = 1;
	  /* Fall through */
	case 'C':
	case 'c':
	  is_time++;
	  p++;
	  if (*p != '<' && *p != '>')
	  {
	    show_usage = 1;
	    break;
	  }
	  /* Fall through */
	case '<':
	case '>':
	{
	  p++;
	  if (!isDigit(*p))
	    show_usage = 1;
	  else
	  {
	    if (is_time)
	    {
	      time_t val = atoi(p);
	      if (p[-1] == '<')
	      {
		if (val < 80000000)	/* Toggle UTC/offset */
		{
		  /*
		   * Demands that
		   * 'TStime() - chptr->creationtime < val * 60'
		   * Which equals
		   * 'chptr->creationtime > TStime() - val * 60'
		   */
		  if (is_time == 1)
		    args.min_time = TStime() - val * 60;
		  else
		    args.min_topic_time = TStime() - val * 60;
		}
		else if (is_time == 1)	/* Creation time in UTC was entered */
		  args.max_time = val;
		else		/* Topic time in UTC was entered */
		  args.max_topic_time = val;
	      }
	      else if (val < 80000000)
	      {
		if (is_time == 1)
		  args.max_time = TStime() - val * 60;
		else
		  args.max_topic_time = TStime() - val * 60;
	      }
	      else if (is_time == 1)
		args.min_time = val;
	      else
		args.min_topic_time = val;
	    }
	    else if (p[-1] == '<')
	      args.max_users = atoi(p);
	    else
	      args.min_users = atoi(p);
	    if ((p = strchr(p, ',')))
	      p++;
	  }
	  break;
	}
	default:
	  if (!IsChannelName(p))
	  {
	    show_usage = 1;
	    break;
	  }
	  if (parc != 2)	/* Don't allow a mixture of channels with <,> */
	    show_usage = 1;
	  show_channels = 1;
	  p = NULL;
	  break;
      }
    }
    while (!show_usage && p);	/* p points after comma, or is NULL */
  }

  if (show_usage)
  {
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	"Usage: \002/QUOTE LIST\002 \037parameters\037");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	"Where \037parameters\037 is a space or comma seperated "
	"list of one or more of:");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	" \002<\002\037max_users\037	; Show all channels with less "
	"than \037max_users\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	" \002>\002\037min_users\037	; Show all channels with more "
	"than \037min_users\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	" \002C<\002\037max_minutes\037 ; Channels that exist less "
	"than \037max_minutes\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	" \002C>\002\037min_minutes\037 ; Channels that exist more "
	"than \037min_minutes\037.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	" \002T<\002\037max_minutes\037 ; Channels with a topic last "
	"set less than \037max_minutes\037 ago.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	" \002T>\002\037min_minutes\037 ; Channels with a topic last "
	"set more than \037min_minutes\037 ago.");
    sendto_one(sptr, rpl_str(RPL_LISTUSAGE), me.name, parv[0],
	"Example: LIST <3,>1,C<10,T>0  ; 2 users, younger than 10 min., "
	"topic set.");
    return 0;
  }

  sendto_one(sptr, rpl_str(RPL_LISTSTART), me.name, parv[0]);

  if (!show_channels)
  {
    if (args.max_users > args.min_users + 1 && args.max_time > args.min_time &&
	args.max_topic_time > args.min_topic_time)	/* Sanity check */
    {
      if ((sptr->listing = (aListingArgs *)RunMalloc(sizeof(aListingArgs))))
      {
	memcpy(sptr->listing, &args, sizeof(aListingArgs));
	if ((sptr->listing->chptr = channel))
	{
	  int m = channel->mode.mode & MODE_LISTED;
	  list_next_channels(sptr, 64);
	  channel->mode.mode |= m;
	  return 0;
	}
	RunFree(sptr->listing);
	sptr->listing = NULL;
      }
    }
    sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);
    return 0;
  }

  for (; (name = strtoken(&p, parv[1], ",")); parv[1] = NULL)
  {
    chptr = FindChannel(name);
    if (chptr && ShowChannel(sptr, chptr) && sptr->user)
      sendto_one(sptr, rpl_str(RPL_LIST), me.name, parv[0],
	  ShowChannel(sptr, chptr) ? chptr->chname : "*",
	  chptr->users - number_of_zombies(chptr), chptr->topic);
  }

  sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);
  return 0;
}

/*
 * m_names                              - Added by Jto 27 Apr 1989
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 */
int m_names(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  Reg1 aChannel *chptr;
  Reg2 aClient *c2ptr;
  Reg3 Link *lp;
  aChannel *ch2ptr = NULL;
  int idx, flag, len, mlen;
  char *s, *para = parc > 1 ? parv[1] : NULL;

  if (parc > 2 && hunt_server(1, cptr, sptr, ":%s NAMES %s %s", 2, parc, parv))
    return 0;

  mlen = strlen(me.name) + 10 + strlen(sptr->name);

  if (!BadPtr(para))
  {
    s = strchr(para, ',');
    if (s)
    {
      parv[1] = ++s;
      m_names(cptr, sptr, parc, parv);
    }
    clean_channelname(para);
    ch2ptr = FindChannel(para);
  }

  /*
   * First, do all visible channels (public and the one user self is)
   */

  for (chptr = channel; chptr; chptr = chptr->nextch)
  {
    if ((chptr != ch2ptr) && !BadPtr(para))
      continue;			/* -- wanted a specific channel */
    if (!MyConnect(sptr) && BadPtr(para))
      continue;
#ifndef GODMODE
    if (!ShowChannel(sptr, chptr))
      continue;			/* -- users on this are not listed */
#endif

    /* Find users on same channel (defined by chptr) */

    strcpy(buf, "* ");
    len = strlen(chptr->chname);
    strcpy(buf + 2, chptr->chname);
    strcpy(buf + 2 + len, " :");

    if (PubChannel(chptr))
      *buf = '=';
    else if (SecretChannel(chptr))
      *buf = '@';
    idx = len + 4;
    flag = 1;
    for (lp = chptr->members; lp; lp = lp->next)
    {
      c2ptr = lp->value.cptr;
#ifndef GODMODE
      if (sptr != c2ptr && IsInvisible(c2ptr) && !IsMember(sptr, chptr))
	continue;
#endif
      if (lp->flags & CHFL_ZOMBIE)
      {
	if (lp->value.cptr != sptr)
	  continue;
	else
	{
	  strcat(buf, "!");
	  idx++;
	}
      }
      else if (lp->flags & CHFL_CHANOP)
      {
	strcat(buf, "@");
	idx++;
      }
      else if (lp->flags & CHFL_VOICE)
      {
	strcat(buf, "+");
	idx++;
      }
      strcat(buf, c2ptr->name);
      strcat(buf, " ");
      idx += strlen(c2ptr->name) + 1;
      flag = 1;
#ifdef GODMODE
      {
	char yxx[6];
	sprintf_irc(yxx, "%s%s", NumNick(c2ptr));
	if (c2ptr != findNUser(yxx))
	  MyCoreDump;
	sprintf_irc(buf + strlen(buf), "(%s) ", yxx);
	idx += 6;
      }
      if (mlen + idx + NICKLEN + 11 > BUFSIZE)
#else
      if (mlen + idx + NICKLEN + 5 > BUFSIZE)
#endif
	/* space, modifier, nick, \r \n \0 */
      {
	sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
	strcpy(buf, "* ");
	strncpy(buf + 2, chptr->chname, len + 1);
	buf[len + 2] = 0;
	strcat(buf, " :");
	if (PubChannel(chptr))
	  *buf = '=';
	else if (SecretChannel(chptr))
	  *buf = '@';
	idx = len + 4;
	flag = 0;
      }
    }
    if (flag)
      sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
  }
  if (!BadPtr(para))
  {
    sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0],
	ch2ptr ? ch2ptr->chname : para);
    return (1);
  }

  /* Second, do all non-public, non-secret channels in one big sweep */

  strcpy(buf, "* * :");
  idx = 5;
  flag = 0;
  for (c2ptr = client; c2ptr; c2ptr = c2ptr->next)
  {
    aChannel *ch3ptr;
    int showflag = 0, secret = 0;

#ifndef GODMODE
    if (!IsUser(c2ptr) || (sptr != c2ptr && IsInvisible(c2ptr)))
#else
    if (!IsUser(c2ptr))
#endif
      continue;
    lp = c2ptr->user->channel;
    /*
     * Don't show a client if they are on a secret channel or when
     * they are on a channel sptr is on since they have already
     * been show earlier. -avalon
     */
    while (lp)
    {
      ch3ptr = lp->value.chptr;
#ifndef GODMODE
      if (PubChannel(ch3ptr) || IsMember(sptr, ch3ptr))
#endif
	showflag = 1;
      if (SecretChannel(ch3ptr))
	secret = 1;
      lp = lp->next;
    }
    if (showflag)		/* Have we already shown them ? */
      continue;
#ifndef GODMODE
    if (secret)			/* On any secret channels ? */
      continue;
#endif
    strcat(buf, c2ptr->name);
    strcat(buf, " ");
    idx += strlen(c2ptr->name) + 1;
    flag = 1;
#ifdef GODMODE
    {
      char yxx[6];
      sprintf_irc(yxx, "%s%s", NumNick(c2ptr));
      if (c2ptr != findNUser(yxx))
	MyCoreDump;
      sprintf_irc(buf + strlen(buf), "(%s) ", yxx);
      idx += 6;
    }
#endif
#ifdef GODMODE
    if (mlen + idx + NICKLEN + 9 > BUFSIZE)
#else
    if (mlen + idx + NICKLEN + 3 > BUFSIZE)	/* space, \r\n\0 */
#endif
    {
      sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
      strcpy(buf, "* * :");
      idx = 5;
      flag = 0;
    }
  }
  if (flag)
    sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
  sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], "*");
  return (1);
}

void send_user_joins(aClient *cptr, aClient *user)
{
  Reg1 Link *lp;
  Reg2 aChannel *chptr;
  Reg3 int cnt = 0, len = 0, clen;
  char *mask;

  *buf = ':';
  strcpy(buf + 1, user->name);
  strcat(buf, " JOIN ");
  len = strlen(user->name) + 7;

  for (lp = user->user->channel; lp; lp = lp->next)
  {
    chptr = lp->value.chptr;
    if ((mask = strchr(chptr->chname, ':')))
      if (match(++mask, cptr->name))
	continue;
    if (*chptr->chname == '&')
      continue;
    if (is_zombie(user, chptr))
      continue;
    clen = strlen(chptr->chname);
    if (clen + 1 + len > BUFSIZE - 3)
    {
      if (cnt)
      {
	buf[len - 1] = '\0';
	sendto_one(cptr, "%s", buf);
      }
      *buf = ':';
      strcpy(buf + 1, user->name);
      strcat(buf, " JOIN ");
      len = strlen(user->name) + 7;
      cnt = 0;
    }
    strcpy(buf + len, chptr->chname);
    cnt++;
    len += clen;
    if (lp->next)
    {
      len++;
      strcat(buf, ",");
    }
  }
  if (*buf && cnt)
    sendto_one(cptr, "%s", buf);

  return;
}

/*
 * send_hack_notice()
 *
 * parc & parv[] are the same as that of the calling function:
 *   mtype == 1 is from m_mode, 2 is from m_create, 3 is from m_kick.
 *
 * This function prepares sendbuf with the server notices and wallops
 *   to be sent for all hacks.  -Ghostwolf 18-May-97
 */

static void send_hack_notice(aClient *cptr, aClient *sptr, int parc,
    char *parv[], int badop, int mtype)
{
  aChannel *chptr;
  static char params[MODEBUFLEN];
  int i = 3;
  chptr = FindChannel(parv[1]);
  *params = '\0';

  if (Protocol(cptr) < 10)	/* We don't get numeric nicks from P09  */
  {				/* servers, so this can be sent "As Is" */
    if (mtype == 1)
    {
      while (i < parc)
      {
	strcat(params, " ");
	strcat(params, parv[i++]);
      }
      sprintf_irc(sendbuf,
	  ":%s NOTICE * :*** Notice -- %sHACK(%d): %s MODE %s %s%s [" TIME_T_FMT
	  "]", me.name, (badop == 3) ? "BOUNCE or " : "", badop, parv[0],
	  parv[1], parv[2], params, chptr->creationtime);
      sendbufto_op_mask((badop == 3) ? SNO_HACK3 : (badop ==
	  4) ? SNO_HACK4 : SNO_HACK2);

      if ((IsServer(sptr)) && (badop == 2))
      {
	sprintf_irc(sendbuf, ":%s DESYNCH :HACK: %s MODE %s %s%s",
	    me.name, parv[0], parv[1], parv[2], params);
	sendbufto_serv_butone(cptr);
      }
    }
    else if (mtype == 3)
    {
      sprintf_irc(sendbuf,
	  ":%s NOTICE * :*** Notice -- HACK: %s KICK %s %s :%s",
	  me.name, sptr->name, parv[1], parv[2], parv[3]);
      sendbufto_op_mask(SNO_HACK4);
    }
  }
  else
  {
    /* P10 servers require numeric nick conversion before sending. */
    switch (mtype)
    {
      case 1:			/* Convert nicks for MODE HACKs here  */
      {
	char *mode = parv[2];
	while (i < parc)
	{
	  while (*mode && *mode != 'o' && *mode != 'v')
	    ++mode;
	  strcat(params, " ");
	  if (*mode == 'o' || *mode == 'v')
	  {
	    register aClient *acptr;
	    if ((acptr = findNUser(parv[i])) != NULL)	/* Convert nicks here */
	      strcat(params, acptr->name);
	    else
	    {
	      strcat(params, "<");
	      strcat(params, parv[i]);
	      strcat(params, ">");
	    }
	  }
	  else			/* If it isn't a numnick, send it 'as is' */
	    strcat(params, parv[i]);
	  i++;
	}
	sprintf_irc(sendbuf,
	    ":%s NOTICE * :*** Notice -- %sHACK(%d): %s MODE %s %s%s ["
	    TIME_T_FMT "]", me.name, (badop == 3) ? "BOUNCE or " : "", badop,
	    parv[0], parv[1], parv[2], params, chptr->creationtime);
	sendbufto_op_mask((badop == 3) ? SNO_HACK3 : (badop ==
	    4) ? SNO_HACK4 : SNO_HACK2);

	if ((IsServer(sptr)) && (badop == 2))
	{
	  sprintf_irc(sendbuf, ":%s DESYNCH :HACK: %s MODE %s %s%s",
	      me.name, parv[0], parv[1], parv[2], params);
	  sendbufto_serv_butone(cptr);
	}
	break;
      }
      case 2:			/* No conversion is needed for CREATE; the only numnick is sptr */
      {
	sendto_serv_butone(cptr, ":%s DESYNCH :HACK: %s CREATE %s %s",
	    me.name, sptr->name, chptr->chname, parv[2]);
	sendto_op_mask(SNO_HACK2, "HACK(2): %s CREATE %s %s",
	    sptr->name, chptr->chname, parv[2]);
	break;
      }
      case 3:			/* Convert nick in KICK message */
      {
	aClient *acptr;
	if ((acptr = findNUser(parv[2])) != NULL)	/* attempt to convert nick */
	  sprintf_irc(sendbuf,
	      ":%s NOTICE * :*** Notice -- HACK: %s KICK %s %s :%s",
	      me.name, sptr->name, parv[1], acptr->name, parv[3]);
	else			/* if conversion fails, send it 'as is' in <>'s */
	  sprintf_irc(sendbuf,
	      ":%s NOTICE * :*** Notice -- HACK: %s KICK %s <%s> :%s",
	      me.name, sptr->name, parv[1], parv[2], parv[3]);
	sendbufto_op_mask(SNO_HACK4);
	break;
      }
    }
  }
}
