/*
 * IRC - Internet Relay Chat, ircd/s_user.c (formerly ircd/s_msg.c)
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
#include "s_user.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "random.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h" /* max_client_count */
#include "send.h"
#include "sprintf_irc.h"
#include "struct.h"
#include "support.h"
#include "supported.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

#include "handlers.h" /* m_motd and m_lusers */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>


static int userCount = 0;

/*
 * 'make_user' add's an User information block to a client
 * if it was not previously allocated.
 */
struct User *make_user(struct Client *cptr)
{
  assert(0 != cptr);

  if (!cptr->user) {
    cptr->user = (struct User*) MyMalloc(sizeof(struct User));
    assert(0 != cptr->user);

    /* All variables are 0 by default */
    memset(cptr->user, 0, sizeof(struct User));
#ifdef  DEBUGMODE
    ++userCount;
#endif
    cptr->user->refcnt = 1;
  }
  return cptr->user;
}

/*
 * free_user
 *
 * Decrease user reference count by one and release block, if count reaches 0.
 */
void free_user(struct User* user)
{
  assert(0 != user);
  assert(0 < user->refcnt);

  if (--user->refcnt == 0) {
    if (user->away)
      MyFree(user->away);
    /*
     * sanity check
     */
    assert(0 == user->joined);
    assert(0 == user->invited);
    assert(0 == user->channel);

    MyFree(user);
#ifdef  DEBUGMODE
    --userCount;
#endif
  }
}

void user_count_memory(size_t* count_out, size_t* bytes_out)
{
  assert(0 != count_out);
  assert(0 != bytes_out);
  *count_out = userCount;
  *bytes_out = userCount * sizeof(struct User);
}

/*
 * user_set_away - set user away state
 * returns 1 if client is away or changed away message, 0 if 
 * client is removing away status.
 * NOTE: this function may modify user and message, so they
 * must be mutable.
 */
int user_set_away(struct User* user, char* message)
{
  char* away;
  assert(0 != user);

  away = user->away;

  if (EmptyString(message)) {
    /*
     * Marking as not away
     */
    if (away) {
      MyFree(away);
      user->away = 0;
    }
  }
  else {
    /*
     * Marking as away
     */
    unsigned int len = strlen(message);

    if (len > TOPICLEN) {
      message[TOPICLEN] = '\0';
      len = TOPICLEN;
    }
    if (away)
      away = (char*) MyRealloc(away, len + 1);
    else
      away = (char*) MyMalloc(len + 1);
    assert(0 != away);

    user->away = away;
    strcpy(away, message);
  }
  return (user->away != 0);
}

/*
 * next_client
 *
 * Local function to find the next matching client. The search
 * can be continued from the specified client entry. Normal
 * usage loop is:
 *
 * for (x = client; x = next_client(x,mask); x = x->next)
 *     HandleMatchingClient;
 *
 */
struct Client *next_client(struct Client *next, const char* ch)
{
  struct Client *tmp = next;

  if (!tmp)
    return NULL;

  next = FindClient(ch);
  next = next ? next : tmp;
  if (tmp->prev == next)
    return NULL;
  if (next != tmp)
    return next;
  for (; next; next = next->next)
    if (!match(ch, next->name))
      break;
  return next;
}

/*
 * hunt_server
 *
 *    Do the basic thing in delivering the message (command)
 *    across the relays to the specific server (server) for
 *    actions.
 *
 *    Note:   The command is a format string and *MUST* be
 *            of prefixed style (e.g. ":%s COMMAND %s ...").
 *            Command can have only max 8 parameters.
 *
 *    server  parv[server] is the parameter identifying the
 *            target server.
 *
 *    *WARNING*
 *            parv[server] is replaced with the pointer to the
 *            real servername from the matched client (I'm lazy
 *            now --msa).
 *
 *    returns: (see #defines)
 */
int hunt_server(int MustBeOper, struct Client *cptr, struct Client *sptr, char *command,
    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char y[8];

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString(parv[server]) || IsUnknown(sptr))
    return (HUNTED_ISME);

  /* Make sure it's a server */
  if (MyUser(sptr) || Protocol(cptr) < 10)
  {
    /* Make sure it's a server */
    if (!strchr(parv[server], '*')) {
      if (0 == (acptr = FindClient(parv[server])))
        return HUNTED_NOSUCH;
      if (acptr->user)
        acptr = acptr->user->server;
    }
    else if (!(acptr = find_match_server(parv[server])))
    {
      send_reply(sptr, ERR_NOSUCHSERVER, parv[server]);
      return (HUNTED_NOSUCH);
    }
  }
  else if (!(acptr = FindNServer(parv[server])))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(sptr))
  {
    send_reply(sptr, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  strcpy(y, acptr->yxx);
  parv[server] = y;

  assert(!IsServer(sptr));
  /* XXX sendto_one used with explicit command; must be very careful */
  sendto_one(acptr, command, NumNick(sptr), parv[1], parv[2], parv[3], parv[4],
      parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

int hunt_server_cmd(struct Client *from, const char *cmd, const char *tok,
		    struct Client *one, int MustBeOper, const char *pattern,
		    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to)))
        return HUNTED_NOSUCH;

      if (acptr->user)
        acptr = acptr->user->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to)))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  assert(!IsServer(from));

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
		parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

/*
 * 'do_nick_name' ensures that the given parameter (nick) is really a proper
 * string for a nickname (note, the 'nick' may be modified in the process...)
 *
 * RETURNS the length of the final NICKNAME (0, if nickname is invalid)
 *
 * Nickname characters are in range 'A'..'}', '_', '-', '0'..'9'
 *  anything outside the above set will terminate nickname.
 * In addition, the first character cannot be '-' or a Digit.
 *
 * Note:
 *  The '~'-character should be allowed, but a change should be global,
 *  some confusion would result if only few servers allowed it...
 */
int do_nick_name(char* nick)
{
  char* ch  = nick;
  char* end = ch + NICKLEN;
  assert(0 != ch);

  if (*ch == '-' || IsDigit(*ch))        /* first character in [0..9-] */
    return 0;

  for ( ; (ch < end) && *ch; ++ch)
    if (!IsNickChar(*ch))
      break;

  *ch = '\0';

  return (ch - nick);
}

/*
 * clean_user_id
 *
 * Copy `source' to `dest', replacing all occurances of '~' and characters that
 * are not `isIrcUi' by an underscore.
 * Copies at most USERLEN - 1 characters or up till the first control character.
 * If `tilde' is true, then a tilde is prepended to `dest'.
 * Note that `dest' and `source' can point to the same area or to different
 * non-overlapping areas.
 */
static char *clean_user_id(char *dest, char *source, int tilde)
{
  char ch;
  char *d = dest;
  char *s = source;
  int rlen = USERLEN;

  ch = *s++;                        /* Store first character to copy: */
  if (tilde)
  {
    *d++ = '~';                        /* If `dest' == `source', then this overwrites `ch' */
    --rlen;
  }
  while (ch && !IsCntrl(ch) && rlen--)
  {
    char nch = *s++;        /* Store next character to copy */
    *d++ = IsUserChar(ch) ? ch : '_';        /* This possibly overwrites it */
    if (nch == '~')
      ch = '_';
    else
      ch = nch;
  }
  *d = 0;
  return dest;
}

/*
 * register_user
 *
 * This function is called when both NICK and USER messages
 * have been accepted for the client, in whatever order. Only
 * after this the USER message is propagated.
 *
 * NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have
 * to implement the following:
 *
 * 1) user telnets in and gives only "NICK foobar" and waits
 * 2) another user far away logs in normally with the nick
 *    "foobar" (quite legal, as this server didn't propagate it).
 * 3) now this server gets nick "foobar" from outside, but
 *    has already the same defined locally. Current server
 *    would just issue "KILL foobar" to clean out dups. But,
 *    this is not fair. It should actually request another
 *    nick from local user or kill him/her...
 */
int register_user(struct Client *cptr, struct Client *sptr,
                  const char *nick, char *username)
{
  struct ConfItem* aconf;
  char*            parv[3];
  char*            tmpstr;
  char*            tmpstr2;
  char             c = 0;    /* not alphanum */
  char             d = 'a';  /* not a digit */
  short            upper = 0;
  short            lower = 0;
  short            pos = 0;
  short            leadcaps = 0;
  short            other = 0;
  short            digits = 0;
  short            badid = 0;
  short            digitgroups = 0;
  struct User*     user = sptr->user;
  char             ip_base64[8];
  char             featurebuf[512];
  struct Gline*    gline;

  user->last = CurrentTime;
  parv[0] = sptr->name;
  parv[1] = parv[2] = NULL;

  if (MyConnect(sptr))
  {
    static time_t last_too_many1;
    static time_t last_too_many2;

    assert(cptr == sptr);
    switch (conf_check_client(sptr))
    {
      case ACR_OK:
        break;
      case ACR_NO_AUTHORIZATION:
        sendto_opmask_butone(0, SNO_UNAUTH, "Unauthorized connection from %s.",
			     get_client_name(sptr, HIDE_IP));
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
			   "No Authorization - use another server");
      case ACR_TOO_MANY_IN_CLASS:
        if (CurrentTime - last_too_many1 >= (time_t) 60)
        {
          last_too_many1 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Too many connections in "
			       "class for %s.",
			       get_client_name(sptr, HIDE_IP));
        }
        ++ServerStats->is_ref;
        IPcheck_connect_fail(sptr->ip);
        return exit_client(cptr, sptr, &me,
			   "Sorry, your connection class is full - try "
			   "again later or try another server");
      case ACR_TOO_MANY_FROM_IP:
        if (CurrentTime - last_too_many2 >= (time_t) 60)
        {
          last_too_many2 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Too many connections from "
			       "same IP for %s.",
			       get_client_name(sptr, HIDE_IP));
        }
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
			   "Too many connections from your host");
      case ACR_ALREADY_AUTHORIZED:
        /* Can this ever happen? */
      case ACR_BAD_SOCKET:
        ++ServerStats->is_ref;
        IPcheck_connect_fail(sptr->ip);
        return exit_client(cptr, sptr, &me, "Unknown error -- Try again");
    }
    ircd_strncpy(user->host, sptr->sockhost, HOSTLEN);
    aconf = sptr->confs->value.aconf;

    clean_user_id(user->username,
        (sptr->flags & FLAGS_GOTID) ? sptr->username : username,
        (sptr->flags & FLAGS_DOID) && !(sptr->flags & FLAGS_GOTID));

    if ((user->username[0] == '\0')
        || ((user->username[0] == '~') && (user->username[1] == '\000')))
      return exit_client(cptr, sptr, &me, "USER: Bogus userid.");

    if (!EmptyString(aconf->passwd)
        && !(IsDigit(*aconf->passwd) && !aconf->passwd[1])
#ifdef USEONE
        && strcmp("ONE", aconf->passwd)
#endif
        && strcmp(sptr->passwd, aconf->passwd))
    {
      ServerStats->is_ref++;
      IPcheck_connect_fail(sptr->ip);
      send_reply(sptr, ERR_PASSWDMISMATCH);
      return exit_client(cptr, sptr, &me, "Bad Password");
    }
    memset(sptr->passwd, 0, sizeof(sptr->passwd));
    /*
     * following block for the benefit of time-dependent K:-lines
     */
    if (find_kill(sptr)) {
      ServerStats->is_ref++;
      IPcheck_connect_fail(sptr->ip);
      return exit_client(cptr, sptr, &me, "K-lined");
    }
    /*
     * Check for mixed case usernames, meaning probably hacked.  Jon2 3-94
     * Summary of rules now implemented in this patch:         Ensor 11-94
     * In a mixed-case name, if first char is upper, one more upper may
     * appear anywhere.  (A mixed-case name *must* have an upper first
     * char, and may have one other upper.)
     * A third upper may appear if all 3 appear at the beginning of the
     * name, separated only by "others" (-/_/.).
     * A single group of digits is allowed anywhere.
     * Two groups of digits are allowed if at least one of the groups is
     * at the beginning or the end.
     * Only one '-', '_', or '.' is allowed (or two, if not consecutive).
     * But not as the first or last char.
     * No other special characters are allowed.
     * Name must contain at least one letter.
     */
    tmpstr2 = tmpstr = (username[0] == '~' ? &username[1] : username);
    while (*tmpstr && !badid)
    {
      pos++;
      c = *tmpstr;
      tmpstr++;
      if (IsLower(c))
      {
        lower++;
      }
      else if (IsUpper(c))
      {
        upper++;
        if ((leadcaps || pos == 1) && !lower && !digits)
          leadcaps++;
      }
      else if (IsDigit(c))
      {
        digits++;
        if (pos == 1 || !IsDigit(d))
        {
          digitgroups++;
          if (digitgroups > 2)
            badid = 1;
        }
      }
      else if (c == '-' || c == '_' || c == '.')
      {
        other++;
        if (pos == 1)
          badid = 1;
        else if (d == '-' || d == '_' || d == '.' || other > 2)
          badid = 1;
      }
      else
        badid = 1;
      d = c;
    }
    if (!badid)
    {
      if (lower && upper && (!leadcaps || leadcaps > 3 ||
          (upper > 2 && upper > leadcaps)))
        badid = 1;
      else if (digitgroups == 2 && !(IsDigit(tmpstr2[0]) || IsDigit(c)))
        badid = 1;
      else if ((!lower && !upper) || !IsAlnum(c))
        badid = 1;
    }
    if (badid && (!(sptr->flags & FLAGS_GOTID) ||
        strcmp(sptr->username, username) != 0))
    {
      ServerStats->is_ref++;

      send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
		 ":Your username is invalid.");
      send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
		 ":Connect with your real username, in lowercase.");
      send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
		 ":If your mail address were foo@bar.com, your username "
		 "would be foo.");
      return exit_client(cptr, sptr, &me, "USER: Bad username");
    }
    Count_unknownbecomesclient(sptr, UserStats);
  }
  else {
    ircd_strncpy(user->username, username, USERLEN);
    Count_newremoteclient(UserStats, user->server);
    if ((gline = gline_lookup(sptr)) && GlineIsActive(gline))
      gline_resend(cptr, gline);
  }
  SetUser(sptr);

  if (IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (IsOper(sptr))
    ++UserStats.opers;

  if (MyConnect(sptr)) {
    sptr->handler = CLIENT_HANDLER;
    release_dns_reply(sptr);

    send_reply(sptr, RPL_WELCOME, nick);
    /*
     * This is a duplicate of the NOTICE but see below...
     */
    send_reply(sptr, RPL_YOURHOST, me.name, version);
    send_reply(sptr, RPL_CREATED, creation);
    send_reply(sptr, RPL_MYINFO, me.name, version);
    sprintf_irc(featurebuf,FEATURES,FEATURESVALUES);
    send_reply(sptr, RPL_ISUPPORT, featurebuf);
    m_lusers(sptr, sptr, 1, parv);
    update_load();
#ifdef NODEFAULTMOTD
    m_motd(sptr, NULL, 1, parv);
#else
    m_motd(sptr, sptr, 1, parv);
#endif
    nextping = CurrentTime;
    if (sptr->snomask & SNO_NOISY)
      set_snomask(sptr, sptr->snomask & SNO_NOISY, SNO_ADD);
    IPcheck_connect_succeeded(sptr);
  }
  else
    /* if (IsServer(cptr)) */
  {
    struct Client *acptr;

    acptr = user->server;
    if (acptr->from != sptr->from)
    {
      sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s != %s[%s])",
		    sptr, me.name, user->server->name, acptr->from->name,
		    acptr->from->sockhost);
      sptr->flags |= FLAGS_KILLED;
      return exit_client(cptr, sptr, &me, "NICK server wrong direction");
    }
    else
      sptr->flags |= (acptr->flags & FLAGS_TS8);

    /*
     * Check to see if this user is being propogated
     * as part of a net.burst, or is using protocol 9.
     * FIXME: This can be speeded up - its stupid to check it for
     * every NICK message in a burst again  --Run.
     */
    for (acptr = user->server; acptr != &me; acptr = acptr->serv->up) {
      if (IsBurst(acptr) || Protocol(acptr) < 10)
        break;
    }
    if (!IPcheck_remote_connect(sptr, (acptr != &me)))
      /*
       * We ran out of bits to count this
       */
      return exit_client(cptr, sptr, &me, "More than 255 connections from this address");
  }

  tmpstr = umode_str(sptr);
  sendcmdto_serv_butone(user->server, CMD_NICK, cptr, *tmpstr ?
			"%s %d %d %s %s +%s %s %s%s :%s" :
			"%s %d %d %s %s %s%s %s%s :%s",
			nick, sptr->hopcount + 1, sptr->lastnick,
			user->username, user->host, tmpstr,
			inttobase64(ip_base64, ntohl(sptr->ip.s_addr), 6),
			NumNick(sptr), sptr->info);

  /* Send umode to client */
  if (MyUser(sptr))
  {
    send_umode(cptr, sptr, 0, ALL_UMODES);
    if (sptr->snomask != SNO_DEFAULT && (sptr->flags & FLAGS_SERVNOTICE))
      send_reply(sptr, RPL_SNOMASK, sptr->snomask, sptr->snomask);
  }

  return 0;
}


static const struct UserMode {
  unsigned int flag;
  char         c;
} userModeList[] = {
  { FLAGS_OPER,        'o' },
  { FLAGS_LOCOP,       'O' },
  { FLAGS_INVISIBLE,   'i' },
  { FLAGS_WALLOP,      'w' },
  { FLAGS_SERVNOTICE,  's' },
  { FLAGS_DEAF,        'd' },
  { FLAGS_CHSERV,      'k' },
  { FLAGS_DEBUG,       'g' }
};

#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)

#if 0
static int user_modes[] = {
  FLAGS_OPER,        'o',
  FLAGS_LOCOP,       'O',
  FLAGS_INVISIBLE,   'i',
  FLAGS_WALLOP,      'w',
  FLAGS_SERVNOTICE,  's',
  FLAGS_DEAF,        'd',
  FLAGS_CHSERV,      'k',
  FLAGS_DEBUG,       'g',
  0,                  0
};
#endif

/*
 * XXX - find a way to get rid of this
 */
static char umodeBuf[BUFSIZE];

int set_nick_name(struct Client* cptr, struct Client* sptr,
                  const char* nick, int parc, char* parv[])
{
  if (IsServer(sptr)) {
    int   i;
    const char* p;

    /*
     * A server introducing a new client, change source
     */
    struct Client* new_client = make_client(cptr, STAT_UNKNOWN);
    assert(0 != new_client);

    new_client->hopcount = atoi(parv[2]);
    new_client->lastnick = atoi(parv[3]);
    if (Protocol(cptr) > 9 && parc > 7 && *parv[6] == '+') {
      for (p = parv[6] + 1; *p; p++) {
        for (i = 0; i < USERMODELIST_SIZE; ++i) {
          if (userModeList[i].c == *p) {
            new_client->flags |= userModeList[i].flag;
            break;
          }
        }
      }
    }
    /*
     * Set new nick name.
     */
    strcpy(new_client->name, nick);
    new_client->user = make_user(new_client);
    new_client->user->server = sptr;
    SetRemoteNumNick(new_client, parv[parc - 2]);
    /*
     * IP# of remote client
     */
    new_client->ip.s_addr = htonl(base64toint(parv[parc - 3]));

    add_client_to_list(new_client);
    hAddClient(new_client);

    sptr->serv->ghost = 0;        /* :server NICK means end of net.burst */
    ircd_strncpy(new_client->username, parv[4], USERLEN);
    ircd_strncpy(new_client->user->host, parv[5], HOSTLEN);
    ircd_strncpy(new_client->info, parv[parc - 1], REALLEN);
    return register_user(cptr, new_client, new_client->name, parv[4]);
  }
  else if (sptr->name[0]) {
    /*
     * Client changing its nick
     *
     * If the client belongs to me, then check to see
     * if client is on any channels where it is currently
     * banned.  If so, do not allow the nick change to occur.
     */
    if (MyUser(sptr)) {
      const char* channel_name;
      if ((channel_name = find_no_nickchange_channel(sptr))) {
	return send_reply(cptr, ERR_BANNICKCHANGE, channel_name);
      }
      /*
       * Refuse nick change if the last nick change was less
       * then 30 seconds ago. This is intended to get rid of
       * clone bots doing NICK FLOOD. -SeKs
       * If someone didn't change their nick for more then 60 seconds
       * however, allow to do two nick changes immedately after another
       * before limiting the nick flood. -Run
       */
      if (CurrentTime < cptr->nextnick) {
        cptr->nextnick += 2;
	send_reply(cptr, ERR_NICKTOOFAST, parv[1],
		   cptr->nextnick - CurrentTime);
        /* Send error message */
	sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cptr->name);
        /* bounce NICK to user */
        return 0;                /* ignore nick change! */
      }
      else {
        /* Limit total to 1 change per NICK_DELAY seconds: */
        cptr->nextnick += NICK_DELAY;
        /* However allow _maximal_ 1 extra consecutive nick change: */
        if (cptr->nextnick < CurrentTime)
          cptr->nextnick = CurrentTime;
      }
    }
    /*
     * Also set 'lastnick' to current time, if changed.
     */
    if (0 != ircd_strcmp(parv[0], nick))
      sptr->lastnick = (sptr == cptr) ? TStime() : atoi(parv[2]);

    /*
     * Client just changing his/her nick. If he/she is
     * on a channel, send note of change to all clients
     * on that channel. Propagate notice to other servers.
     */
    if (IsUser(sptr)) {
      sendcmdto_common_channels(sptr, CMD_NICK, ":%s", nick);
      add_history(sptr, 1);
      sendcmdto_serv_butone(sptr, CMD_NICK, cptr, "%s %Tu", nick,
			    sptr->lastnick);
    }
    else
      sendcmdto_one(sptr, CMD_NICK, sptr, ":%s", nick);

    if (sptr->name[0])
      hRemClient(sptr);
    strcpy(sptr->name, nick);
    hAddClient(sptr);
  }
  else {
    /* Local client setting NICK the first time */

    strcpy(sptr->name, nick);
    if (!sptr->user) {
      sptr->user = make_user(sptr);
      sptr->user->server = &me;
    }
    SetLocalNumNick(sptr);
    hAddClient(sptr);

    /*
     * If the client hasn't gotten a cookie-ping yet,
     * choose a cookie and send it. -record!jegelhof@cloud9.net
     */
    if (!sptr->cookie) {
      do {
        sptr->cookie = (ircrandom() & 0x7fffffff);
      } while (!sptr->cookie);
      sendrawto_one(cptr, MSG_PING " :%u", sptr->cookie);
    }
    else if (*sptr->user->host && sptr->cookie == COOKIE_VERIFIED) {
      /*
       * USER and PONG already received, now we have NICK.
       * register_user may reject the client and call exit_client
       * for it - must test this and exit m_nick too !
       */
      sptr->lastnick = TStime();        /* Always local client */
      if (register_user(cptr, sptr, nick, sptr->user->username) == CPTR_KILLED)
        return CPTR_KILLED;
    }
  }
  return 0;
}

static unsigned char hash_target(unsigned int target)
{
  return (unsigned char) (target >> 16) ^ (target >> 8);
}

/*
 * add_target
 *
 * sptr must be a local client!
 *
 * Cannonifies target for client `sptr'.
 */
void add_target(struct Client *sptr, void *target)
{
  unsigned char  hash = hash_target((unsigned int) target);
  unsigned char* targets;
  int            i;
  assert(0 != sptr);
  assert(sptr->local);

  targets = sptr->targets;
  /* 
   * Already in table?
   */
  for (i = 0; i < MAXTARGETS; ++i) {
    if (targets[i] == hash)
      return;
  }
  /*
   * New target
   */
  memmove(&targets[RESERVEDTARGETS + 1],
          &targets[RESERVEDTARGETS], MAXTARGETS - RESERVEDTARGETS - 1);
  targets[RESERVEDTARGETS] = hash;
}

/*
 * check_target_limit
 *
 * sptr must be a local client !
 *
 * Returns 'true' (1) when too many targets are addressed.
 * Returns 'false' (0) when it's ok to send to this target.
 */
int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created)
{
  unsigned char hash = hash_target((unsigned int) target);
  int            i;
  unsigned char* targets;

  assert(0 != sptr);
  assert(sptr->local);
  targets = sptr->targets;

  /*
   * Same target as last time?
   */
  if (targets[0] == hash)
    return 0;
  for (i = 1; i < MAXTARGETS; ++i) {
    if (targets[i] == hash) {
      memmove(&targets[1], &targets[0], i);
      targets[0] = hash;
      return 0;
    }
  }
  /*
   * New target
   */
  if (!created) {
    if (CurrentTime < sptr->nexttarget) {
      if (sptr->nexttarget - CurrentTime < TARGET_DELAY + 8) {
        /*
         * No server flooding
         */
        sptr->nexttarget += 2;
	send_reply(sptr, ERR_TARGETTOOFAST, name,
		   sptr->nexttarget - CurrentTime);
      }
      return 1;
    }
    else {
#ifdef GODMODE
      /* XXX Let's get rid of GODMODE */
      sendto_one(sptr, ":%s NOTICE %s :New target: %s; ft " TIME_T_FMT, /* XXX Possibly DEAD */
          me.name, sptr->name, name, (CurrentTime - sptr->nexttarget) / TARGET_DELAY);
#endif
      sptr->nexttarget += TARGET_DELAY;
      if (sptr->nexttarget < CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1)))
        sptr->nexttarget = CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1));
    }
  }
  memmove(&targets[1], &targets[0], MAXTARGETS - 1);
  targets[0] = hash;
  return 0;
}

/*
 * whisper - called from m_cnotice and m_cprivmsg.
 *
 * parv[0] = sender prefix
 * parv[1] = nick
 * parv[2] = #channel
 * parv[3] = Private message text
 *
 * Added 971023 by Run.
 * Reason: Allows channel operators to sent an arbitrary number of private
 *   messages to users on their channel, avoiding the max.targets limit.
 *   Building this into m_private would use too much cpu because we'd have
 *   to a cross channel lookup for every private message!
 * Note that we can't allow non-chan ops to use this command, it would be
 *   abused by mass advertisers.
 *
 */
int whisper(struct Client* source, const char* nick, const char* channel,
            const char* text, int is_notice)
{
  struct Client*     dest;
  struct Channel*    chptr;
  struct Membership* membership;

  assert(0 != source);
  assert(0 != nick);
  assert(0 != channel);
  assert(MyUser(source));

  if (!(dest = FindUser(nick))) {
    return send_reply(source, ERR_NOSUCHNICK, nick);
  }
  if (!(chptr = FindChannel(channel))) {
    return send_reply(source, ERR_NOSUCHCHANNEL, channel);
  }
  /*
   * compare both users channel lists, instead of the channels user list
   * since the link is the same, this should be a little faster for channels
   * with a lot of users
   */
  for (membership = source->user->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership) {
    return send_reply(source, ERR_NOTONCHANNEL, chptr->chname);
  }
  if (!IsVoicedOrOpped(membership)) {
    return send_reply(source, ERR_VOICENEEDED, chptr->chname);
  }
  /*
   * lookup channel in destination
   */
  assert(0 != dest->user);
  for (membership = dest->user->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership || IsZombie(membership)) {
    return send_reply(source, ERR_USERNOTINCHANNEL, dest->name, chptr->chname);
  }
  if (is_silenced(source, dest))
    return 0;
          
  if (dest->user->away)
    send_reply(source, RPL_AWAY, dest->name, dest->user->away);
  if (is_notice)
    sendcmdto_one(source, CMD_NOTICE, dest, "%C :%s", dest, text);
  else
    sendcmdto_one(source, CMD_PRIVATE, dest, "%C :%s", dest, text);
  return 0;
}


/*
 * added Sat Jul 25 07:30:42 EST 1992
 */
void send_umode_out(struct Client *cptr, struct Client *sptr, int old)
{
  int i;
  struct Client *acptr;

  send_umode(NULL, sptr, old, SEND_UMODES);

  for (i = HighestFd; i >= 0; i--) {
    if ((acptr = LocalClientArray[i]) && IsServer(acptr) &&
        (acptr != cptr) && (acptr != sptr) && *umodeBuf)
      sendcmdto_one(sptr, CMD_MODE, acptr, "%s :%s", sptr->name, umodeBuf);
  }
  if (cptr && MyUser(cptr))
    send_umode(cptr, sptr, old, ALL_UMODES);
}


/*
 * send_user_info - send user info userip/userhost
 * NOTE: formatter must put info into buffer and return a pointer to the end of
 * the data it put in the buffer.
 */
void send_user_info(struct Client* sptr, char* names, int rpl, InfoFormatter fmt)
{
  char*          sbuf;
  char*          name;
  char*          p = 0;
  int            arg_count = 0;
  int            users_found = 0;
  struct Client* acptr;
  char           buf[BUFSIZE * 2];

  assert(0 != sptr);
  assert(0 != names);
  assert(0 != fmt);

  sbuf = sprintf_irc(buf, rpl_str(rpl), me.name, sptr->name);

  for (name = ircd_strtok(&p, names, " "); name; name = ircd_strtok(&p, 0, " ")) {
    if ((acptr = FindUser(name))) {
      if (users_found++)
        *sbuf++ = ' ';
      sbuf = (*fmt)(acptr, sbuf);
    }
    if (5 == ++arg_count)
      break;
  }
  if (users_found)
    send_buffer(sptr, buf);
}


/*
 * set_user_mode() added 15/10/91 By Darren Reed.
 *
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char** p;
  char*  m;
  struct Client *acptr;
  int what;
  int i;
  int setflags;
  unsigned int tmpmask = 0;
  int snomask_given = 0;
  char buf[BUFSIZE];

  what = MODE_ADD;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  if (!(acptr = FindUser(parv[1])))
  {
    if (MyConnect(sptr))
      send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
    return 0;
  }

  if (IsServer(sptr) || sptr != acptr)
  {
    if (IsServer(cptr))
      sendcmdto_flag_butone(&me, CMD_WALLOPS, 0, FLAGS_WALLOP,
			    ":MODE for User %s from %s!%s", parv[1],
			    cptr->name, sptr->name);
    else
      send_reply(sptr, ERR_USERSDONTMATCH);
    return 0;
  }

  if (parc < 3)
  {
    m = buf;
    *m++ = '+';
    for (i = 0; i < USERMODELIST_SIZE; ++i) {
      if ( (userModeList[i].flag & sptr->flags))
        *m++ = userModeList[i].c;
    }
    *m = '\0';
    send_reply(sptr, RPL_UMODEIS, buf);
    if ((sptr->flags & FLAGS_SERVNOTICE) && MyConnect(sptr)
        && sptr->snomask !=
        (unsigned int)(IsOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT))
      send_reply(sptr, RPL_SNOMASK, sptr->snomask, sptr->snomask);
    return 0;
  }

  /*
   * find flags already set for user
   * why not just copy them?
   */
  setflags = sptr->flags;
#if 0
  setflags = 0;
  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    if (sptr->flags & userModeList[i].flag)
      setflags |= userModeList[i].flag;
  }
#endif
  if (MyConnect(sptr))
    tmpmask = sptr->snomask;

  /*
   * parse mode change string(s)
   */
  for (p = &parv[2]; *p; p++) {       /* p is changed in loop too */
    for (m = *p; *m; m++) {
      switch (*m) {
      case '+':
        what = MODE_ADD;
        break;
      case '-':
        what = MODE_DEL;
        break;
      case 's':
        if (*(p + 1) && is_snomask(*(p + 1))) {
          snomask_given = 1;
          tmpmask = umode_make_snomask(tmpmask, *++p, what);
          tmpmask &= (IsAnOper(sptr) ? SNO_ALL : SNO_USER);
        }
        else
          tmpmask = (what == MODE_ADD) ?
              (IsAnOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT) : 0;
        if (tmpmask)
          sptr->flags |= FLAGS_SERVNOTICE;
        else
          sptr->flags &= ~FLAGS_SERVNOTICE;
        break;
      case 'w':
        if (what == MODE_ADD)
          SetWallops(sptr);
        else
          ClearWallops(sptr);
        break;
      case 'o':
        if (what == MODE_ADD)
          SetOper(sptr);
        else {
          sptr->flags &= ~(FLAGS_OPER | FLAGS_LOCOP);
          if (MyConnect(sptr)) {
            tmpmask = sptr->snomask & ~SNO_OPER;
            sptr->handler = CLIENT_HANDLER;
          }
        }
        break;
      case 'O':
        if (what == MODE_ADD)
          SetLocOp(sptr);
        else { 
          sptr->flags &= ~(FLAGS_OPER | FLAGS_LOCOP);
          if (MyConnect(sptr)) {
            tmpmask = sptr->snomask & ~SNO_OPER;
            sptr->handler = CLIENT_HANDLER;
          }
        }
        break;
      case 'i':
        if (what == MODE_ADD)
          SetInvisible(sptr);
        else
          ClearInvisible(sptr);
        break;
      case 'd':
        if (what == MODE_ADD)
          SetDeaf(sptr);
        else
          ClearDeaf(sptr);
        break;
      case 'k':
        if (what == MODE_ADD)
          SetChannelService(sptr);
        else
          ClearChannelService(sptr);
        break;
      case 'g':
        if (what == MODE_ADD)
          SetDebug(sptr);
        else
          ClearDebug(sptr);
        break;
      default:
        break;
      }
    }
  }
  /*
   * Evaluate rules for new user mode
   * Stop users making themselves operators too easily:
   */
  if (!(setflags & FLAGS_OPER) && IsOper(sptr) && !IsServer(cptr))
    ClearOper(sptr);
  if (!(setflags & FLAGS_LOCOP) && IsLocOp(sptr) && !IsServer(cptr))
    ClearLocOp(sptr);
#ifdef WALLOPS_OPER_ONLY
  /*
   * only send wallops to opers
   */
  if (!IsAnOper(sptr) && !(setflags & FLAGS_WALLOP) && !IsServer(cptr))
    ClearWallops(sptr);
#endif
  if ((setflags & (FLAGS_OPER | FLAGS_LOCOP)) && !IsAnOper(sptr) &&
      MyConnect(sptr))
    det_confs_butmask(sptr, CONF_CLIENT & ~CONF_OPS);
  /*
   * new umode; servers can set it, local users cannot;
   * prevents users from /kick'ing or /mode -o'ing
   */
  if (!(setflags & FLAGS_CHSERV) && !IsServer(cptr))
    ClearChannelService(sptr);
  /*
   * Compare new flags with old flags and send string which
   * will cause servers to update correctly.
   */
  if ((setflags & FLAGS_OPER) && !IsOper(sptr))
    --UserStats.opers;
  if (!(setflags & FLAGS_OPER) && IsOper(sptr))
    ++UserStats.opers;
  if ((setflags & FLAGS_INVISIBLE) && !IsInvisible(sptr))
    --UserStats.inv_clients;
  if (!(setflags & FLAGS_INVISIBLE) && IsInvisible(sptr))
    ++UserStats.inv_clients;
  send_umode_out(cptr, sptr, setflags);

  if (MyConnect(sptr)) {
    if (tmpmask != sptr->snomask)
      set_snomask(sptr, tmpmask, SNO_SET);
    if (sptr->snomask && snomask_given)
      send_reply(sptr, RPL_SNOMASK, sptr->snomask, sptr->snomask);
  }

  return 0;
}

/*
 * Build umode string for BURST command
 * --Run
 */
char *umode_str(struct Client *cptr)
{
  char* m = umodeBuf;                /* Maximum string size: "owidg\0" */
  int   i;
  int   c_flags;

  c_flags = cptr->flags & SEND_UMODES;        /* cleaning up the original code */

  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    if ( (c_flags & userModeList[i].flag))
      *m++ = userModeList[i].c;
  }
  *m = '\0';

  return umodeBuf;                /* Note: static buffer, gets
                                   overwritten by send_umode() */
}

/*
 * Send the MODE string for user (user) to connection cptr
 * -avalon
 */
void send_umode(struct Client *cptr, struct Client *sptr, int old, int sendmask)
{
  int i;
  int flag;
  char *m;
  int what = MODE_NULL;

  /*
   * Build a string in umodeBuf to represent the change in the user's
   * mode between the new (sptr->flag) and 'old'.
   */
  m = umodeBuf;
  *m = '\0';
  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    flag = userModeList[i].flag;
    if (MyUser(sptr) && !(flag & sendmask))
      continue;
    if ( (flag & old) && !(sptr->flags & flag))
    {
      if (what == MODE_DEL)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_DEL;
        *m++ = '-';
        *m++ = userModeList[i].c;
      }
    }
    else if (!(flag & old) && (sptr->flags & flag))
    {
      if (what == MODE_ADD)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_ADD;
        *m++ = '+';
        *m++ = userModeList[i].c;
      }
    }
  }
  *m = '\0';
  if (*umodeBuf && cptr)
    sendcmdto_one(sptr, CMD_MODE, cptr, "%s :%s", sptr->name, umodeBuf);
}

/*
 * Check to see if this resembles a sno_mask.  It is if 1) there is
 * at least one digit and 2) The first digit occurs before the first
 * alphabetic character.
 */
int is_snomask(char *word)
{
  if (word)
  {
    for (; *word; word++)
      if (IsDigit(*word))
        return 1;
      else if (IsAlpha(*word))
        return 0;
  }
  return 0;
}

/*
 * If it begins with a +, count this as an additive mask instead of just
 * a replacement.  If what == MODE_DEL, "+" has no special effect.
 */
unsigned int umode_make_snomask(unsigned int oldmask, char *arg, int what)
{
  unsigned int sno_what;
  unsigned int newmask;
  if (*arg == '+')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_ADD;
    else
      sno_what = SNO_DEL;
  }
  else if (*arg == '-')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_DEL;
    else
      sno_what = SNO_ADD;
  }
  else
    sno_what = (what == MODE_ADD) ? SNO_SET : SNO_DEL;
  /* pity we don't have strtoul everywhere */
  newmask = (unsigned int)atoi(arg);
  if (sno_what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (sno_what == SNO_ADD)
    newmask |= oldmask;
  return newmask;
}

static void delfrom_list(struct Client *cptr, struct SLink **list)
{
  struct SLink* tmp;
  struct SLink* prv = NULL;

  for (tmp = *list; tmp; tmp = tmp->next) {
    if (tmp->value.cptr == cptr) {
      if (prv)
        prv->next = tmp->next;
      else
        *list = tmp->next;
      free_link(tmp);
      break;
    }
    prv = tmp;
  }
}

/*
 * This function sets a Client's server notices mask, according to
 * the parameter 'what'.  This could be even faster, but the code
 * gets mighty hard to read :)
 */
void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  unsigned int oldmask, diffmask;        /* unsigned please */
  int i;
  struct SLink *tmp;

  oldmask = cptr->snomask;

  if (what == SNO_ADD)
    newmask |= oldmask;
  else if (what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (what != SNO_SET)        /* absolute set, no math needed */
    sendto_opmask_butone(0, SNO_OLDSNO, "setsnomask called with %d ?!", what);

  newmask &= (IsAnOper(cptr) ? SNO_ALL : SNO_USER);

  diffmask = oldmask ^ newmask;

  for (i = 0; diffmask >> i; i++) {
    if (((diffmask >> i) & 1))
    {
      if (((newmask >> i) & 1))
      {
        tmp = make_link();
        tmp->next = opsarray[i];
        tmp->value.cptr = cptr;
        opsarray[i] = tmp;
      }
      else
        /* not real portable :( */
        delfrom_list(cptr, &opsarray[i]);
    }
  }
  cptr->snomask = newmask;
}

/*
 * is_silenced : Does the actual check wether sptr is allowed
 *               to send a message to acptr.
 *               Both must be registered persons.
 * If sptr is silenced by acptr, his message should not be propagated,
 * but more over, if this is detected on a server not local to sptr
 * the SILENCE mask is sent upstream.
 */
int is_silenced(struct Client *sptr, struct Client *acptr)
{
  struct SLink *lp;
  struct User *user;
  static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
  static char senderip[16 + NICKLEN + USERLEN + 5];

  if (!(acptr->user) || !(lp = acptr->user->silence) || !(user = sptr->user))
    return 0;
  sprintf_irc(sender, "%s!%s@%s", sptr->name, user->username, user->host);
  sprintf_irc(senderip, "%s!%s@%s", sptr->name, user->username,
              ircd_ntoa((const char*) &sptr->ip));
  for (; lp; lp = lp->next)
  {
    if ((!(lp->flags & CHFL_SILENCE_IPMASK) && !match(lp->value.cp, sender)) ||
        ((lp->flags & CHFL_SILENCE_IPMASK) && !match(lp->value.cp, senderip)))
    {
      if (!MyConnect(sptr))
      {
	sendcmdto_one(acptr, CMD_SILENCE, sptr->from, "%C %s", sptr,
		      lp->value.cp);
      }
      return 1;
    }
  }
  return 0;
}

/*
 * del_silence
 *
 * Removes all silence masks from the list of sptr that fall within `mask'
 * Returns -1 if none where found, 0 otherwise.
 */
int del_silence(struct Client *sptr, char *mask)
{
  struct SLink **lp;
  struct SLink *tmp;
  int ret = -1;

  for (lp = &sptr->user->silence; *lp;) {
    if (!mmatch(mask, (*lp)->value.cp))
    {
      tmp = *lp;
      *lp = tmp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      ret = 0;
    }
    else
      lp = &(*lp)->next;
  }
  return ret;
}

int add_silence(struct Client* sptr, const char* mask)
{
  struct SLink *lp, **lpp;
  int cnt = 0, len = strlen(mask);
  char *ip_start;

  for (lpp = &sptr->user->silence, lp = *lpp; lp;)
  {
    if (0 == ircd_strcmp(mask, lp->value.cp))
      return -1;
    if (!mmatch(mask, lp->value.cp))
    {
      struct SLink *tmp = lp;
      *lpp = lp = lp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      continue;
    }
    if (MyUser(sptr))
    {
      len += strlen(lp->value.cp);
      if ((len > MAXSILELENGTH) || (++cnt >= MAXSILES))
      {
	send_reply(sptr, ERR_SILELISTFULL, mask);
        return -1;
      }
      else if (!mmatch(lp->value.cp, mask))
        return -1;
    }
    lpp = &lp->next;
    lp = *lpp;
  }
  lp = make_link();
  memset(lp, 0, sizeof(struct SLink));
  lp->next = sptr->user->silence;
  lp->value.cp = (char*) MyMalloc(strlen(mask) + 1);
  assert(0 != lp->value.cp);
  strcpy(lp->value.cp, mask);
  if ((ip_start = strrchr(mask, '@')) && check_if_ipmask(ip_start + 1))
    lp->flags = CHFL_SILENCE_IPMASK;
  sptr->user->silence = lp;
  return 0;
}

