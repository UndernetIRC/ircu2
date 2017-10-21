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
 */
/** @file
 * @brief Miscellaneous user-related helper functions.
 * @version $Id$
 */
#include "config.h"

#include "s_user.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "random.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h" /* max_client_count */
#include "send.h"
#include "struct.h"
#include "supported.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

#include "handlers.h" /* m_motd and m_lusers */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/** Count of allocated User structures. */
static int userCount = 0;

/** Makes sure that \a cptr has a User information block.
 * If cli_user(cptr) != NULL, does nothing.
 * @param[in] cptr Client to attach User struct to.
 * @return User struct associated with \a cptr.
 */
struct User *make_user(struct Client *cptr)
{
  assert(0 != cptr);

  if (!cli_user(cptr)) {
    cli_user(cptr) = (struct User*) MyMalloc(sizeof(struct User));
    assert(0 != cli_user(cptr));

    /* All variables are 0 by default */
    memset(cli_user(cptr), 0, sizeof(struct User));
    ++userCount;
    cli_user(cptr)->refcnt = 1;
  }
  return cli_user(cptr);
}

/** Dereference \a user.
 * User structures are reference-counted; if the refcount of \a user
 * becomes zero, free it.
 * @param[in] user User to dereference.
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
    assert(userCount>0);
    --userCount;
  }
}

/** Find number of User structs allocated and memory used by them.
 * @param[out] count_out Receives number of User structs allocated.
 * @param[out] bytes_out Receives number of bytes used by User structs.
 */
void user_count_memory(size_t* count_out, size_t* bytes_out)
{
  assert(0 != count_out);
  assert(0 != bytes_out);
  *count_out = userCount;
  *bytes_out = userCount * sizeof(struct User);
}


/** Find the next client (starting at \a next) with a name that matches \a ch.
 * Normal usage loop is:
 * for (x = client; x = next_client(x,mask); x = x->next)
 *     HandleMatchingClient;
 *
 * @param[in] next First client to check.
 * @param[in] ch Name mask to check against.
 * @return Next matching client found, or NULL if none.
 */
struct Client *next_client(struct Client *next, const char* ch)
{
  struct Client *tmp = next;

  if (!tmp)
    return NULL;

  next = FindClient(ch);
  next = next ? next : tmp;
  if (cli_prev(tmp) == next)
    return NULL;
  if (next != tmp)
    return next;
  for (; next; next = cli_next(next))
    if (!match(ch, cli_name(next)))
      break;
  return next;
}

/** Find the destination server for a command, and forward it if that is not us.
 *
 * \a server may be a nickname, server name, server mask (if \a from
 * is a local user) or server numnick (if \a is a server or remote
 * user).
 *
 * @param[in] from Client that sent the command to us.
 * @param[in] cmd Long-form command text.
 * @param[in] tok Token-form command text.
 * @param[in] one Client that originated the command (ignored).
 * @param[in] MustBeOper If non-zero and \a from is not an operator, return HUNTED_NOSUCH.
 * @param[in] pattern Format string of arguments to command.
 * @param[in] server Index of target name or mask in \a parv.
 * @param[in] parc Number of valid elements in \a parv (must be less than 9).
 * @param[in] parv Array of arguments to command.
 * @return One of HUNTED_ISME, HUNTED_NOSUCH or HUNTED_PASS.
 */
int hunt_server_cmd(struct Client *from, const char *cmd, const char *tok,
                    struct Client *one, int MustBeOper, const char *pattern,
                    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from))
  {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to))) {
    send_reply(from, SND_EXPLICIT | ERR_NOSUCHSERVER, "* :Server has disconnected");
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */
  }

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* assert(!IsServer(from)); */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
                parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

/** Find the destination server for a command, and forward it (as a
 * high-priority command) if that is not us.
 *
 * \a server may be a nickname, server name, server mask (if \a from
 * is a local user) or server numnick (if \a is a server or remote
 * user).
 * Unlike hunt_server_cmd(), this appends the message to the
 * high-priority message queue for the destination server.
 *
 * @param[in] from Client that sent the command to us.
 * @param[in] cmd Long-form command text.
 * @param[in] tok Token-form command text.
 * @param[in] one Client that originated the command (ignored).
 * @param[in] MustBeOper If non-zero and \a from is not an operator, return HUNTED_NOSUCH.
 * @param[in] pattern Format string of arguments to command.
 * @param[in] server Index of target name or mask in \a parv.
 * @param[in] parc Number of valid elements in \a parv (must be less than 9).
 * @param[in] parv Array of arguments to command.
 * @return One of HUNTED_ISME, HUNTED_NOSUCH or HUNTED_PASS.
 */
int hunt_server_prio_cmd(struct Client *from, const char *cmd, const char *tok,
			 struct Client *one, int MustBeOper,
			 const char *pattern, int server, int parc,
			 char *parv[])
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
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
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

  /* assert(!IsServer(from)); SETTIME to particular destinations permitted */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_prio_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
		     parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
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
/** Finish registering a user who has sent both NICK and USER.
 * For local connections, possibly check IAuth; make sure there is a
 * matching Client config block; clean the username field; check
 * K/k-lines; check for "hacked" looking usernames; assign a numnick;
 * and send greeting (WELCOME, ISUPPORT, MOTD, etc).
 * For all connections, update the invisible user and operator counts;
 * run IPcheck against their address; and forward the NICK.
 *
 * @param[in] cptr Client who introduced the user.
 * @param[in,out] sptr Client who has been fully introduced.
 * @return Zero or CPTR_KILLED.
 */
int register_user(struct Client *cptr, struct Client *sptr)
{
  char*            parv[4];
  char*            tmpstr;
  struct User*     user = cli_user(sptr);
  char             ip_base64[25];

  user->last = CurrentTime;
  parv[0] = cli_name(sptr);
  parv[1] = parv[2] = NULL;

  if (MyConnect(sptr))
  {
    assert(cptr == sptr);

    Count_unknownbecomesclient(sptr, UserStats);

    /*
     * Set user's initial modes
     */
    tmpstr = (char*)client_get_default_umode(sptr);
    if (tmpstr) {
      char *umodev[] = { NULL, NULL, NULL, NULL };
      umodev[2] = tmpstr;
      set_user_mode(cptr, sptr, 3, umodev, ALLOWMODES_ANY);
    }

    SetUser(sptr);
    cli_handler(sptr) = CLIENT_HANDLER;
    SetLocalNumNick(sptr);
    send_reply(sptr,
               RPL_WELCOME,
               feature_str(FEAT_NETWORK),
               feature_str(FEAT_PROVIDER) ? " via " : "",
               feature_str(FEAT_PROVIDER) ? feature_str(FEAT_PROVIDER) : "",
               cli_name(sptr));
    /*
     * This is a duplicate of the NOTICE but see below...
     */
    send_reply(sptr, RPL_YOURHOST, cli_name(&me), version);
    send_reply(sptr, RPL_CREATED, creation);
    send_reply(sptr, RPL_MYINFO, cli_name(&me), version, infousermodes,
               infochanmodes, infochanmodeswithparams);
    send_supported(sptr);
    m_lusers(sptr, sptr, 1, parv);
    update_load();
    motd_signon(sptr);
    if (cli_snomask(sptr) & SNO_NOISY)
      set_snomask(sptr, cli_snomask(sptr) & SNO_NOISY, SNO_ADD);
    if (feature_bool(FEAT_CONNEXIT_NOTICES))
      sendto_opmask_butone(0, SNO_CONNEXIT,
                           "Client connecting: %s (%s@%s) [%s] {%s} [%s] <%s%s>",
                           cli_name(sptr), user->username, user->host,
                           cli_sock_ip(sptr), get_client_class(sptr),
                           cli_info(sptr), NumNick(cptr) /* two %s's */);

    IPcheck_connect_succeeded(sptr);
  }
  else {
    struct Client *acptr = user->server;

    if (cli_from(acptr) != cli_from(sptr))
    {
      sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s != %s[%s])",
                    sptr, cli_name(&me), cli_name(user->server), cli_name(cli_from(acptr)),
                    cli_sockhost(cli_from(acptr)));
      SetFlag(sptr, FLAG_KILLED);
      return exit_client(cptr, sptr, &me, "NICK server wrong direction");
    }
    else if (HasFlag(acptr, FLAG_TS8))
      SetFlag(sptr, FLAG_TS8);

    /*
     * Check to see if this user is being propagated
     * as part of a net.burst, or is using protocol 9.
     * FIXME: This can be sped up - its stupid to check it for
     * every NICK message in a burst again  --Run.
     */
    for (; acptr != &me; acptr = cli_serv(acptr)->up)
    {
      if (IsBurst(acptr) || Protocol(acptr) < 10)
        break;
    }
    if (!IPcheck_remote_connect(sptr, (acptr != &me)))
    {
      /*
       * We ran out of bits to count this
       */
      sendcmdto_one(&me, CMD_KILL, sptr, "%C :%s (Too many connections from your host -- Ghost)",
                    sptr, cli_name(&me));
      return exit_client(cptr, sptr, &me,"Too many connections from your host -- throttled");
    }
    SetUser(sptr);
  }

  /* If they get both +x and an account during registration, hide
   * their hostmask here.  Calling hide_hostmask() from IAuth's
   * account assignment causes a numeric reply during registration.
   */
  if (HasHiddenHost(sptr))
    hide_hostmask(sptr, FLAG_HIDDENHOST);
  if (IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (IsOper(sptr))
    ++UserStats.opers;

  tmpstr = umode_str(sptr);
  /* Send full IP address to IPv6-grokking servers. */
  sendcmdto_flag_serv_butone(user->server, CMD_NICK, cptr,
                             FLAG_IPV6, FLAG_LAST_FLAG,
                             "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                             cli_name(sptr), cli_hopcount(sptr) + 1,
                             cli_lastnick(sptr),
                             user->username, user->realhost,
                             *tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
                             iptobase64(ip_base64, &cli_ip(sptr), sizeof(ip_base64), 1),
                             NumNick(sptr), cli_info(sptr));
  /* Send fake IPv6 addresses to pre-IPv6 servers. */
  sendcmdto_flag_serv_butone(user->server, CMD_NICK, cptr,
                             FLAG_LAST_FLAG, FLAG_IPV6,
                             "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                             cli_name(sptr), cli_hopcount(sptr) + 1,
                             cli_lastnick(sptr),
                             user->username, user->realhost,
                             *tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
                             iptobase64(ip_base64, &cli_ip(sptr), sizeof(ip_base64), 0),
                             NumNick(sptr), cli_info(sptr));

  /* Send user mode to client */
  if (MyUser(sptr))
  {
    static struct Flags flags; /* automatically initialized to zeros */
    /* To avoid sending +r to the client due to auth-on-connect, set
     * the "old" FLAG_ACCOUNT bit to match the client's value.
     */
    if (IsAccount(cptr))
      FlagSet(&flags, FLAG_ACCOUNT);
    else
      FlagClr(&flags, FLAG_ACCOUNT);
    client_set_privs(sptr, NULL, 0);
    send_umode(cptr, sptr, &flags, ALL_UMODES);
    if ((cli_snomask(sptr) != SNO_DEFAULT) && HasFlag(sptr, FLAG_SERVNOTICE))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
  }
  return 0;
}

/** List of user mode characters. */
static const struct UserMode {
  unsigned int flag; /**< User mode constant. */
  char         c;    /**< Character corresponding to the mode. */
} userModeList[] = {
  { FLAG_OPER,        'o' },
  { FLAG_LOCOP,       'O' },
  { FLAG_INVISIBLE,   'i' },
  { FLAG_WALLOP,      'w' },
  { FLAG_SERVNOTICE,  's' },
  { FLAG_DEAF,        'd' },
  { FLAG_CHSERV,      'k' },
  { FLAG_DEBUG,       'g' },
  { FLAG_ACCOUNT,     'r' },
  { FLAG_HIDDENHOST,  'x' }
};

/** Length of #userModeList. */
#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)

/*
 * XXX - find a way to get rid of this
 */
/** Nasty global buffer used for communications with umode_str() and others. */
static char umodeBuf[BUFSIZE];

/** Try to set a user's nickname.
 * If \a sptr is a server, the client is being introduced for the first time.
 * @param[in] cptr Client to set nickname.
 * @param[in] sptr Client sending the NICK.
 * @param[in] nick New nickname.
 * @param[in] parc Number of arguments to NICK.
 * @param[in] parv Argument list to NICK.
 * @return CPTR_KILLED if \a cptr was killed, else 0.
 */
int set_nick_name(struct Client* cptr, struct Client* sptr,
                  const char* nick, int parc, char* parv[])
{
  if (IsServer(sptr)) {

    /*
     * A server introducing a new client, change source
     */
    struct Client* new_client = make_client(cptr, STAT_UNKNOWN);
    assert(0 != new_client);

    cli_hopcount(new_client) = atoi(parv[2]);
    cli_lastnick(new_client) = atoi(parv[3]);

    /*
     * Set new nick name.
     */
    strcpy(cli_name(new_client), nick);
    cli_user(new_client) = make_user(new_client);
    cli_user(new_client)->server = sptr;
    SetRemoteNumNick(new_client, parv[parc - 2]);
    /*
     * IP# of remote client
     */
    base64toip(parv[parc - 3], &cli_ip(new_client));

    add_client_to_list(new_client);
    hAddClient(new_client);

    cli_serv(sptr)->ghost = 0;        /* :server NICK means end of net.burst */
    ircd_strncpy(cli_username(new_client), parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->username, parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->host, parv[5], HOSTLEN);
    ircd_strncpy(cli_user(new_client)->realhost, parv[5], HOSTLEN);
    ircd_strncpy(cli_info(new_client), parv[parc - 1], REALLEN);

    Count_newremoteclient(UserStats, sptr);

    if (parc > 7 && *parv[6] == '+') {
      /* (parc-4) -3 for the ip, numeric nick, realname */
      set_user_mode(cptr, new_client, parc-7, parv+4, ALLOWMODES_ANY);
    }

    return register_user(cptr, new_client);
  }
  else if ((cli_name(sptr))[0]) {
    /*
     * Client changing its nick
     *
     * If the client belongs to me, then check to see
     * if client is on any channels where it is currently
     * banned.  If so, do not allow the nick change to occur.
     */
    if (MyUser(sptr)) {
      const char* channel_name;
      struct Membership *member;
      if ((channel_name = find_no_nickchange_channel(sptr))) {
        return send_reply(cptr, ERR_BANNICKCHANGE, channel_name);
      }
      /*
       * Refuse nick change if the last nick change was less
       * then 30 seconds ago. This is intended to get rid of
       * clone bots doing NICK FLOOD. -SeKs
       * If someone didn't change their nick for more then 60 seconds
       * however, allow to do two nick changes immediately after another
       * before limiting the nick flood. -Run
       */
      if (CurrentTime < cli_nextnick(cptr))
      {
        cli_nextnick(cptr) += 2;
        send_reply(cptr, ERR_NICKTOOFAST, parv[1],
                   cli_nextnick(cptr) - CurrentTime);
        /* Send error message */
        sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cli_name(cptr));
        /* bounce NICK to user */
        return 0;                /* ignore nick change! */
      }
      else {
        /* Limit total to 1 change per NICK_DELAY seconds: */
        cli_nextnick(cptr) += NICK_DELAY;
        /* However allow _maximal_ 1 extra consecutive nick change: */
        if (cli_nextnick(cptr) < CurrentTime)
          cli_nextnick(cptr) = CurrentTime;
      }
      /* Invalidate all bans against the user so we check them again */
      for (member = (cli_user(cptr))->channel; member;
	   member = member->next_channel)
	ClearBanValid(member);
    }
    /*
     * Also set 'lastnick' to current time, if changed.
     */
    if (0 != ircd_strcmp(parv[0], nick))
      cli_lastnick(sptr) = (sptr == cptr) ? TStime() : atoi(parv[2]);

    /*
     * Client just changing his/her nick. If he/she is
     * on a channel, send note of change to all clients
     * on that channel. Propagate notice to other servers.
     */
    if (IsUser(sptr)) {
      sendcmdto_common_channels_butone(sptr, CMD_NICK, NULL, ":%s", nick);
      add_history(sptr, 1);
      sendcmdto_serv_butone(sptr, CMD_NICK, cptr, "%s %Tu", nick,
                            cli_lastnick(sptr));
    }
    else
      sendcmdto_one(sptr, CMD_NICK, sptr, ":%s", nick);

    if ((cli_name(sptr))[0])
      hRemClient(sptr);
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);
  }
  else {
    /* Local client setting NICK the first time */
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);
    return auth_set_nick(cli_auth(sptr), nick);
  }
  return 0;
}

/** Calculate the hash value for a target.
 * @param[in] target Pointer to target, cast to unsigned int.
 * @return Hash value constructed from the pointer.
 */
static unsigned char hash_target(unsigned int target)
{
  return (unsigned char) (target >> 16) ^ (target >> 8);
}

/** Records \a target as a recent target for \a sptr.
 * @param[in] sptr User who has sent to a new target.
 * @param[in] target Target to add.
 */
void
add_target(struct Client *sptr, void *target)
{
  /* Ok, this shouldn't work esp on alpha
  */
  unsigned char  hash = hash_target((unsigned long) target);
  unsigned char* targets;
  int            i;
  assert(0 != sptr);
  assert(cli_local(sptr));

  targets = cli_targets(sptr);

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

/** Check whether \a sptr can send to or join \a target yet.
 * @param[in] sptr User trying to join a channel or send a message.
 * @param[in] target Target of the join or message.
 * @param[in] name Name of the target.
 * @param[in] created If non-zero, trying to join a new channel.
 * @return Non-zero if too many target changes; zero if okay to send.
 */
int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created)
{
  unsigned char hash = hash_target((unsigned long) target);
  int            i;
  unsigned char* targets;

  assert(0 != sptr);
  assert(cli_local(sptr));
  targets = cli_targets(sptr);

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
    if (CurrentTime < cli_nexttarget(sptr)) {
      /* If user is invited to channel, give him/her a free target */
      if (IsChannelName(name) && IsInvited(sptr, target))
        return 0;

      if (cli_nexttarget(sptr) - CurrentTime < TARGET_DELAY + 8) {
        /*
         * No server flooding
         */
        cli_nexttarget(sptr) += 2;
        send_reply(sptr, ERR_TARGETTOOFAST, name,
                   cli_nexttarget(sptr) - CurrentTime);
      }
      return 1;
    }
    else {
      cli_nexttarget(sptr) += TARGET_DELAY;
      if (cli_nexttarget(sptr) < CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1)))
        cli_nexttarget(sptr) = CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1));
    }
  }
  memmove(&targets[1], &targets[0], MAXTARGETS - 1);
  targets[0] = hash;
  return 0;
}

/** Allows a channel operator to avoid target change checks when
 * sending messages to users on their channel.
 * @param[in] source User sending the message.
 * @param[in] nick Destination of the message.
 * @param[in] channel Name of channel being sent to.
 * @param[in] text Message to send.
 * @param[in] is_notice If non-zero, use CNOTICE instead of CPRIVMSG.
 */
/* Added 971023 by Run. */
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
  for (membership = cli_user(source)->channel; membership; membership = membership->next_channel) {
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
  assert(0 != cli_user(dest));
  for (membership = cli_user(dest)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership || IsZombie(membership)) {
    return send_reply(source, ERR_USERNOTINCHANNEL, cli_name(dest), chptr->chname);
  }
  if (is_silenced(source, dest))
    return 0;
          
  if (is_notice)
    sendcmdto_one(source, CMD_NOTICE, dest, "%C :%s", dest, text);
  else
  {
    if (cli_user(dest)->away)
      send_reply(source, RPL_AWAY, cli_name(dest), cli_user(dest)->away);
    sendcmdto_one(source, CMD_PRIVATE, dest, "%C :%s", dest, text);
  }
  return 0;
}


/** Send a user mode change for \a cptr to neighboring servers.
 * @param[in] cptr User whose mode is changing.
 * @param[in] sptr Client who sent us the mode change message.
 * @param[in] old Prior set of user flags.
 * @param[in] prop If non-zero, also include FLAG_OPER.
 */
void send_umode_out(struct Client *cptr, struct Client *sptr,
                    struct Flags *old, int prop)
{
  int i;
  struct Client *acptr;

  send_umode(NULL, sptr, old, prop ? SEND_UMODES : SEND_UMODES_BUT_OPER);

  for (i = HighestFd; i >= 0; i--)
  {
    if ((acptr = LocalClientArray[i]) && IsServer(acptr) &&
        (acptr != cptr) && (acptr != sptr) && *umodeBuf)
      sendcmdto_one(sptr, CMD_MODE, acptr, "%s :%s", cli_name(sptr), umodeBuf);
  }
  if (cptr && MyUser(cptr))
    send_umode(cptr, sptr, old, ALL_UMODES);
}


/** Call \a fmt for each Client named in \a names.
 * @param[in] sptr Client requesting information.
 * @param[in] names Space-delimited list of nicknames.
 * @param[in] rpl Base reply string for messages.
 * @param[in] fmt Formatting callback function.
 */
void send_user_info(struct Client* sptr, char* names, int rpl, InfoFormatter fmt)
{
  char*          name;
  char*          p = 0;
  int            arg_count = 0;
  int            users_found = 0;
  struct Client* acptr;
  struct MsgBuf* mb;

  assert(0 != sptr);
  assert(0 != names);
  assert(0 != fmt);

  mb = msgq_make(sptr, rpl_str(rpl), cli_name(&me), cli_name(sptr));

  for (name = ircd_strtok(&p, names, " "); name; name = ircd_strtok(&p, 0, " ")) {
    if ((acptr = FindUser(name))) {
      if (users_found++)
	msgq_append(0, mb, " ");
      (*fmt)(acptr, sptr, mb);
    }
    if (5 == ++arg_count)
      break;
  }
  send_buffer(sptr, mb, 0);
  msgq_clean(mb);
}

/** Set \a flag on \a cptr and possibly hide the client's hostmask.
 * @param[in,out] cptr User who is getting a new flag.
 * @param[in] flag Some flag that affects host-hiding (FLAG_HIDDENHOST, FLAG_ACCOUNT).
 * @return Zero.
 */
int
hide_hostmask(struct Client *cptr, unsigned int flag)
{
  struct Membership *chan;

  switch (flag) {
  case FLAG_HIDDENHOST:
    /* Local users cannot set +x unless FEAT_HOST_HIDING is true. */
    if (MyConnect(cptr) && !feature_bool(FEAT_HOST_HIDING))
      return 0;
    break;
  case FLAG_ACCOUNT:
    /* Invalidate all bans against the user so we check them again */
    for (chan = (cli_user(cptr))->channel; chan;
         chan = chan->next_channel)
      ClearBanValid(chan);
    break;
  default:
    return 0;
  }

  SetFlag(cptr, flag);
  if (!HasFlag(cptr, FLAG_HIDDENHOST) || !HasFlag(cptr, FLAG_ACCOUNT))
    return 0;

  sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Registered");
  ircd_snprintf(0, cli_user(cptr)->host, HOSTLEN, "%s.%s",
                cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));

  /* ok, the client is now fully hidden, so let them know -- hikari */
  if (MyConnect(cptr))
   send_reply(cptr, RPL_HOSTHIDDEN, cli_user(cptr)->host);

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel)
  {
    if (IsZombie(chan))
      continue;
    /* Send a JOIN unless the user's join has been delayed. */
    if (!IsDelayedJoin(chan))
      sendcmdto_channel_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
                                         "%H", chan->channel);
    if (IsChanOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +ov %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsChanOp(chan) || HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
        "%H +%c %C", chan->channel, IsChanOp(chan) ? 'o' : 'v', cptr);
  }
  return 0;
}

/** Set a user's mode.  This function prevents local users from setting
 * unauthorized modes and applies any other side effects of
 * a successful mode change.
 *
 * @param[in] cptr Neighbor that sent the mode change message.
 * @param[in] sptr Source (originator) of the mode change.
 * @param[in] parc Number of parameters in \a parv.
 * @param[in] parv Parameters to MODE.
 * @param[in] allow_modes ALLOWMODES_ANY for any mode, ALLOWMODES_DEFAULT for 
 *                        only permitting legitimate default user modes.
 * @return Zero.
 */
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc, 
		char *parv[], int allow_modes)
{
  char** p;
  char*  m;
  int what;
  int i;
  struct Flags setflags;
  unsigned int tmpmask = 0;
  int snomask_given = 0;
  char buf[BUFSIZE];
  int prop = 0;
  int do_host_hiding = 0;
  char* account = NULL;

  what = MODE_ADD;

  if (parc < 3)
  {
    m = buf;
    *m++ = '+';
    for (i = 0; i < USERMODELIST_SIZE; i++)
    {
      if (HasFlag(sptr, userModeList[i].flag) &&
          userModeList[i].flag != FLAG_ACCOUNT)
        *m++ = userModeList[i].c;
    }
    *m = '\0';
    send_reply(sptr, RPL_UMODEIS, buf);
    if (HasFlag(sptr, FLAG_SERVNOTICE) && MyConnect(sptr)
        && cli_snomask(sptr) !=
        (unsigned int)(IsOper(sptr) ? SNO_OPERDEFAULT : SNO_DEFAULT))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    return 0;
  }

  /*
   * find flags already set for user
   * why not just copy them?
   */
  setflags = cli_flags(sptr);

  if (MyConnect(sptr))
    tmpmask = cli_snomask(sptr);

  /*
   * parse mode change string(s)
   */
  for (p = &parv[2]; *p && p<&parv[parc]; p++) {       /* p is changed in loop too */
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
	  SetServNotice(sptr);
        else
	  ClearServNotice(sptr);
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
          ClrFlag(sptr, FLAG_OPER);
          ClrFlag(sptr, FLAG_LOCOP);
          if (MyConnect(sptr))
            tmpmask = cli_snomask(sptr) & ~SNO_OPER;
        }
        break;
      case 'O':
        if (what == MODE_ADD)
          SetLocOp(sptr);
        else
        { 
          ClrFlag(sptr, FLAG_OPER);
          ClrFlag(sptr, FLAG_LOCOP);
          if (MyConnect(sptr))
            tmpmask = cli_snomask(sptr) & ~SNO_OPER;
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
      case 'x':
        if (what == MODE_ADD)
	  do_host_hiding = 1;
	break;
      case 'r':
	if (*(p + 1) && (what == MODE_ADD)) {
	  account = *(++p);
	  SetAccount(sptr);
	}
	/* There is no -r */
	break;
      default:
        send_reply(sptr, ERR_UMODEUNKNOWNFLAG, *m);
        break;
      }
    }
  }
  /*
   * Evaluate rules for new user mode
   * Stop users making themselves operators too easily:
   */
  if (!IsServer(cptr))
  {
    if (!FlagHas(&setflags, FLAG_OPER) && IsOper(sptr))
      ClearOper(sptr);
    if (!FlagHas(&setflags, FLAG_LOCOP) && IsLocOp(sptr))
      ClearLocOp(sptr);
    if (!FlagHas(&setflags, FLAG_ACCOUNT) && IsAccount(sptr))
      ClrFlag(sptr, FLAG_ACCOUNT);
    /*
     * new umode; servers can set it, local users cannot;
     * prevents users from /kick'ing or /mode -o'ing
     */
    if (!FlagHas(&setflags, FLAG_CHSERV))
      ClearChannelService(sptr);
    /*
     * only send wallops to opers
     */
    if (feature_bool(FEAT_WALLOPS_OPER_ONLY) && !IsAnOper(sptr) &&
	!FlagHas(&setflags, FLAG_WALLOP))
      ClearWallops(sptr);
    if (feature_bool(FEAT_HIS_SNOTICES_OPER_ONLY) && MyConnect(sptr) &&
        !IsAnOper(sptr) && !FlagHas(&setflags, FLAG_SERVNOTICE))
    {
      ClearServNotice(sptr);
      set_snomask(sptr, 0, SNO_SET);
    }
    if (feature_bool(FEAT_HIS_DEBUG_OPER_ONLY) &&
        !IsAnOper(sptr) && !FlagHas(&setflags, FLAG_DEBUG))
      ClearDebug(sptr);
  }
  if (MyConnect(sptr))
  {
    if ((FlagHas(&setflags, FLAG_OPER) || FlagHas(&setflags, FLAG_LOCOP)) &&
        !IsAnOper(sptr))
    {
      cli_handler(sptr) = CLIENT_HANDLER;
      det_confs_butmask(sptr, CONF_CLIENT & ~CONF_OPERATOR);
    }

    if (SendServNotice(sptr))
    {
      if (tmpmask != cli_snomask(sptr))
	set_snomask(sptr, tmpmask, SNO_SET);
      if (cli_snomask(sptr) && snomask_given)
	send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    }
    else
      set_snomask(sptr, 0, SNO_SET);
  }
  /*
   * Compare new flags with old flags and send string which
   * will cause servers to update correctly.
   */
  if (!FlagHas(&setflags, FLAG_ACCOUNT) && IsAccount(sptr)) {
      int len = ACCOUNTLEN;
      char *ts;
      if ((ts = strchr(account, ':'))) {
	len = (ts++) - account;
	cli_user(sptr)->acc_create = atoi(ts);
	Debug((DEBUG_DEBUG, "Received timestamped account in user mode; "
	      "account \"%s\", timestamp %Tu", account,
	      cli_user(sptr)->acc_create));
      }
      ircd_strncpy(cli_user(sptr)->account, account, len);
  }
  if (!FlagHas(&setflags, FLAG_HIDDENHOST) && do_host_hiding && allow_modes != ALLOWMODES_DEFAULT)
    hide_hostmask(sptr, FLAG_HIDDENHOST);

  if (IsRegistered(sptr)) {
    if (!FlagHas(&setflags, FLAG_OPER) && IsOper(sptr)) {
      /* user now oper */
      ++UserStats.opers;
      client_set_privs(sptr, NULL, 0); /* may set propagate privilege */
    }
    /* remember propagate privilege setting */
    if (HasPriv(sptr, PRIV_PROPAGATE)) {
      prop = 1;
    }
    if ((FlagHas(&setflags, FLAG_OPER) || FlagHas(&setflags, FLAG_LOCOP))
        && !IsAnOper(sptr)) {
      if (FlagHas(&setflags, FLAG_OPER)) {
        /* user no longer (global) oper */
        assert(UserStats.opers > 0);
        --UserStats.opers;
      }
      client_set_privs(sptr, NULL, 0); /* will clear propagate privilege */
    }
    if (FlagHas(&setflags, FLAG_INVISIBLE) && !IsInvisible(sptr)) {
      assert(UserStats.inv_clients > 0);
      --UserStats.inv_clients;
    }
    if (!FlagHas(&setflags, FLAG_INVISIBLE) && IsInvisible(sptr)) {
      ++UserStats.inv_clients;
    }
    assert(UserStats.opers <= UserStats.clients + UserStats.unknowns);
    assert(UserStats.inv_clients <= UserStats.clients + UserStats.unknowns);
    send_umode_out(cptr, sptr, &setflags, prop);
  }

  return 0;
}

/** Build a mode string to describe modes for \a cptr.
 * @param[in] cptr Some user.
 * @return Pointer to a static buffer.
 */
char *umode_str(struct Client *cptr)
{
  /* Maximum string size: "owidgrx\0" */
  char *m = umodeBuf;
  int i;
  struct Flags c_flags = cli_flags(cptr);

  if (!HasPriv(cptr, PRIV_PROPAGATE))
    FlagClr(&c_flags, FLAG_OPER);

  for (i = 0; i < USERMODELIST_SIZE; ++i)
  {
    if (FlagHas(&c_flags, userModeList[i].flag) &&
        userModeList[i].flag >= FLAG_GLOBAL_UMODES)
      *m++ = userModeList[i].c;
  }

  if (IsAccount(cptr))
  {
    char* t = cli_user(cptr)->account;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */

    if (cli_user(cptr)->acc_create) {
      char nbuf[20];
      Debug((DEBUG_DEBUG, "Sending timestamped account in user mode for "
	     "account \"%s\"; timestamp %Tu", cli_user(cptr)->account,
	     cli_user(cptr)->acc_create));
      ircd_snprintf(0, t = nbuf, sizeof(nbuf), ":%Tu",
		    cli_user(cptr)->acc_create);
      m--; /* back up over previous nul-termination */
      while ((*m++ = *t++))
	; /* Empty loop */
    }
  }

  *m = '\0';

  return umodeBuf;                /* Note: static buffer, gets
                                   overwritten by send_umode() */
}

/** Send a mode change string for \a sptr to \a cptr.
 * @param[in] cptr Destination of mode change message.
 * @param[in] sptr User whose mode has changed.
 * @param[in] old Pre-change set of modes for \a sptr.
 * @param[in] sendset One of ALL_UMODES, SEND_UMODES_BUT_OPER,
 * SEND_UMODES, to select which changed user modes to send.
 */
void send_umode(struct Client *cptr, struct Client *sptr, struct Flags *old,
                int sendset)
{
  int i;
  int flag;
  char *m;
  int what = MODE_NULL;

  /*
   * Build a string in umodeBuf to represent the change in the user's
   * mode between the new (cli_flags(sptr)) and 'old', but skipping
   * the modes indicated by sendset.
   */
  m = umodeBuf;
  *m = '\0';
  for (i = 0; i < USERMODELIST_SIZE; ++i)
  {
    flag = userModeList[i].flag;
    if (FlagHas(old, flag)
        == HasFlag(sptr, flag))
      continue;
    switch (sendset)
    {
    case ALL_UMODES:
      break;
    case SEND_UMODES_BUT_OPER:
      if (flag == FLAG_OPER)
        continue;
      /* and fall through */
    case SEND_UMODES:
      if (flag < FLAG_GLOBAL_UMODES)
        continue;
      break;      
    }
    if (FlagHas(old, flag))
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
    else /* !FlagHas(old, flag) */
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
    sendcmdto_one(sptr, CMD_MODE, cptr, "%s :%s", cli_name(sptr), umodeBuf);
}

/**
 * Check to see if this resembles a sno_mask.  It is if 1) there is
 * at least one digit and 2) The first digit occurs before the first
 * alphabetic character.
 * @param[in] word Word to check for sno_mask-ness.
 * @return Non-zero if \a word looks like a server notice mask; zero if not.
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

/** Update snomask \a oldmask according to \a arg and \a what.
 * @param[in] oldmask Original user mask.
 * @param[in] arg Update string (either a number or '+'/'-' followed by a number).
 * @param[in] what MODE_ADD if adding the mask.
 * @return New value of service notice mask.
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

/** Remove \a cptr from the singly linked list \a list.
 * @param[in] cptr Client to remove from list.
 * @param[in,out] list Pointer to head of list containing \a cptr.
 */
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

/** Set \a cptr's server notice mask, according to \a what.
 * @param[in,out] cptr Client whose snomask is updating.
 * @param[in] newmask Base value for new snomask.
 * @param[in] what One of SNO_ADD, SNO_DEL, SNO_SET, to choose operation.
 */
void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  unsigned int oldmask, diffmask;        /* unsigned please */
  int i;
  struct SLink *tmp;

  oldmask = cli_snomask(cptr);

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
  cli_snomask(cptr) = newmask;
}

/** Check whether \a sptr is allowed to send a message to \a acptr.
 * If \a sptr is a remote user, it means some server has an outdated
 * SILENCE list for \a acptr, so send the missing SILENCE mask(s) back
 * in the direction of \a sptr.  Skip the check if \a sptr is a server.
 * @param[in] sptr Client trying to send a message.
 * @param[in] acptr Destination of message.
 * @return Non-zero if \a sptr is SILENCEd by \a acptr, zero if not.
 */
int is_silenced(struct Client *sptr, struct Client *acptr)
{
  struct Ban *found;
  struct User *user;
  size_t buf_used, slen;
  char buf[BUFSIZE];

  if (IsServer(sptr) || !(user = cli_user(acptr))
      || !(found = find_ban(sptr, user->silence)))
    return 0;
  assert(!(found->flags & BAN_EXCEPTION));
  if (!MyConnect(sptr)) {
    /* Buffer positive silence to send back. */
    buf_used = strlen(found->banstr);
    memcpy(buf, found->banstr, buf_used);
    /* Add exceptions to buffer. */
    for (found = user->silence; found; found = found->next) {
      if (!(found->flags & BAN_EXCEPTION))
        continue;
      slen = strlen(found->banstr);
      if (buf_used + slen + 4 > 400) {
        buf[buf_used] = '\0';
        sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr, buf);
        buf_used = 0;
      }
      if (buf_used)
        buf[buf_used++] = ',';
      buf[buf_used++] = '+';
      buf[buf_used++] = '~';
      memcpy(buf + buf_used, found->banstr, slen);
      buf_used += slen;
    }
    /* Flush silence buffer. */
    if (buf_used) {
      buf[buf_used] = '\0';
      sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr, buf);
      buf_used = 0;
    }
  }
  return 1;
}

/** Send RPL_ISUPPORT lines to \a cptr.
 * @param[in] cptr Client to send ISUPPORT to.
 * @return Zero.
 */
int
send_supported(struct Client *cptr)
{
  char featurebuf[512];

  ircd_snprintf(0, featurebuf, sizeof(featurebuf), FEATURES1, FEATURESVALUES1);
  send_reply(cptr, RPL_ISUPPORT, featurebuf);
  ircd_snprintf(0, featurebuf, sizeof(featurebuf), FEATURES2, FEATURESVALUES2);
  send_reply(cptr, RPL_ISUPPORT, featurebuf);

  return 0; /* convenience return, if it's ever needed */
}

/* vim: shiftwidth=2 
 */ 
