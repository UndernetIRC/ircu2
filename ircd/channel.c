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
 *
 * $Id$
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"
#include "whowas.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Channel* GlobalChannelList = 0;

static unsigned int membershipAllocCount;
static struct Membership* membershipFreeList;

void del_invite(struct Client *, struct Channel *);

const char* const PartFmt1     = ":%s " MSG_PART " %s";
const char* const PartFmt2     = ":%s " MSG_PART " %s :%s";
const char* const PartFmt1serv = "%s%s " TOK_PART " %s";
const char* const PartFmt2serv = "%s%s " TOK_PART " %s :%s";


static struct SLink* next_ban;
static struct SLink* prev_ban;
static struct SLink* removed_bans_list;

/*
 * Use a global variable to remember if an oper set a mode on a local channel. Ugly,
 * but the only way to do it without changing set_mode intensively.
 */
int LocalChanOperMode = 0;

#if !defined(NDEBUG)
/*
 * return the length (>=0) of a chain of links.
 */
static int list_length(struct SLink *lp)
{
  int count = 0;

  for (; lp; lp = lp->next)
    ++count;
  return count;
}
#endif

struct Membership* find_member_link(struct Channel* chptr, const struct Client* cptr)
{
  struct Membership *m;
  assert(0 != cptr);
  assert(0 != chptr);
  
  /* Servers don't have member links */
  if (IsServer(cptr)||IsMe(cptr))
     return 0;
  
  /* +k users are typically on a LOT of channels.  So we iterate over who
   * is in the channel.  X/W are +k and are in about 5800 channels each.
   * however there are typically no more than 1000 people in a channel
   * at a time.
   */
  if (IsChannelService(cptr)) {
    m = chptr->members;
    while (m) {
      assert(m->channel == chptr);
      if (m->user == cptr)
        return m;
      m = m->next_member;
    }
  }
  /* Users on the other hand aren't allowed on more than 15 channels.  50%
   * of users that are on channels are on 2 or less, 95% are on 7 or less,
   * and 99% are on 10 or less.
   */
  else {
   m = (cli_user(cptr))->channel;
   while (m) {
     assert(m->user == cptr);
     if (m->channel == chptr)
       return m;
     m = m->next_channel;
   }
  }
  return 0;
}

/*
 * find_chasing - Find the client structure for a nick name (user)
 * using history mechanism if necessary. If the client is not found, an error
 * message (NO SUCH NICK) is generated. If the client was found
 * through the history, chasing will be 1 and otherwise 0.
 */
struct Client* find_chasing(struct Client* sptr, const char* user, int* chasing)
{
  struct Client* who = FindClient(user);

  if (chasing)
    *chasing = 0;
  if (who)
    return who;

  if (!(who = get_history(user, feature_int(FEAT_KILLCHASETIMELIMIT)))) {
    send_reply(sptr, ERR_NOSUCHNICK, user);
    return 0;
  }
  if (chasing)
    *chasing = 1;
  return who;
}

/*
 * Create a string of form "foo!bar@fubar" given foo, bar and fubar
 * as the parameters.  If NULL, they become "*".
 */
#define NUH_BUFSIZE	(NICKLEN + USERLEN + HOSTLEN + 3)
static char *make_nick_user_host(char *namebuf, const char *nick,
				 const char *name, const char *host)
{
  ircd_snprintf(0, namebuf, NUH_BUFSIZE, "%s!%s@%s", nick, name, host);
  return namebuf;
}

/*
 * Create a string of form "foo!bar@123.456.789.123" given foo, bar and the
 * IP-number as the parameters.  If NULL, they become "*".
 */
#define NUI_BUFSIZE	(NICKLEN + USERLEN + 16 + 3)
static char *make_nick_user_ip(char *ipbuf, char *nick, char *name,
			       struct in_addr ip)
{
  ircd_snprintf(0, ipbuf, NUI_BUFSIZE, "%s!%s@%s", nick, name,
		ircd_ntoa((const char*) &ip));
  return ipbuf;
}

/*
 * Subtract one user from channel i (and free channel
 * block, if channel became empty).
 * Returns: true  (1) if channel still exists
 *          false (0) if the channel was destroyed
 */
int sub1_from_channel(struct Channel* chptr)
{
  struct SLink *tmp;
  struct SLink *obtmp;

  if (chptr->users > 1)         /* Can be 0, called for an empty channel too */
  {
    assert(0 != chptr->members);
    --chptr->users;
    return 1;
  }

  assert(0 == chptr->members);

  /* Channel became (or was) empty: Remove channel */
  if (is_listed(chptr))
  {
    int i;
    for (i = 0; i <= HighestFd; i++)
    {
      struct Client *acptr = 0;
      if ((acptr = LocalClientArray[i]) && cli_listing(acptr) &&
          (cli_listing(acptr))->chptr == chptr)
      {
        list_next_channels(acptr, 1);
        break;                  /* Only one client can list a channel */
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
    MyFree(obtmp->value.ban.banstr);
    MyFree(obtmp->value.ban.who);
    free_link(obtmp);
  }
  if (chptr->prev)
    chptr->prev->next = chptr->next;
  else
    GlobalChannelList = chptr->next;
  if (chptr->next)
    chptr->next->prev = chptr->prev;
  hRemChannel(chptr);
  --UserStats.channels;
  /*
   * make sure that channel actually got removed from hash table
   */
  assert(chptr->hnext == chptr);
  MyFree(chptr);
  return 0;
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
int add_banid(struct Client *cptr, struct Channel *chptr, char *banid,
                     int change, int firsttime)
{
  struct SLink*  ban;
  struct SLink** banp;
  int            cnt = 0;
  int            removed_bans = 0;
  int            len = strlen(banid);

  if (firsttime)
  {
    next_ban = NULL;
    assert(0 == prev_ban);
    assert(0 == removed_bans_list);
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
      struct SLink *tmp = *banp;
      if (change)
      {
        if (MyUser(cptr))
        {
          cnt--;
          len -= strlen(tmp->value.ban.banstr);
        }
        *banp = tmp->next;
        /* These will be sent to the user later as -b */
        tmp->next = removed_bans_list;
        removed_bans_list = tmp;
        removed_bans = 1;
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
  if (MyUser(cptr) && !removed_bans &&
      (len > (feature_int(FEAT_AVBANLEN) * feature_int(FEAT_MAXBANS)) ||
       (cnt >= feature_int(FEAT_MAXBANS))))
  {
    send_reply(cptr, ERR_BANLISTFULL, chptr->chname, banid);
    return -1;
  }
  if (change)
  {
    char*              ip_start;
    struct Membership* member;
    ban = make_link();
    ban->next = chptr->banlist;

    ban->value.ban.banstr = (char*) MyMalloc(strlen(banid) + 1);
    assert(0 != ban->value.ban.banstr);
    strcpy(ban->value.ban.banstr, banid);

    if (feature_bool(FEAT_HIS_BANWHO) && IsServer(cptr))
      DupString(ban->value.ban.who, cli_name(&me));
    else
      DupString(ban->value.ban.who, cli_name(cptr));
    assert(0 != ban->value.ban.who);

    ban->value.ban.when = TStime();
    ban->flags = CHFL_BAN;      /* This bit is never used I think... */
    if ((ip_start = strrchr(banid, '@')) && check_if_ipmask(ip_start + 1))
      ban->flags |= CHFL_BAN_IPMASK;
    chptr->banlist = ban;

    /*
     * Erase ban-valid-bit
     */
    for (member = chptr->members; member; member = member->next_member)
      ClearBanValid(member);     /* `ban' == channel member ! */
  }
  return 0;
}

struct SLink *next_removed_overlapped_ban(void)
{
  struct SLink *tmp = removed_bans_list;
  if (prev_ban)
  {
    if (prev_ban->value.ban.banstr)     /* Can be set to NULL in set_mode() */
      MyFree(prev_ban->value.ban.banstr);
    MyFree(prev_ban->value.ban.who);
    free_link(prev_ban);
    prev_ban = 0;
  }
  if (tmp)
    removed_bans_list = removed_bans_list->next;
  prev_ban = tmp;
  return tmp;
}

/*
 * find_channel_member - returns Membership * if a person is joined and not a zombie
 */
struct Membership* find_channel_member(struct Client* cptr, struct Channel* chptr)
{
  struct Membership* member;
  assert(0 != chptr);

  member = find_member_link(chptr, cptr);
  return (member && !IsZombie(member)) ? member : 0;
}

/*
 * is_banned - a non-zero value if banned else 0.
 */
static int is_banned(struct Client *cptr, struct Channel *chptr,
                     struct Membership* member)
{
  struct SLink* tmp;
  char          tmphost[HOSTLEN + 1];
  char          nu_host[NUH_BUFSIZE];
  char          nu_realhost[NUH_BUFSIZE];
  char          nu_ip[NUI_BUFSIZE];
  char*         s;
  char*         sr = NULL;
  char*         ip_s = NULL;

  if (!IsUser(cptr))
    return 0;

  if (member && IsBanValid(member))
    return IsBanned(member);

  s = make_nick_user_host(nu_host, cli_name(cptr), (cli_user(cptr))->username,
			  (cli_user(cptr))->host);

  if (IsAccount(cptr)) {
     if (HasHiddenHost(cptr))
        sr = make_nick_user_host(nu_realhost, cli_name(cptr),
                                cli_user(cptr)->username,
                                cli_user(cptr)->realhost);
     else {
        ircd_snprintf(0, tmphost, HOSTLEN, "%s.%s",
                      cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));
        sr = make_nick_user_host(nu_realhost, cli_name(cptr),
                                 cli_user(cptr)->username,
                                 tmphost);
     }
  }

  for (tmp = chptr->banlist; tmp; tmp = tmp->next) {
    if ((tmp->flags & CHFL_BAN_IPMASK)) {
      if (!ip_s)
        ip_s = make_nick_user_ip(nu_ip, cli_name(cptr),
				 (cli_user(cptr))->username, cli_ip(cptr));
      if (match(tmp->value.ban.banstr, ip_s) == 0)
        break;
    }
    else if (match(tmp->value.ban.banstr, s) == 0)
      break;
    else if (sr && match(tmp->value.ban.banstr, sr) == 0)
      break;
  }

  if (member) {
    SetBanValid(member);
    if (tmp) {
      SetBanned(member);
      return 1;
    }
    else {
      ClearBanned(member);
      return 0;
    }
  }

  return (tmp != NULL);
}

/*
 * adds a user to a channel by adding another link to the channels member
 * chain.
 */
void add_user_to_channel(struct Channel* chptr, struct Client* who,
                                unsigned int flags)
{
  assert(0 != chptr);
  assert(0 != who);

  if (cli_user(who)) {
   
    struct Membership* member = membershipFreeList;
    if (member)
      membershipFreeList = member->next_member;
    else {
      member = (struct Membership*) MyMalloc(sizeof(struct Membership));
      ++membershipAllocCount;
    }

    assert(0 != member);
    member->user         = who;
    member->channel      = chptr;
    member->status       = flags;

    member->next_member  = chptr->members;
    if (member->next_member)
      member->next_member->prev_member = member;
    member->prev_member  = 0; 
    chptr->members       = member;

    member->next_channel = (cli_user(who))->channel;
    if (member->next_channel)
      member->next_channel->prev_channel = member;
    member->prev_channel = 0;
    (cli_user(who))->channel = member;

    ++chptr->users;
    ++((cli_user(who))->joined);
  }
}

static int remove_member_from_channel(struct Membership* member)
{
  struct Channel* chptr;
  assert(0 != member);
  chptr = member->channel;
  /*
   * unlink channel member list
   */
  if (member->next_member)
    member->next_member->prev_member = member->prev_member;
  if (member->prev_member)
    member->prev_member->next_member = member->next_member;
  else
    member->channel->members = member->next_member; 
      
  /*
   * unlink client channel list
   */
  if (member->next_channel)
    member->next_channel->prev_channel = member->prev_channel;
  if (member->prev_channel)
    member->prev_channel->next_channel = member->next_channel;
  else
    (cli_user(member->user))->channel = member->next_channel;

  --(cli_user(member->user))->joined;

  member->next_member = membershipFreeList;
  membershipFreeList = member;

  return sub1_from_channel(chptr);
}

static int channel_all_zombies(struct Channel* chptr)
{
  struct Membership* member;

  for (member = chptr->members; member; member = member->next_member) {
    if (!IsZombie(member))
      return 0;
  }
  return 1;
}
      

void remove_user_from_channel(struct Client* cptr, struct Channel* chptr)
{
  
  struct Membership* member;
  assert(0 != chptr);

  if ((member = find_member_link(chptr, cptr))) {
    if (remove_member_from_channel(member)) {
      if (channel_all_zombies(chptr)) {
        /*
         * XXX - this looks dangerous but isn't if we got the referential
         * integrity right for channels
         */
        while (remove_member_from_channel(chptr->members))
          ;
      }
    }
  }
}

void remove_user_from_all_channels(struct Client* cptr)
{
  struct Membership* chan;
  assert(0 != cptr);
  assert(0 != cli_user(cptr));

  while ((chan = (cli_user(cptr))->channel))
    remove_user_from_channel(cptr, chan->channel);
}

int is_chan_op(struct Client *cptr, struct Channel *chptr)
{
  struct Membership* member;
  assert(chptr);
  if ((member = find_member_link(chptr, cptr)))
    return (!IsZombie(member) && IsChanOp(member));

  return 0;
}

int is_zombie(struct Client *cptr, struct Channel *chptr)
{
  struct Membership* member;

  assert(0 != chptr);

  if ((member = find_member_link(chptr, cptr)))
      return IsZombie(member);
  return 0;
}

int has_voice(struct Client* cptr, struct Channel* chptr)
{
  struct Membership* member;

  assert(0 != chptr);
  if ((member = find_member_link(chptr, cptr)))
    return (!IsZombie(member) && HasVoice(member));

  return 0;
}

int member_can_send_to_channel(struct Membership* member)
{
  assert(0 != member);

  if (IsVoicedOrOpped(member))
    return 1;
  /*
   * If it's moderated, and you aren't a priviledged user, you can't
   * speak.  
   */
  if (member->channel->mode.mode & MODE_MODERATED)
    return 0;
  /*
   * If you're banned then you can't speak either.
   * but because of the amount of CPU time that is_banned chews
   * we only check it for our clients.
   */
  if (MyUser(member->user) && is_banned(member->user, member->channel, member))
    return 0;
  return 1;
}

int client_can_send_to_channel(struct Client *cptr, struct Channel *chptr)
{
  struct Membership *member;
  assert(0 != cptr); 
  /*
   * Servers can always speak on channels.
   */
  if (IsServer(cptr))
    return 1;

  member = find_channel_member(cptr, chptr);

  /* You can't speak if your off channel and +n (no external messages) or +m (moderated). */
  if (!member) {
    if ((chptr->mode.mode & (MODE_NOPRIVMSGS|MODE_MODERATED)) ||
	((chptr->mode.mode & MODE_REGONLY) && !IsAccount(cptr)))
      return 0;
    else
      return !is_banned(cptr, chptr, NULL);
  }
  return member_can_send_to_channel(member); 
}

/*
 * find_no_nickchange_channel
 * if a member and not opped or voiced and banned
 * return the name of the first channel banned on
 */
const char* find_no_nickchange_channel(struct Client* cptr)
{
  if (MyUser(cptr)) {
    struct Membership* member;
    for (member = (cli_user(cptr))->channel; member;
	 member = member->next_channel) {
      if (!IsVoicedOrOpped(member) && is_banned(cptr, member->channel, member))
        return member->channel->chname;
    }
  }
  return 0;
}


/*
 * write the "simple" list of channel modes for channel chptr onto buffer mbuf
 * with the parameters in pbuf.
 */
void channel_modes(struct Client *cptr, char *mbuf, char *pbuf, int buflen,
                          struct Channel *chptr)
{
  assert(0 != mbuf);
  assert(0 != pbuf);
  assert(0 != chptr);

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
  if (chptr->mode.mode & MODE_REGONLY)
    *mbuf++ = 'r';
  if (chptr->mode.limit) {
    *mbuf++ = 'l';
    ircd_snprintf(0, pbuf, buflen, "%u", chptr->mode.limit);
  }

  if (*chptr->mode.key) {
    *mbuf++ = 'k';
    if (chptr->mode.limit)
      strcat(pbuf, " ");
    if (is_chan_op(cptr, chptr) || IsServer(cptr)) {
      strcat(pbuf, chptr->mode.key);
    } else
      strcat(pbuf, "*");
  }
  *mbuf = '\0';
}

/*
 * send "cptr" a full list of the modes for channel chptr.
 */
void send_channel_modes(struct Client *cptr, struct Channel *chptr)
{
  static unsigned int current_flags[4] =
      { 0, CHFL_CHANOP | CHFL_VOICE, CHFL_VOICE, CHFL_CHANOP };
  int                first = 1;
  int                full  = 1;
  int                flag_cnt = 0;
  int                new_mode = 0;
  size_t             len;
  struct Membership* member;
  struct SLink*      lp2;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  struct MsgBuf *mb;

  assert(0 != cptr);
  assert(0 != chptr); 

  if (IsLocalChannel(chptr->chname))
    return;

  member = chptr->members;
  lp2 = chptr->banlist;

  *modebuf = *parabuf = '\0';
  channel_modes(cptr, modebuf, parabuf, sizeof(parabuf), chptr);

  for (first = 1; full; first = 0)      /* Loop for multiple messages */
  {
    full = 0;                   /* Assume by default we get it
                                 all in one message */

    /* (Continued) prefix: "<Y> B <channel> <TS>" */
    /* is there any better way we can do this? */
    mb = msgq_make(&me, "%C " TOK_BURST " %H %Tu", &me, chptr,
		   chptr->creationtime);

    if (first && modebuf[1])    /* Add simple modes (iklmnpst)
                                 if first message */
    {
      /* prefix: "<Y> B <channel> <TS>[ <modes>[ <params>]]" */
      msgq_append(&me, mb, " %s", modebuf);

      if (*parabuf)
	msgq_append(&me, mb, " %s", parabuf);
    }

    /*
     * Attach nicks, comma seperated " nick[:modes],nick[:modes],..."
     *
     * Run 4 times over all members, to group the members with the
     * same mode together
     */
    for (first = 1; flag_cnt < 4;
         member = chptr->members, new_mode = 1, flag_cnt++)
    {
      for (; member; member = member->next_member)
      {
        if ((member->status & CHFL_VOICED_OR_OPPED) !=
            current_flags[flag_cnt])
          continue;             /* Skip members with different flags */
	if (msgq_bufleft(mb) < NUMNICKLEN + 4)
          /* The 4 is a possible ",:ov" */
        {
          full = 1;           /* Make sure we continue after
                                 sending it so far */
          new_mode = 1;       /* Ensure the new BURST line contains the current
                                 mode. --Gte */
          break;              /* Do not add this member to this message */
        }
	msgq_append(&me, mb, "%c%C", first ? ' ' : ',', member->user);
        first = 0;              /* From now on, us comma's to add new nicks */

        /*
         * Do we have a nick with a new mode ?
         * Or are we starting a new BURST line?
         */
        if (new_mode)
        {
          new_mode = 0;
          if (IsVoicedOrOpped(member)) {
	    char tbuf[4] = ":";
	    int loc = 1;

            if (IsChanOp(member))
	      tbuf[loc++] = 'o';
            if (HasVoice(member))
	      tbuf[loc++] = 'v';
	    tbuf[loc] = '\0';
	    msgq_append(&me, mb, tbuf);
          }
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
	if (msgq_bufleft(mb) < len + 1 + first)
          /* The +1 stands for the added ' '.
           * The +first stands for the added ":%".
           */
        {
          full = 1;
          break;
        }
	msgq_append(&me, mb, " %s%s", first ? ":%" : "",
		    lp2->value.ban.banstr);
	first = 0;
      }
    }

    send_buffer(cptr, mb, 0);  /* Send this message */
    msgq_clean(mb);
  }                             /* Continue when there was something
                                 that didn't fit (full==1) */
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
  static char retmask[NUH_BUFSIZE];
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
  return make_nick_user_host(retmask, nick, user, host);
}

static void send_ban_list(struct Client* cptr, struct Channel* chptr)
{
  struct SLink* lp;

  assert(0 != cptr);
  assert(0 != chptr);

  for (lp = chptr->banlist; lp; lp = lp->next)
    send_reply(cptr, RPL_BANLIST, chptr->chname, lp->value.ban.banstr,
	       lp->value.ban.who, lp->value.ban.when);

  send_reply(cptr, RPL_ENDOFBANLIST, chptr->chname);
}

/* We are now treating the <key> part of /join <channel list> <key> as a key
 * ring; that is, we try one key against the actual channel key, and if that
 * doesn't work, we try the next one, and so on. -Kev -Texaco
 * Returns: 0 on match, 1 otherwise
 * This version contributed by SeKs <intru@info.polymtl.ca>
 */
static int compall(char *key, char *keyring)
{
  char *p1;

top:
  p1 = key;                     /* point to the key... */
  while (*p1 && *p1 == *keyring)
  {                             /* step through the key and ring until they
                                   don't match... */
    p1++;
    keyring++;
  }

  if (!*p1 && (!*keyring || *keyring == ','))
    /* ok, if we're at the end of the and also at the end of one of the keys
       in the keyring, we have a match */
    return 0;

  if (!*keyring)                /* if we're at the end of the key ring, there
                                   weren't any matches, so we return 1 */
    return 1;

  /* Not at the end of the key ring, so step
     through to the next key in the ring: */
  while (*keyring && *(keyring++) != ',');

  goto top;                     /* and check it against the key */
}

int can_join(struct Client *sptr, struct Channel *chptr, char *key)
{
  int overrideJoin = 0;  
  
  /*
   * Now a banned user CAN join if invited -- Nemesi
   * Now a user CAN escape channel limit if invited -- bfriendly
   * Now a user CAN escape anything if invited -- Isomer
   */

  if(IsInvited(sptr, chptr))
    return 0;
  
  /* An oper can force a join on a local channel using "OVERRIDE" as the key. 
     a HACK(4) notice will be sent if he would not have been supposed
     to join normally. */ 
  if (IsLocalChannel(chptr->chname) && HasPriv(sptr, PRIV_WALK_LCHAN) &&
      !BadPtr(key) && compall("OVERRIDE",key) == 0
      && compall("OVERRIDE",chptr->mode.key) != 0)
    overrideJoin = MAGIC_OPER_OVERRIDE;

  if (chptr->mode.mode & MODE_INVITEONLY)
  	return overrideJoin + ERR_INVITEONLYCHAN;
  	
  if (chptr->mode.limit && chptr->users >= chptr->mode.limit)
  	return overrideJoin + ERR_CHANNELISFULL;

  if ((chptr->mode.mode & MODE_REGONLY) && !IsAccount(sptr))
  	return overrideJoin + ERR_NEEDREGGEDNICK;
  	
  if (is_banned(sptr, chptr, NULL))
  	return overrideJoin + ERR_BANNEDFROMCHAN;
  
  /*
   * now using compall (above) to test against a whole key ring -Kev
   */
  if (*chptr->mode.key && (EmptyString(key) || compall(chptr->mode.key, key)))
    return overrideJoin + ERR_BADCHANNELKEY;

  if (overrideJoin) 	
  	return ERR_DONTCHEAT;
  	
  return 0;
}

/*
 * Remove bells and commas from channel name
 */
void clean_channelname(char *cn)
{
  int i;

  for (i = 0; cn[i]; i++) {
    if (i >= CHANNELLEN || !IsChannelChar(cn[i])) {
      cn[i] = '\0';
      return;
    }
    if (IsChannelLower(cn[i])) {
      cn[i] = ToLower(cn[i]);
#ifndef FIXME
      /*
       * Remove for .08+
       * toupper(0xd0)
       */
      if ((unsigned char)(cn[i]) == 0xd0)
        cn[i] = (char) 0xf0;
#endif
    }
  }
}

/*
 *  Get Channel block for i (and allocate a new channel
 *  block, if it didn't exists before).
 */
struct Channel *get_channel(struct Client *cptr, char *chname, ChannelGetType flag)
{
  struct Channel *chptr;
  int len;

  if (EmptyString(chname))
    return NULL;

  len = strlen(chname);
  if (MyUser(cptr) && len > CHANNELLEN)
  {
    len = CHANNELLEN;
    *(chname + CHANNELLEN) = '\0';
  }
  if ((chptr = FindChannel(chname)))
    return (chptr);
  if (flag == CGT_CREATE)
  {
    chptr = (struct Channel*) MyMalloc(sizeof(struct Channel) + len);
    assert(0 != chptr);
    ++UserStats.channels;
    memset(chptr, 0, sizeof(struct Channel));
    strcpy(chptr->chname, chname);
    if (GlobalChannelList)
      GlobalChannelList->prev = chptr;
    chptr->prev = NULL;
    chptr->next = GlobalChannelList;
    chptr->creationtime = MyUser(cptr) ? TStime() : (time_t) 0;
    GlobalChannelList = chptr;
    hAddChannel(chptr);
  }
  return chptr;
}

void add_invite(struct Client *cptr, struct Channel *chptr)
{
  struct SLink *inv, **tmp;

  del_invite(cptr, chptr);
  /*
   * Delete last link in chain if the list is max length
   */
  assert(list_length((cli_user(cptr))->invited) == (cli_user(cptr))->invites);
  if ((cli_user(cptr))->invites >= feature_int(FEAT_MAXCHANNELSPERUSER))
    del_invite(cptr, (cli_user(cptr))->invited->value.chptr);
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
  for (tmp = &((cli_user(cptr))->invited); *tmp; tmp = &((*tmp)->next));
  inv = make_link();
  inv->value.chptr = chptr;
  inv->next = NULL;
  (*tmp) = inv;
  (cli_user(cptr))->invites++;
}

/*
 * Delete Invite block from channel invite list and client invite list
 */
void del_invite(struct Client *cptr, struct Channel *chptr)
{
  struct SLink **inv, *tmp;

  for (inv = &(chptr->invites); (tmp = *inv); inv = &tmp->next)
    if (tmp->value.cptr == cptr)
    {
      *inv = tmp->next;
      free_link(tmp);
      tmp = 0;
      (cli_user(cptr))->invites--;
      break;
    }

  for (inv = &((cli_user(cptr))->invited); (tmp = *inv); inv = &tmp->next)
    if (tmp->value.chptr == chptr)
    {
      *inv = tmp->next;
      free_link(tmp);
      tmp = 0;
      break;
    }
}

/* List and skip all channels that are listen */
void list_next_channels(struct Client *cptr, int nr)
{
  struct ListingArgs *args = cli_listing(cptr);
  struct Channel *chptr = args->chptr;
  chptr->mode.mode &= ~MODE_LISTED;
  while (is_listed(chptr) || --nr >= 0)
  {
    for (; chptr; chptr = chptr->next)
    {
      if (!cli_user(cptr) || (SecretChannel(chptr) && !find_channel_member(cptr, chptr)))
        continue;
      if (chptr->users > args->min_users && chptr->users < args->max_users &&
          chptr->creationtime > args->min_time &&
          chptr->creationtime < args->max_time &&
          (!args->topic_limits || (*chptr->topic &&
          chptr->topic_time > args->min_topic_time &&
          chptr->topic_time < args->max_topic_time)))
      {
        if (ShowChannel(cptr,chptr))
	  send_reply(cptr, RPL_LIST, chptr->chname, chptr->users,
		     chptr->topic);
        chptr = chptr->next;
        break;
      }
    }
    if (!chptr)
    {
      MyFree(cli_listing(cptr));
      cli_listing(cptr) = NULL;
      send_reply(cptr, RPL_LISTEND);
      break;
    }
  }
  if (chptr)
  {
    (cli_listing(cptr))->chptr = chptr;
    chptr->mode.mode |= MODE_LISTED;
  }

  update_write(cptr);
}

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
void make_zombie(struct Membership* member, struct Client* who, struct Client* cptr,
                 struct Client* sptr, struct Channel* chptr)
{
  assert(0 != member);
  assert(0 != who);
  assert(0 != cptr);
  assert(0 != chptr);

  /* Default for case a): */
  SetZombie(member);

  /* Case b) or c) ?: */
  if (MyUser(who))      /* server 4 */
  {
    if (IsServer(cptr)) /* Case b) ? */
      sendcmdto_one(who, CMD_PART, cptr, "%H", chptr);
    remove_user_from_channel(who, chptr);
    return;
  }
  if (cli_from(who) == cptr)        /* True on servers 1, 5 and 6 */
  {
    struct Client *acptr = IsServer(sptr) ? sptr : (cli_user(sptr))->server;
    for (; acptr != &me; acptr = (cli_serv(acptr))->up)
      if (acptr == (cli_user(who))->server)   /* Case d) (server 5) */
      {
        remove_user_from_channel(who, chptr);
        return;
      }
  }

  /* Case a) (servers 1, 2, 3 and 6) */
  if (channel_all_zombies(chptr))
    remove_user_from_channel(who, chptr);

  /* XXX Can't actually call Debug here; if the channel is all zombies,
   * chptr will no longer exist when we get here.
  Debug((DEBUG_INFO, "%s is now a zombie on %s", who->name, chptr->chname));
  */
}

int number_of_zombies(struct Channel *chptr)
{
  struct Membership* member;
  int                count = 0;

  assert(0 != chptr);
  for (member = chptr->members; member; member = member->next_member) {
    if (IsZombie(member))
      ++count;
  }
  return count;
}

/*
 * This helper function builds an argument string in strptr, consisting
 * of the original string, a space, and str1 and str2 concatenated (if,
 * of course, str2 is not NULL)
 */
static void
build_string(char *strptr, int *strptr_i, char *str1, char *str2, char c)
{
  if (c)
    strptr[(*strptr_i)++] = c;

  while (*str1)
    strptr[(*strptr_i)++] = *(str1++);

  if (str2)
    while (*str2)
      strptr[(*strptr_i)++] = *(str2++);

  strptr[(*strptr_i)] = '\0';
}

/*
 * This is the workhorse of our ModeBuf suite; this actually generates the
 * output MODE commands, HACK notices, or whatever.  It's pretty complicated.
 */
static int
modebuf_flush_int(struct ModeBuf *mbuf, int all)
{
  /* we only need the flags that don't take args right now */
  static int flags[] = {
/*  MODE_CHANOP,	'o', */
/*  MODE_VOICE,		'v', */
    MODE_PRIVATE,	'p',
    MODE_SECRET,	's',
    MODE_MODERATED,	'm',
    MODE_TOPICLIMIT,	't',
    MODE_INVITEONLY,	'i',
    MODE_NOPRIVMSGS,	'n',
    MODE_REGONLY,	'r',
/*  MODE_KEY,		'k', */
/*  MODE_BAN,		'b', */
/*  MODE_LIMIT,		'l', */
    0x0, 0x0
  };
  int i;
  int *flag_p;

  struct Client *app_source; /* where the MODE appears to come from */

  char addbuf[20]; /* accumulates +psmtin, etc. */
  int addbuf_i = 0;
  char rembuf[20]; /* accumulates -psmtin, etc. */
  int rembuf_i = 0;
  char *bufptr; /* we make use of indirection to simplify the code */
  int *bufptr_i;

  char addstr[BUFSIZE]; /* accumulates MODE parameters to add */
  int addstr_i;
  char remstr[BUFSIZE]; /* accumulates MODE parameters to remove */
  int remstr_i;
  char *strptr; /* more indirection to simplify the code */
  int *strptr_i;

  int totalbuflen = BUFSIZE - 200; /* fuzz factor -- don't overrun buffer! */
  int tmp;

  char limitbuf[20]; /* convert limits to strings */

  unsigned int limitdel = MODE_LIMIT;

  assert(0 != mbuf);

  /* If the ModeBuf is empty, we have nothing to do */
  if (mbuf->mb_add == 0 && mbuf->mb_rem == 0 && mbuf->mb_count == 0)
    return 0;

  /* Ok, if we were given the OPMODE flag or if it's a server, hide source */
  if (mbuf->mb_dest & MODEBUF_DEST_OPMODE || IsServer(mbuf->mb_source))
    app_source = &me;
  else
    app_source = mbuf->mb_source;

  /*
   * Account for user we're bouncing; we have to get it in on the first
   * bounced MODE, or we could have problems
   */
  if (mbuf->mb_dest & MODEBUF_DEST_DEOP)
    totalbuflen -= 6; /* numeric nick == 5, plus one space */

  /* Calculate the simple flags */
  for (flag_p = flags; flag_p[0]; flag_p += 2) {
    if (*flag_p & mbuf->mb_add)
      addbuf[addbuf_i++] = flag_p[1];
    else if (*flag_p & mbuf->mb_rem)
      rembuf[rembuf_i++] = flag_p[1];
  }

  /* Now go through the modes with arguments... */
  for (i = 0; i < mbuf->mb_count; i++) {
    if (MB_TYPE(mbuf, i) & MODE_ADD) { /* adding or removing? */
      bufptr = addbuf;
      bufptr_i = &addbuf_i;
    } else {
      bufptr = rembuf;
      bufptr_i = &rembuf_i;
    }

    if (MB_TYPE(mbuf, i) & (MODE_CHANOP | MODE_VOICE)) {
      tmp = strlen(cli_name(MB_CLIENT(mbuf, i)));

      if ((totalbuflen - IRCD_MAX(5, tmp)) <= 0) /* don't overflow buffer */
	MB_TYPE(mbuf, i) |= MODE_SAVE; /* save for later */
      else {
	bufptr[(*bufptr_i)++] = MB_TYPE(mbuf, i) & MODE_CHANOP ? 'o' : 'v';
	totalbuflen -= IRCD_MAX(5, tmp) + 1;
      }
    } else if (MB_TYPE(mbuf, i) & MODE_BAN) {
      tmp = strlen(MB_STRING(mbuf, i));

      if ((totalbuflen - tmp) <= 0) /* don't overflow buffer */
	MB_TYPE(mbuf, i) |= MODE_SAVE; /* save for later */
      else {
	bufptr[(*bufptr_i)++] = 'b';
	totalbuflen -= tmp + 1;
      }
    } else if (MB_TYPE(mbuf, i) & MODE_KEY) {
      tmp = (mbuf->mb_dest & MODEBUF_DEST_NOKEY ? 1 :
	     strlen(MB_STRING(mbuf, i)));

      if ((totalbuflen - tmp) <= 0) /* don't overflow buffer */
	MB_TYPE(mbuf, i) |= MODE_SAVE; /* save for later */
      else {
	bufptr[(*bufptr_i)++] = 'k';
	totalbuflen -= tmp + 1;
      }
    } else if (MB_TYPE(mbuf, i) & MODE_LIMIT) {
      /* if it's a limit, we also format the number */
      ircd_snprintf(0, limitbuf, sizeof(limitbuf), "%u", MB_UINT(mbuf, i));

      tmp = strlen(limitbuf);

      if ((totalbuflen - tmp) <= 0) /* don't overflow buffer */
	MB_TYPE(mbuf, i) |= MODE_SAVE; /* save for later */
      else {
	bufptr[(*bufptr_i)++] = 'l';
	totalbuflen -= tmp + 1;
      }
    }
  }

  /* terminate the mode strings */
  addbuf[addbuf_i] = '\0';
  rembuf[rembuf_i] = '\0';

  /* If we're building a user visible MODE or HACK... */
  if (mbuf->mb_dest & (MODEBUF_DEST_CHANNEL | MODEBUF_DEST_HACK2 |
		       MODEBUF_DEST_HACK3   | MODEBUF_DEST_HACK4 |
		       MODEBUF_DEST_LOG)) {
    /* Set up the parameter strings */
    addstr[0] = '\0';
    addstr_i = 0;
    remstr[0] = '\0';
    remstr_i = 0;

    for (i = 0; i < mbuf->mb_count; i++) {
      if (MB_TYPE(mbuf, i) & MODE_SAVE)
	continue;

      if (MB_TYPE(mbuf, i) & MODE_ADD) { /* adding or removing? */
	strptr = addstr;
	strptr_i = &addstr_i;
      } else {
	strptr = remstr;
	strptr_i = &remstr_i;
      }

      /* deal with clients... */
      if (MB_TYPE(mbuf, i) & (MODE_CHANOP | MODE_VOICE))
	build_string(strptr, strptr_i, cli_name(MB_CLIENT(mbuf, i)), 0, ' ');

      /* deal with bans... */
      else if (MB_TYPE(mbuf, i) & MODE_BAN)
	build_string(strptr, strptr_i, MB_STRING(mbuf, i), 0, ' ');

      /* deal with keys... */
      else if (MB_TYPE(mbuf, i) & MODE_KEY)
	build_string(strptr, strptr_i, mbuf->mb_dest & MODEBUF_DEST_NOKEY ?
		     "*" : MB_STRING(mbuf, i), 0, ' ');

      /*
       * deal with limit; note we cannot include the limit parameter if we're
       * removing it
       */
      else if ((MB_TYPE(mbuf, i) & (MODE_ADD | MODE_LIMIT)) ==
	       (MODE_ADD | MODE_LIMIT))
	build_string(strptr, strptr_i, limitbuf, 0, ' ');
    }

    /* send the messages off to their destination */
    if (mbuf->mb_dest & MODEBUF_DEST_HACK2)
      sendto_opmask_butone(0, SNO_HACK2, "HACK(2): %s MODE %s %s%s%s%s%s%s "
			   "[%Tu]",
			   cli_name(feature_bool(FEAT_HIS_SNOTICES) ?
				    mbuf->mb_source : app_source),
			   mbuf->mb_channel->chname,
			   rembuf_i ? "-" : "", rembuf, addbuf_i ? "+" : "",
			   addbuf, remstr, addstr,
			   mbuf->mb_channel->creationtime);

    if (mbuf->mb_dest & MODEBUF_DEST_HACK3)
      sendto_opmask_butone(0, SNO_HACK3, "BOUNCE or HACK(3): %s MODE %s "
			   "%s%s%s%s%s%s [%Tu]",
			   cli_name(feature_bool(FEAT_HIS_SNOTICES) ?
				    mbuf->mb_source : app_source),
			   mbuf->mb_channel->chname, rembuf_i ? "-" : "",
			   rembuf, addbuf_i ? "+" : "", addbuf, remstr, addstr,
			   mbuf->mb_channel->creationtime);

    if (mbuf->mb_dest & MODEBUF_DEST_HACK4)
      sendto_opmask_butone(0, SNO_HACK4, "HACK(4): %s MODE %s %s%s%s%s%s%s "
			   "[%Tu]",
			   cli_name(feature_bool(FEAT_HIS_SNOTICES) ? 
				    mbuf->mb_source : app_source),
			   mbuf->mb_channel->chname,
			   rembuf_i ? "-" : "", rembuf, addbuf_i ? "+" : "",
			   addbuf, remstr, addstr,
			   mbuf->mb_channel->creationtime);

    if (mbuf->mb_dest & MODEBUF_DEST_LOG)
      log_write(LS_OPERMODE, L_INFO, LOG_NOSNOTICE,
		"%#C OPMODE %H %s%s%s%s%s%s", mbuf->mb_source,
		mbuf->mb_channel, rembuf_i ? "-" : "", rembuf,
		addbuf_i ? "+" : "", addbuf, remstr, addstr);

    if (mbuf->mb_dest & MODEBUF_DEST_CHANNEL)
      sendcmdto_channel_butserv_butone(app_source, CMD_MODE, mbuf->mb_channel, NULL,
				"%H %s%s%s%s%s%s", mbuf->mb_channel,
				rembuf_i ? "-" : "", rembuf,
				addbuf_i ? "+" : "", addbuf, remstr, addstr);
  }

  /* Now are we supposed to propagate to other servers? */
  if (mbuf->mb_dest & MODEBUF_DEST_SERVER) {
    /* set up parameter string */
    addstr[0] = '\0';
    addstr_i = 0;
    remstr[0] = '\0';
    remstr_i = 0;

    /*
     * limit is supressed if we're removing it; we have to figure out which
     * direction is the direction for it to be removed, though...
     */
    limitdel |= (mbuf->mb_dest & MODEBUF_DEST_HACK2) ? MODE_DEL : MODE_ADD;

    for (i = 0; i < mbuf->mb_count; i++) {
      if (MB_TYPE(mbuf, i) & MODE_SAVE)
	continue;

      if (MB_TYPE(mbuf, i) & MODE_ADD) { /* adding or removing? */
	strptr = addstr;
	strptr_i = &addstr_i;
      } else {
	strptr = remstr;
	strptr_i = &remstr_i;
      }

      /* deal with modes that take clients */
      if (MB_TYPE(mbuf, i) & (MODE_CHANOP | MODE_VOICE))
	build_string(strptr, strptr_i, NumNick(MB_CLIENT(mbuf, i)), ' ');

      /* deal with modes that take strings */
      else if (MB_TYPE(mbuf, i) & (MODE_KEY | MODE_BAN))
	build_string(strptr, strptr_i, MB_STRING(mbuf, i), 0, ' ');

      /*
       * deal with the limit.  Logic here is complicated; if HACK2 is set,
       * we're bouncing the mode, so sense is reversed, and we have to
       * include the original limit if it looks like it's being removed
       */
      else if ((MB_TYPE(mbuf, i) & limitdel) == limitdel)
	build_string(strptr, strptr_i, limitbuf, 0, ' ');
    }

    /* we were told to deop the source */
    if (mbuf->mb_dest & MODEBUF_DEST_DEOP) {
      addbuf[addbuf_i++] = 'o'; /* remember, sense is reversed */
      addbuf[addbuf_i] = '\0'; /* terminate the string... */
      build_string(addstr, &addstr_i, NumNick(mbuf->mb_source), ' ');

      /* mark that we've done this, so we don't do it again */
      mbuf->mb_dest &= ~MODEBUF_DEST_DEOP;
    }

    if (mbuf->mb_dest & MODEBUF_DEST_OPMODE) {
      /* If OPMODE was set, we're propagating the mode as an OPMODE message */
      sendcmdto_serv_butone(mbuf->mb_source, CMD_OPMODE, mbuf->mb_connect,
			    "%H %s%s%s%s%s%s", mbuf->mb_channel,
			    rembuf_i ? "-" : "", rembuf, addbuf_i ? "+" : "",
			    addbuf, remstr, addstr);
    } else if (mbuf->mb_dest & MODEBUF_DEST_BOUNCE) {
      /*
       * If HACK2 was set, we're bouncing; we send the MODE back to the
       * connection we got it from with the senses reversed and a TS of 0;
       * origin is us
       */
      sendcmdto_one(&me, CMD_MODE, mbuf->mb_connect, "%H %s%s%s%s%s%s %Tu",
		    mbuf->mb_channel, addbuf_i ? "-" : "", addbuf,
		    rembuf_i ? "+" : "", rembuf, addstr, remstr,
		    mbuf->mb_channel->creationtime);
    } else {
      /*
       * We're propagating a normal MODE command to the rest of the network;
       * we send the actual channel TS unless this is a HACK3 or a HACK4
       */
      if (IsServer(mbuf->mb_source))
	sendcmdto_serv_butone(mbuf->mb_source, CMD_MODE, mbuf->mb_connect,
			      "%H %s%s%s%s%s%s %Tu", mbuf->mb_channel,
			      rembuf_i ? "-" : "", rembuf, addbuf_i ? "+" : "",
			      addbuf, remstr, addstr,
			      (mbuf->mb_dest & MODEBUF_DEST_HACK4) ? 0 :
			      mbuf->mb_channel->creationtime);
      else
	sendcmdto_serv_butone(mbuf->mb_source, CMD_MODE, mbuf->mb_connect,
			      "%H %s%s%s%s%s%s", mbuf->mb_channel,
			      rembuf_i ? "-" : "", rembuf, addbuf_i ? "+" : "",
			      addbuf, remstr, addstr);
    }
  }

  /* We've drained the ModeBuf... */
  mbuf->mb_add = 0;
  mbuf->mb_rem = 0;
  mbuf->mb_count = 0;

  /* reinitialize the mode-with-arg slots */
  for (i = 0; i < MAXMODEPARAMS; i++) {
    /* If we saved any, pack them down */
    if (MB_TYPE(mbuf, i) & MODE_SAVE) {
      mbuf->mb_modeargs[mbuf->mb_count] = mbuf->mb_modeargs[i];
      MB_TYPE(mbuf, mbuf->mb_count) &= ~MODE_SAVE; /* don't save anymore */

      if (mbuf->mb_count++ == i) /* don't overwrite our hard work */
	continue;
    } else if (MB_TYPE(mbuf, i) & MODE_FREE)
      MyFree(MB_STRING(mbuf, i)); /* free string if needed */

    MB_TYPE(mbuf, i) = 0;
    MB_UINT(mbuf, i) = 0;
  }

  /* If we're supposed to flush it all, do so--all hail tail recursion */
  if (all && mbuf->mb_count)
    return modebuf_flush_int(mbuf, 1);

  return 0;
}

/*
 * This routine just initializes a ModeBuf structure with the information
 * needed and the options given.
 */
void
modebuf_init(struct ModeBuf *mbuf, struct Client *source,
	     struct Client *connect, struct Channel *chan, unsigned int dest)
{
  int i;

  assert(0 != mbuf);
  assert(0 != source);
  assert(0 != chan);
  assert(0 != dest);

  mbuf->mb_add = 0;
  mbuf->mb_rem = 0;
  mbuf->mb_source = source;
  mbuf->mb_connect = connect;
  mbuf->mb_channel = chan;
  mbuf->mb_dest = dest;
  mbuf->mb_count = 0;

  /* clear each mode-with-parameter slot */
  for (i = 0; i < MAXMODEPARAMS; i++) {
    MB_TYPE(mbuf, i) = 0;
    MB_UINT(mbuf, i) = 0;
  }
}

/*
 * This routine simply adds modes to be added or deleted; do a binary OR
 * with either MODE_ADD or MODE_DEL
 */
void
modebuf_mode(struct ModeBuf *mbuf, unsigned int mode)
{
  assert(0 != mbuf);
  assert(0 != (mode & (MODE_ADD | MODE_DEL)));

  mode &= (MODE_ADD | MODE_DEL | MODE_PRIVATE | MODE_SECRET | MODE_MODERATED |
	   MODE_TOPICLIMIT | MODE_INVITEONLY | MODE_NOPRIVMSGS | MODE_REGONLY);

  if (!(mode & ~(MODE_ADD | MODE_DEL))) /* don't add empty modes... */
    return;

  if (mode & MODE_ADD) {
    mbuf->mb_rem &= ~mode;
    mbuf->mb_add |= mode;
  } else {
    mbuf->mb_add &= ~mode;
    mbuf->mb_rem |= mode;
  }
}

/*
 * This routine adds a mode to be added or deleted that takes a unsigned
 * int parameter; mode may *only* be the relevant mode flag ORed with one
 * of MODE_ADD or MODE_DEL
 */
void
modebuf_mode_uint(struct ModeBuf *mbuf, unsigned int mode, unsigned int uint)
{
  assert(0 != mbuf);
  assert(0 != (mode & (MODE_ADD | MODE_DEL)));

  MB_TYPE(mbuf, mbuf->mb_count) = mode;
  MB_UINT(mbuf, mbuf->mb_count) = uint;

  /* when we've reached the maximal count, flush the buffer */
  if (++mbuf->mb_count >=
      (MAXMODEPARAMS - (mbuf->mb_dest & MODEBUF_DEST_DEOP ? 1 : 0)))
    modebuf_flush_int(mbuf, 0);
}

/*
 * This routine adds a mode to be added or deleted that takes a string
 * parameter; mode may *only* be the relevant mode flag ORed with one of
 * MODE_ADD or MODE_DEL
 */
void
modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode, char *string,
		    int free)
{
  assert(0 != mbuf);
  assert(0 != (mode & (MODE_ADD | MODE_DEL)));

  MB_TYPE(mbuf, mbuf->mb_count) = mode | (free ? MODE_FREE : 0);
  MB_STRING(mbuf, mbuf->mb_count) = string;

  /* when we've reached the maximal count, flush the buffer */
  if (++mbuf->mb_count >=
      (MAXMODEPARAMS - (mbuf->mb_dest & MODEBUF_DEST_DEOP ? 1 : 0)))
    modebuf_flush_int(mbuf, 0);
}

/*
 * This routine adds a mode to be added or deleted that takes a client
 * parameter; mode may *only* be the relevant mode flag ORed with one of
 * MODE_ADD or MODE_DEL
 */
void
modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
		    struct Client *client)
{
  assert(0 != mbuf);
  assert(0 != (mode & (MODE_ADD | MODE_DEL)));

  MB_TYPE(mbuf, mbuf->mb_count) = mode;
  MB_CLIENT(mbuf, mbuf->mb_count) = client;

  /* when we've reached the maximal count, flush the buffer */
  if (++mbuf->mb_count >=
      (MAXMODEPARAMS - (mbuf->mb_dest & MODEBUF_DEST_DEOP ? 1 : 0)))
    modebuf_flush_int(mbuf, 0);
}

/*
 * This is the exported binding for modebuf_flush()
 */
int
modebuf_flush(struct ModeBuf *mbuf)
{
  return modebuf_flush_int(mbuf, 1);
}

/*
 * This extracts the simple modes contained in mbuf
 */
void
modebuf_extract(struct ModeBuf *mbuf, char *buf)
{
  static int flags[] = {
/*  MODE_CHANOP,	'o', */
/*  MODE_VOICE,		'v', */
    MODE_PRIVATE,	'p',
    MODE_SECRET,	's',
    MODE_MODERATED,	'm',
    MODE_TOPICLIMIT,	't',
    MODE_INVITEONLY,	'i',
    MODE_NOPRIVMSGS,	'n',
    MODE_KEY,		'k',
/*  MODE_BAN,		'b', */
    MODE_LIMIT,		'l',
    MODE_REGONLY,	'r',
    0x0, 0x0
  };
  unsigned int add;
  int i, bufpos = 0, len;
  int *flag_p;
  char *key = 0, limitbuf[20];

  assert(0 != mbuf);
  assert(0 != buf);

  buf[0] = '\0';

  add = mbuf->mb_add;

  for (i = 0; i < mbuf->mb_count; i++) { /* find keys and limits */
    if (MB_TYPE(mbuf, i) & MODE_ADD) {
      add |= MB_TYPE(mbuf, i) & (MODE_KEY | MODE_LIMIT);

      if (MB_TYPE(mbuf, i) & MODE_KEY) /* keep strings */
	key = MB_STRING(mbuf, i);
      else if (MB_TYPE(mbuf, i) & MODE_LIMIT)
	ircd_snprintf(0, limitbuf, sizeof(limitbuf), "%u", MB_UINT(mbuf, i));
    }
  }

  if (!add)
    return;

  buf[bufpos++] = '+'; /* start building buffer */

  for (flag_p = flags; flag_p[0]; flag_p += 2)
    if (*flag_p & add)
      buf[bufpos++] = flag_p[1];

  for (i = 0, len = bufpos; i < len; i++) {
    if (buf[i] == 'k')
      build_string(buf, &bufpos, key, 0, ' ');
    else if (buf[i] == 'l')
      build_string(buf, &bufpos, limitbuf, 0, ' ');
  }

  buf[bufpos] = '\0';

  return;
}

/*
 * Simple function to invalidate bans
 */
void
mode_ban_invalidate(struct Channel *chan)
{
  struct Membership *member;

  for (member = chan->members; member; member = member->next_member)
    ClearBanValid(member);
}

/*
 * Simple function to drop invite structures
 */
void
mode_invite_clear(struct Channel *chan)
{
  while (chan->invites)
    del_invite(chan->invites->value.cptr, chan);
}

/* What we've done for mode_parse so far... */
#define DONE_LIMIT	0x01	/* We've set the limit */
#define DONE_KEY	0x02	/* We've set the key */
#define DONE_BANLIST	0x04	/* We've sent the ban list */
#define DONE_NOTOPER	0x08	/* We've sent a "Not oper" error */
#define DONE_BANCLEAN	0x10	/* We've cleaned bans... */

struct ParseState {
  struct ModeBuf *mbuf;
  struct Client *cptr;
  struct Client *sptr;
  struct Channel *chptr;
  int parc;
  char **parv;
  unsigned int flags;
  unsigned int dir;
  unsigned int done;
  unsigned int add;
  unsigned int del;
  int args_used;
  int max_args;
  int numbans;
  struct SLink banlist[MAXPARA];
  struct {
    unsigned int flag;
    struct Client *client;
  } cli_change[MAXPARA];
};

/*
 * Here's a helper function to deal with sending along "Not oper" or
 * "Not member" messages
 */
static void
send_notoper(struct ParseState *state)
{
  if (state->done & DONE_NOTOPER)
    return;

  send_reply(state->sptr, (state->flags & MODE_PARSE_NOTOPER) ?
	     ERR_CHANOPRIVSNEEDED : ERR_NOTONCHANNEL, state->chptr->chname);

  state->done |= DONE_NOTOPER;
}

/*
 * Helper function to convert limits
 */
static void
mode_parse_limit(struct ParseState *state, int *flag_p)
{
  unsigned int t_limit;

  if (state->dir == MODE_ADD) { /* convert arg only if adding limit */
    if (MyUser(state->sptr) && state->max_args <= 0) /* too many args? */
      return;

    if (state->parc <= 0) { /* warn if not enough args */
      if (MyUser(state->sptr))
	need_more_params(state->sptr, "MODE +l");
      return;
    }

    t_limit = strtoul(state->parv[state->args_used++], 0, 10); /* grab arg */
    state->parc--;
    state->max_args--;

    if (!(state->flags & MODE_PARSE_WIPEOUT) &&
	(!t_limit || t_limit == state->chptr->mode.limit))
      return;
  } else
    t_limit = state->chptr->mode.limit;

  /* If they're not an oper, they can't change modes */
  if (state->flags & (MODE_PARSE_NOTOPER | MODE_PARSE_NOTMEMBER)) {
    send_notoper(state);
    return;
  }

  if (state->done & DONE_LIMIT) /* allow limit to be set only once */
    return;
  state->done |= DONE_LIMIT;

  if (!state->mbuf)
    return;

  modebuf_mode_uint(state->mbuf, state->dir | flag_p[0], t_limit);

  if (state->flags & MODE_PARSE_SET) { /* set the limit */
    if (state->dir & MODE_ADD) {
      state->chptr->mode.mode |= flag_p[0];
      state->chptr->mode.limit = t_limit;
    } else {
      state->chptr->mode.mode &= ~flag_p[0];
      state->chptr->mode.limit = 0;
    }
  }
}

/*
 * Helper function to convert keys
 */
static void
mode_parse_key(struct ParseState *state, int *flag_p)
{
  char *t_str, *s;
  int t_len;

  if (MyUser(state->sptr) && state->max_args <= 0) /* drop if too many args */
    return;

  if (state->parc <= 0) { /* warn if not enough args */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +k" :
		       "MODE -k");
    return;
  }

  t_str = state->parv[state->args_used++]; /* grab arg */
  state->parc--;
  state->max_args--;

  /* If they're not an oper, they can't change modes */
  if (state->flags & (MODE_PARSE_NOTOPER | MODE_PARSE_NOTMEMBER)) {
    send_notoper(state);
    return;
  }

  if (state->done & DONE_KEY) /* allow key to be set only once */
    return;
  state->done |= DONE_KEY;

  t_len = KEYLEN;

  /* clean up the key string */
  s = t_str;
  while (*++s > ' ' && *s != ':' && --t_len)
    ;
  *s = '\0';

  if (!*t_str) { /* warn if empty */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +k" :
		       "MODE -k");
    return;
  }

  if (!state->mbuf)
    return;

  /* can't add a key if one is set, nor can one remove the wrong key */
  if (!(state->flags & MODE_PARSE_FORCE))
    if ((state->dir == MODE_ADD && *state->chptr->mode.key) ||
	(state->dir == MODE_DEL &&
	 ircd_strcmp(state->chptr->mode.key, t_str))) {
      send_reply(state->sptr, ERR_KEYSET, state->chptr->chname);
      return;
    }

  if (!(state->flags & MODE_PARSE_WIPEOUT) && state->dir == MODE_ADD &&
      !ircd_strcmp(state->chptr->mode.key, t_str))
    return; /* no key change */

  if (state->flags & MODE_PARSE_BOUNCE) {
    if (*state->chptr->mode.key) /* reset old key */
      modebuf_mode_string(state->mbuf, MODE_DEL | flag_p[0],
			  state->chptr->mode.key, 0);
    else /* remove new bogus key */
      modebuf_mode_string(state->mbuf, MODE_ADD | flag_p[0], t_str, 0);
  } else /* send new key */
    modebuf_mode_string(state->mbuf, state->dir | flag_p[0], t_str, 0);

  if (state->flags & MODE_PARSE_SET) {
    if (state->dir == MODE_ADD) /* set the new key */
      ircd_strncpy(state->chptr->mode.key, t_str, KEYLEN);
    else /* remove the old key */
      *state->chptr->mode.key = '\0';
  }
}

/*
 * Helper function to convert bans
 */
static void
mode_parse_ban(struct ParseState *state, int *flag_p)
{
  char *t_str, *s;
  struct SLink *ban, *newban = 0;

  if (state->parc <= 0) { /* Not enough args, send ban list */
    if (MyUser(state->sptr) && !(state->done & DONE_BANLIST)) {
      send_ban_list(state->sptr, state->chptr);
      state->done |= DONE_BANLIST;
    }

    return;
  }

  if (MyUser(state->sptr) && state->max_args <= 0) /* drop if too many args */
    return;

  t_str = state->parv[state->args_used++]; /* grab arg */
  state->parc--;
  state->max_args--;

  /* If they're not an oper, they can't change modes */
  if (state->flags & (MODE_PARSE_NOTOPER | MODE_PARSE_NOTMEMBER)) {
    send_notoper(state);
    return;
  }

  if ((s = strchr(t_str, ' ')))
    *s = '\0';

  if (!*t_str || *t_str == ':') { /* warn if empty */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +b" :
		       "MODE -b");
    return;
  }

  t_str = collapse(pretty_mask(t_str));

  /* remember the ban for the moment... */
  if (state->dir == MODE_ADD) {
    newban = state->banlist + (state->numbans++);
    newban->next = 0;

    DupString(newban->value.ban.banstr, t_str);
    newban->value.ban.who = cli_name(state->sptr);
    newban->value.ban.when = TStime();

    newban->flags = CHFL_BAN | MODE_ADD;

    if ((s = strrchr(t_str, '@')) && check_if_ipmask(s + 1))
      newban->flags |= CHFL_BAN_IPMASK;
  }

  if (!state->chptr->banlist) {
    state->chptr->banlist = newban; /* add our ban with its flags */
    state->done |= DONE_BANCLEAN;
    return;
  }

  /* Go through all bans */
  for (ban = state->chptr->banlist; ban; ban = ban->next) {
    /* first, clean the ban flags up a bit */
    if (!(state->done & DONE_BANCLEAN))
      /* Note: We're overloading *lots* of bits here; be careful! */
      ban->flags &= ~(MODE_ADD | MODE_DEL | CHFL_BAN_OVERLAPPED);

    /* Bit meanings:
     *
     * MODE_ADD		   - Ban was added; if we're bouncing modes,
     *			     then we'll remove it below; otherwise,
     *			     we'll have to allocate a real ban
     *
     * MODE_DEL		   - Ban was marked for deletion; if we're
     *			     bouncing modes, we'll have to re-add it,
     *			     otherwise, we'll have to remove it
     *
     * CHFL_BAN_OVERLAPPED - The ban we added turns out to overlap
     *			     with a ban already set; if we're
     *			     bouncing modes, we'll have to bounce
     *			     this one; otherwise, we'll just ignore
     *			     it when we process added bans
     */

    if (state->dir == MODE_DEL && !ircd_strcmp(ban->value.ban.banstr, t_str)) {
      ban->flags |= MODE_DEL; /* delete one ban */

      if (state->done & DONE_BANCLEAN) /* If we're cleaning, finish */
	break;
    } else if (state->dir == MODE_ADD) {
      /* if the ban already exists, don't worry about it */
      if (!ircd_strcmp(ban->value.ban.banstr, t_str)) {
	newban->flags &= ~MODE_ADD; /* don't add ban at all */
	MyFree(newban->value.ban.banstr); /* stopper a leak */
	state->numbans--; /* deallocate last ban */
	if (state->done & DONE_BANCLEAN) /* If we're cleaning, finish */
	  break;
      } else if (!mmatch(ban->value.ban.banstr, t_str)) {
	if (!(ban->flags & MODE_DEL))
	  newban->flags |= CHFL_BAN_OVERLAPPED; /* our ban overlaps */
      } else if (!mmatch(t_str, ban->value.ban.banstr))
	ban->flags |= MODE_DEL; /* mark ban for deletion: overlapping */

      if (!ban->next && (newban->flags & MODE_ADD)) {
	ban->next = newban; /* add our ban with its flags */
	break; /* get out of loop */
      }
    }
  }
  state->done |= DONE_BANCLEAN;
}

/*
 * This is the bottom half of the ban processor
 */
static void
mode_process_bans(struct ParseState *state)
{
  struct SLink *ban, *newban, *prevban, *nextban;
  int count = 0;
  int len = 0;
  int banlen;
  int changed = 0;

  for (prevban = 0, ban = state->chptr->banlist; ban; ban = nextban) {
    count++;
    banlen = strlen(ban->value.ban.banstr);
    len += banlen;
    nextban = ban->next;

    if ((ban->flags & (MODE_DEL | MODE_ADD)) == (MODE_DEL | MODE_ADD)) {
      if (prevban)
	prevban->next = 0; /* Break the list; ban isn't a real ban */
      else
	state->chptr->banlist = 0;

      count--;
      len -= banlen;

      MyFree(ban->value.ban.banstr);

      continue;
    } else if (ban->flags & MODE_DEL) { /* Deleted a ban? */
      modebuf_mode_string(state->mbuf, MODE_DEL | MODE_BAN,
			  ban->value.ban.banstr,
			  state->flags & MODE_PARSE_SET);

      if (state->flags & MODE_PARSE_SET) { /* Ok, make it take effect */
	if (prevban) /* clip it out of the list... */
	  prevban->next = ban->next;
	else
	  state->chptr->banlist = ban->next;

	count--;
	len -= banlen;

	MyFree(ban->value.ban.who);
	free_link(ban);

	changed++;
	continue; /* next ban; keep prevban like it is */
      } else
	ban->flags &= (CHFL_BAN | CHFL_BAN_IPMASK); /* unset other flags */
    } else if (ban->flags & MODE_ADD) { /* adding a ban? */
      if (prevban)
	prevban->next = 0; /* Break the list; ban isn't a real ban */
      else
	state->chptr->banlist = 0;

      /* If we're supposed to ignore it, do so. */
      if (ban->flags & CHFL_BAN_OVERLAPPED &&
	  !(state->flags & MODE_PARSE_BOUNCE)) {
	count--;
	len -= banlen;

	MyFree(ban->value.ban.banstr);
      } else {
	if (state->flags & MODE_PARSE_SET && MyUser(state->sptr) &&
	    (len > (feature_int(FEAT_AVBANLEN) * feature_int(FEAT_MAXBANS)) ||
	     count > feature_int(FEAT_MAXBANS))) {
	  send_reply(state->sptr, ERR_BANLISTFULL, state->chptr->chname,
		     ban->value.ban.banstr);
	  count--;
	  len -= banlen;

	  MyFree(ban->value.ban.banstr);
	} else {
	  /* add the ban to the buffer */
	  modebuf_mode_string(state->mbuf, MODE_ADD | MODE_BAN,
			      ban->value.ban.banstr,
			      !(state->flags & MODE_PARSE_SET));

	  if (state->flags & MODE_PARSE_SET) { /* create a new ban */
	    newban = make_link();
	    newban->value.ban.banstr = ban->value.ban.banstr;
	    DupString(newban->value.ban.who, ban->value.ban.who);
	    newban->value.ban.when = ban->value.ban.when;
	    newban->flags = ban->flags & (CHFL_BAN | CHFL_BAN_IPMASK);

	    newban->next = state->chptr->banlist; /* and link it in */
	    state->chptr->banlist = newban;

	    changed++;
	  }
	}
      }
    }

    prevban = ban;
  } /* for (prevban = 0, ban = state->chptr->banlist; ban; ban = nextban) { */

  if (changed) /* if we changed the ban list, we must invalidate the bans */
    mode_ban_invalidate(state->chptr);
}

/*
 * Helper function to process client changes
 */
static void
mode_parse_client(struct ParseState *state, int *flag_p)
{
  char *t_str;
  struct Client *acptr;
  int i;

  if (MyUser(state->sptr) && state->max_args <= 0) /* drop if too many args */
    return;

  if (state->parc <= 0) /* return if not enough args */
    return;

  t_str = state->parv[state->args_used++]; /* grab arg */
  state->parc--;
  state->max_args--;

  /* If they're not an oper, they can't change modes */
  if (state->flags & (MODE_PARSE_NOTOPER | MODE_PARSE_NOTMEMBER)) {
    send_notoper(state);
    return;
  }

  if (MyUser(state->sptr)) /* find client we're manipulating */
    acptr = find_chasing(state->sptr, t_str, NULL);
  else
    acptr = findNUser(t_str);

  if (!acptr)
    return; /* find_chasing() already reported an error to the user */

  for (i = 0; i < MAXPARA; i++) /* find an element to stick them in */
    if (!state->cli_change[i].flag || (state->cli_change[i].client == acptr &&
				       state->cli_change[i].flag & flag_p[0]))
      break; /* found a slot */

  /* Store what we're doing to them */
  state->cli_change[i].flag = state->dir | flag_p[0];
  state->cli_change[i].client = acptr;
}

/*
 * Helper function to process the changed client list
 */
static void
mode_process_clients(struct ParseState *state)
{
  int i;
  struct Membership *member;

  for (i = 0; state->cli_change[i].flag; i++) {
    assert(0 != state->cli_change[i].client);

    /* look up member link */
    if (!(member = find_member_link(state->chptr,
				    state->cli_change[i].client)) ||
	(MyUser(state->sptr) && IsZombie(member))) {
      if (MyUser(state->sptr))
	send_reply(state->sptr, ERR_USERNOTINCHANNEL,
		   cli_name(state->cli_change[i].client),
		   state->chptr->chname);
      continue;
    }

    if ((state->cli_change[i].flag & MODE_ADD &&
	 (state->cli_change[i].flag & member->status)) ||
	(state->cli_change[i].flag & MODE_DEL &&
	 !(state->cli_change[i].flag & member->status)))
      continue; /* no change made, don't do anything */

    /* see if the deop is allowed */
    if ((state->cli_change[i].flag & (MODE_DEL | MODE_CHANOP)) ==
	(MODE_DEL | MODE_CHANOP)) {
      /* prevent +k users from being deopped */
      if (IsChannelService(state->cli_change[i].client)) {
	if (state->flags & MODE_PARSE_FORCE) /* it was forced */
	  sendto_opmask_butone(0, SNO_HACK4, "Deop of +k user on %H by %s",
			       state->chptr,
			       (IsServer(state->sptr) ? cli_name(state->sptr) :
				cli_name((cli_user(state->sptr))->server)));

	else if (MyUser(state->sptr) && state->flags & MODE_PARSE_SET) {
	  send_reply(state->sptr, ERR_ISCHANSERVICE,
		     cli_name(state->cli_change[i].client),
		     state->chptr->chname);
	  continue;
	}
      }

      /* don't allow local opers to be deopped on local channels */
      if (MyUser(state->sptr) && state->cli_change[i].client != state->sptr &&
	  IsLocalChannel(state->chptr->chname) &&
	  HasPriv(state->cli_change[i].client, PRIV_DEOP_LCHAN)) {
	send_reply(state->sptr, ERR_ISOPERLCHAN,
		   cli_name(state->cli_change[i].client),
		   state->chptr->chname);
	continue;
      }
    }

    /* accumulate the change */
    modebuf_mode_client(state->mbuf, state->cli_change[i].flag,
			state->cli_change[i].client);

    /* actually effect the change */
    if (state->flags & MODE_PARSE_SET) {
      if (state->cli_change[i].flag & MODE_ADD) {
	member->status |= (state->cli_change[i].flag &
			   (MODE_CHANOP | MODE_VOICE));
	if (state->cli_change[i].flag & MODE_CHANOP)
	  ClearDeopped(member);
      } else
	member->status &= ~(state->cli_change[i].flag &
			    (MODE_CHANOP | MODE_VOICE));
    }
  } /* for (i = 0; state->cli_change[i].flags; i++) { */
}

/*
 * Helper function to process the simple modes
 */
static void
mode_parse_mode(struct ParseState *state, int *flag_p)
{
  /* If they're not an oper, they can't change modes */
  if (state->flags & (MODE_PARSE_NOTOPER | MODE_PARSE_NOTMEMBER)) {
    send_notoper(state);
    return;
  }

  if (!state->mbuf)
    return;

  if (state->dir == MODE_ADD) {
    state->add |= flag_p[0];
    state->del &= ~flag_p[0];

    if (flag_p[0] & MODE_SECRET) {
      state->add &= ~MODE_PRIVATE;
      state->del |= MODE_PRIVATE;
    } else if (flag_p[0] & MODE_PRIVATE) {
      state->add &= ~MODE_SECRET;
      state->del |= MODE_SECRET;
    }
  } else {
    state->add &= ~flag_p[0];
    state->del |= flag_p[0];
  }

  assert(0 == (state->add & state->del));
  assert((MODE_SECRET | MODE_PRIVATE) !=
	 (state->add & (MODE_SECRET | MODE_PRIVATE)));
}

/*
 * This routine is intended to parse MODE or OPMODE commands and effect the
 * changes (or just build the bounce buffer).  We pass the starting offset
 * as a 
 */
int
mode_parse(struct ModeBuf *mbuf, struct Client *cptr, struct Client *sptr,
	   struct Channel *chptr, int parc, char *parv[], unsigned int flags)
{
  static int chan_flags[] = {
    MODE_CHANOP,	'o',
    MODE_VOICE,		'v',
    MODE_PRIVATE,	'p',
    MODE_SECRET,	's',
    MODE_MODERATED,	'm',
    MODE_TOPICLIMIT,	't',
    MODE_INVITEONLY,	'i',
    MODE_NOPRIVMSGS,	'n',
    MODE_KEY,		'k',
    MODE_BAN,		'b',
    MODE_LIMIT,		'l',
    MODE_REGONLY,	'r',
    MODE_ADD,		'+',
    MODE_DEL,		'-',
    0x0, 0x0
  };
  int i;
  int *flag_p;
  unsigned int t_mode;
  char *modestr;
  struct ParseState state;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(0 != chptr);
  assert(0 != parc);
  assert(0 != parv);

  state.mbuf = mbuf;
  state.cptr = cptr;
  state.sptr = sptr;
  state.chptr = chptr;
  state.parc = parc;
  state.parv = parv;
  state.flags = flags;
  state.dir = MODE_ADD;
  state.done = 0;
  state.add = 0;
  state.del = 0;
  state.args_used = 0;
  state.max_args = MAXMODEPARAMS;
  state.numbans = 0;

  for (i = 0; i < MAXPARA; i++) { /* initialize ops/voices arrays */
    state.banlist[i].next = 0;
    state.banlist[i].value.ban.banstr = 0;
    state.banlist[i].value.ban.who = 0;
    state.banlist[i].value.ban.when = 0;
    state.banlist[i].flags = 0;
    state.cli_change[i].flag = 0;
    state.cli_change[i].client = 0;
  }

  modestr = state.parv[state.args_used++];
  state.parc--;

  while (*modestr) {
    for (; *modestr; modestr++) {
      for (flag_p = chan_flags; flag_p[0]; flag_p += 2) /* look up flag */
	if (flag_p[1] == *modestr)
	  break;

      if (!flag_p[0]) { /* didn't find it?  complain and continue */
	if (MyUser(state.sptr))
	  send_reply(state.sptr, ERR_UNKNOWNMODE, *modestr);
	continue;
      }

      switch (*modestr) {
      case '+': /* switch direction to MODE_ADD */
      case '-': /* switch direction to MODE_DEL */
	state.dir = flag_p[0];
	break;

      case 'l': /* deal with limits */
	mode_parse_limit(&state, flag_p);
	break;

      case 'k': /* deal with keys */
	mode_parse_key(&state, flag_p);
	break;

      case 'b': /* deal with bans */
	mode_parse_ban(&state, flag_p);
	break;

      case 'o': /* deal with ops/voice */
      case 'v':
	mode_parse_client(&state, flag_p);
	break;

      default: /* deal with other modes */
	mode_parse_mode(&state, flag_p);
	break;
      } /* switch (*modestr) { */
    } /* for (; *modestr; modestr++) { */

    if (state.flags & MODE_PARSE_BURST)
      break; /* don't interpret any more arguments */

    if (state.parc > 0) { /* process next argument in string */
      modestr = state.parv[state.args_used++];
      state.parc--;

      /* is it a TS? */
      if (IsServer(state.sptr) && !state.parc && IsDigit(*modestr)) {
	time_t recv_ts;

	if (!(state.flags & MODE_PARSE_SET))	  /* don't set earlier TS if */
	  break;		     /* we're then going to bounce the mode! */

	recv_ts = atoi(modestr);

	if (recv_ts && recv_ts < state.chptr->creationtime)
	  state.chptr->creationtime = recv_ts; /* respect earlier TS */

	break; /* break out of while loop */
      } else if (state.flags & MODE_PARSE_STRICT ||
		 (MyUser(state.sptr) && state.max_args <= 0)) {
	state.parc++; /* we didn't actually gobble the argument */
	state.args_used--;
	break; /* break out of while loop */
      }
    }
  } /* while (*modestr) { */

  /*
   * the rest of the function finishes building resultant MODEs; if the
   * origin isn't a member or an oper, skip it.
   */
  if (!state.mbuf || state.flags & (MODE_PARSE_NOTOPER | MODE_PARSE_NOTMEMBER))
    return state.args_used; /* tell our parent how many args we gobbled */

  t_mode = state.chptr->mode.mode;

  if (state.del & t_mode) { /* delete any modes to be deleted... */
    modebuf_mode(state.mbuf, MODE_DEL | (state.del & t_mode));

    t_mode &= ~state.del;
  }
  if (state.add & ~t_mode) { /* add any modes to be added... */
    modebuf_mode(state.mbuf, MODE_ADD | (state.add & ~t_mode));

    t_mode |= state.add;
  }

  if (state.flags & MODE_PARSE_SET) { /* set the channel modes */
    if ((state.chptr->mode.mode & MODE_INVITEONLY) &&
	!(t_mode & MODE_INVITEONLY))
      mode_invite_clear(state.chptr);

    state.chptr->mode.mode = t_mode;
  }

  if (state.flags & MODE_PARSE_WIPEOUT) {
    if (state.chptr->mode.limit && !(state.done & DONE_LIMIT))
      modebuf_mode_uint(state.mbuf, MODE_DEL | MODE_LIMIT,
			state.chptr->mode.limit);
    if (*state.chptr->mode.key && !(state.done & DONE_KEY))
      modebuf_mode_string(state.mbuf, MODE_DEL | MODE_KEY,
			  state.chptr->mode.key, 0);
  }

  if (state.done & DONE_BANCLEAN) /* process bans */
    mode_process_bans(&state);

  /* process client changes */
  if (state.cli_change[0].flag)
    mode_process_clients(&state);

  return state.args_used; /* tell our parent how many args we gobbled */
}

/*
 * Initialize a join buffer
 */
void
joinbuf_init(struct JoinBuf *jbuf, struct Client *source,
	     struct Client *connect, unsigned int type, char *comment,
	     time_t create)
{
  int i;

  assert(0 != jbuf);
  assert(0 != source);
  assert(0 != connect);

  jbuf->jb_source = source; /* just initialize struct JoinBuf */
  jbuf->jb_connect = connect;
  jbuf->jb_type = type;
  jbuf->jb_comment = comment;
  jbuf->jb_create = create;
  jbuf->jb_count = 0;
  jbuf->jb_strlen = (((type == JOINBUF_TYPE_JOIN ||
		       type == JOINBUF_TYPE_PART ||
		       type == JOINBUF_TYPE_PARTALL) ?
		      STARTJOINLEN : STARTCREATELEN) +
		     (comment ? strlen(comment) + 2 : 0));

  for (i = 0; i < MAXJOINARGS; i++)
    jbuf->jb_channels[i] = 0;
}

/*
 * Add a channel to the join buffer
 */
void
joinbuf_join(struct JoinBuf *jbuf, struct Channel *chan, unsigned int flags)
{
  unsigned int len;
  int is_local;

  assert(0 != jbuf);

  if (!chan) {
    if (jbuf->jb_type == JOINBUF_TYPE_JOIN)
      sendcmdto_serv_butone(jbuf->jb_source, CMD_JOIN, jbuf->jb_connect, "0");

    return;
  }

  is_local = IsLocalChannel(chan->chname);

  if (jbuf->jb_type == JOINBUF_TYPE_PART ||
      jbuf->jb_type == JOINBUF_TYPE_PARTALL) {
    /* Send notification to channel */
    if (!(flags & CHFL_ZOMBIE))
      sendcmdto_channel_butserv_butone(jbuf->jb_source, CMD_PART, chan, NULL,
				(flags & CHFL_BANNED || !jbuf->jb_comment) ?
				":%H" : "%H :%s", chan, jbuf->jb_comment);
    else if (MyUser(jbuf->jb_source))
      sendcmdto_one(jbuf->jb_source, CMD_PART, jbuf->jb_source,
		    (flags & CHFL_BANNED || !jbuf->jb_comment) ?
		    ":%H" : "%H :%s", chan, jbuf->jb_comment);
    /* XXX: Shouldn't we send a PART here anyway? */
    /* to users on the channel?  Why?  From their POV, the user isn't on
     * the channel anymore anyway.  We don't send to servers until below,
     * when we gang all the channel parts together.  Note that this is
     * exactly the same logic, albeit somewhat more concise, as was in
     * the original m_part.c */

    /* got to remove user here */
    if (jbuf->jb_type == JOINBUF_TYPE_PARTALL || is_local)
      remove_user_from_channel(jbuf->jb_source, chan);
  } else {
    /* Add user to channel */
    add_user_to_channel(chan, jbuf->jb_source, flags);

    /* send notification to all servers */
    if (jbuf->jb_type != JOINBUF_TYPE_CREATE && !IsLocalChannel(chan->chname))
      sendcmdto_serv_butone(jbuf->jb_source, CMD_JOIN, jbuf->jb_connect,
			    "%H %Tu", chan, chan->creationtime);

    /* Send the notification to the channel */
    sendcmdto_channel_butserv_butone(jbuf->jb_source, CMD_JOIN, chan, NULL, ":%H", chan);

    /* send an op, too, if needed */
    if (!MyUser(jbuf->jb_source) && jbuf->jb_type == JOINBUF_TYPE_CREATE)
      sendcmdto_channel_butserv_butone(jbuf->jb_source, CMD_MODE, chan, NULL, "%H +o %C",
				chan, jbuf->jb_source);
  }

  if (jbuf->jb_type == JOINBUF_TYPE_PARTALL ||
      jbuf->jb_type == JOINBUF_TYPE_JOIN ||
      is_local)
    return; /* don't send to remote */

  /* figure out if channel name will cause buffer to be overflowed */
  len = chan ? strlen(chan->chname) + 1 : 2;
  if (jbuf->jb_strlen + len > BUFSIZE)
    joinbuf_flush(jbuf);

  /* add channel to list of channels to send and update counts */
  jbuf->jb_channels[jbuf->jb_count++] = chan;
  jbuf->jb_strlen += len;

  /* if we've used up all slots, flush */
  if (jbuf->jb_count >= MAXJOINARGS)
    joinbuf_flush(jbuf);
}

/*
 * Flush the channel list to remote servers
 */
int
joinbuf_flush(struct JoinBuf *jbuf)
{
  char chanlist[BUFSIZE];
  int chanlist_i = 0;
  int i;

  if (!jbuf->jb_count || jbuf->jb_type == JOINBUF_TYPE_PARTALL ||
      jbuf->jb_type == JOINBUF_TYPE_JOIN)
    return 0; /* no joins to process */

  for (i = 0; i < jbuf->jb_count; i++) { /* build channel list */
    build_string(chanlist, &chanlist_i,
		 jbuf->jb_channels[i] ? jbuf->jb_channels[i]->chname : "0", 0,
		 i == 0 ? '\0' : ',');
    if (JOINBUF_TYPE_PART == jbuf->jb_type)
      /* Remove user from channel */
      remove_user_from_channel(jbuf->jb_source, jbuf->jb_channels[i]);

    jbuf->jb_channels[i] = 0; /* mark slot empty */
  }

  jbuf->jb_count = 0; /* reset base counters */
  jbuf->jb_strlen = ((jbuf->jb_type == JOINBUF_TYPE_PART ?
		      STARTJOINLEN : STARTCREATELEN) +
		     (jbuf->jb_comment ? strlen(jbuf->jb_comment) + 2 : 0));

  /* and send the appropriate command */
  switch (jbuf->jb_type) {
  case JOINBUF_TYPE_CREATE:
    sendcmdto_serv_butone(jbuf->jb_source, CMD_CREATE, jbuf->jb_connect,
			  "%s %Tu", chanlist, jbuf->jb_create);
    break;

  case JOINBUF_TYPE_PART:
    sendcmdto_serv_butone(jbuf->jb_source, CMD_PART, jbuf->jb_connect,
			  jbuf->jb_comment ? "%s :%s" : "%s", chanlist,
			  jbuf->jb_comment);
    break;
  }

  return 0;
}

/* Returns TRUE (1) if client is invited, FALSE (0) if not */

int IsInvited(struct Client* cptr, struct Channel* chptr)
{
  struct SLink *lp;

  for (lp = (cli_user(cptr))->invited; lp; lp = lp->next)
    if (lp->value.chptr == chptr)
      return 1;

  return 0;
}
