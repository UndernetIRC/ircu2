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
/** @file
 * @brief Channel management and maintanance
 * @version $Id$
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "destruct_event.h"
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
#include "sys.h"
#include "whowas.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Linked list containing the full list of all channels */
struct Channel* GlobalChannelList = 0;

/** Number of struct Membership*'s allocated */
static unsigned int membershipAllocCount;
/** Freelist for struct Membership*'s */
static struct Membership* membershipFreeList;

void del_invite(struct Client *, struct Channel *);

const char* const PartFmt1     = ":%s " MSG_PART " %s";
const char* const PartFmt2     = ":%s " MSG_PART " %s :%s";
const char* const PartFmt1serv = "%s%s " TOK_PART " %s";
const char* const PartFmt2serv = "%s%s " TOK_PART " %s :%s";


static struct Ban* next_ban;
static struct Ban* prev_ban;
static struct Ban* removed_bans_list;
static struct Ban* free_bans;

/**
 * Use a global variable to remember if an oper set a mode on a local channel. 
 * Ugly, but the only way to do it without changing set_mode intensively.
 */
int LocalChanOperMode = 0;

#if !defined(NDEBUG)
/** return the length (>=0) of a chain of links.
 * @param lp	pointer to the start of the linked list
 * @return the number of items in the list
 */
static int list_length(struct SLink *lp)
{
  int count = 0;

  for (; lp; lp = lp->next)
    ++count;
  return count;
}
#endif

/** Allocate a new Ban structure.
 * @param[in] banstr Ban mask to use.
 * @return Newly allocated ban.
 */
struct Ban *
make_ban(const char *banstr)
{
  struct Ban *ban;
  if (free_bans) {
    ban = free_bans;
    free_bans = free_bans->next;
  }
  else if (!(ban = MyMalloc(sizeof(*ban))))
    return NULL;
  memset(ban, 0, sizeof(*ban));
  if (banstr)
    DupString(ban->banstr, banstr);
  return ban;
}

/** Deallocate a ban structure.
 * @param[in] ban Ban to deallocate.
 */
void
free_ban(struct Ban *ban)
{
  MyFree(ban->who);
  MyFree(ban->banstr);
  ban->next = free_bans;
  free_bans = ban;
}

/** return the struct Membership* that represents a client on a channel
 * This function finds a struct Membership* which holds the state about
 * a client on a specific channel.  The code is smart enough to iterate
 * over the channels a user is in, or the users in a channel to find the
 * user depending on which is likely to be more efficient.
 *
 * @param chptr	pointer to the channel struct
 * @param cptr pointer to the client struct
 *
 * @returns pointer to the struct Membership representing this client on 
 *          this channel.  Returns NULL if the client is not on the channel.
 *          Returns NULL if the client is actually a server.
 * @see find_channel_member()
 */
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

/** Find the client structure for a nick name (user) 
 * Find the client structure for a nick name (user)
 * using history mechanism if necessary. If the client is not found, an error
 * message (NO SUCH NICK) is generated. If the client was found
 * through the history, chasing will be 1 and otherwise 0.
 *
 * This function was used extensively in the P09 days, and since we now have
 * numeric nicks is no longer quite as important.
 *
 * @param sptr	Pointer to the client that has requested the search
 * @param user	a string represeting the client to be found
 * @param chasing a variable set to 0 if the user was found directly, 
 * 		1 otherwise
 * @returns a pointer the client, or NULL if the client wasn't found.
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

/** build up a hostmask
 * Create a string of form "foo!bar@fubar" given foo, bar and fubar
 * as the parameters.  If NULL, they become "*".
 * @param namebuf the buffer to build the hostmask into.  Must be at least
 * 		  NICKLEN+USERLEN+HOSTLEN+3 charactors long.
 * @param nick The nickname
 * @param name The ident
 * @param host the hostname
 * @returns namebuf
 * @see make_nick_user_ip()
 */
static char *make_nick_user_host(char *namebuf, const char *nick,
				 const char *name, const char *host)
{
#define NUH_BUFSIZE	(NICKLEN + USERLEN + HOSTLEN + 3)
  ircd_snprintf(0, namebuf, NUH_BUFSIZE, "%s!%s@%s", nick, name, host);
  return namebuf;
}

/** Create a hostmask using an IP address
 * Create a string of form "foo!bar@123.456.789.123" given foo, bar and the
 * IP-number as the parameters.  If NULL, they become "*".
 *
 * @param ipbuf Buffer at least NICKLEN+USERLEN+SOCKIPLEN+4 to hold the final
 * 		match.
 * @param nick	The nickname (or NULL for *)
 * @param name	The ident (or NULL for *)
 * @param ip	The IP address
 * @returns ipbuf
 * @see make_nick_user_host()
 */
#define NUI_BUFSIZE	(NICKLEN + USERLEN + SOCKIPLEN + 4)
static char *make_nick_user_ip(char *ipbuf, char *nick, char *name,
			       const struct irc_in_addr *ip)
{
  ircd_snprintf(0, ipbuf, NUI_BUFSIZE, "%s!%s@%s", nick, name, ircd_ntoa(ip));
  return ipbuf;
}

/** Decrement the count of users, and free if empty.
 * Subtract one user from channel i (and free channel * block, if channel 
 * became empty).
 *
 * @param chptr The channel to subtract one from.
 *
 * @returns true  (1) if channel still has members.
 *          false (0) if the channel is now empty.
 */
int sub1_from_channel(struct Channel* chptr)
{
  if (chptr->users > 1)         /* Can be 0, called for an empty channel too */
  {
    assert(0 != chptr->members);
    --chptr->users;
    return 1;
  }

  chptr->users = 0;

  /*
   * Also channels without Apass set need to be kept alive,
   * otherwise Bad Guys(tm) would be able to takeover
   * existing channels too easily, and then set an Apass!
   * However, if a channel without Apass becomes empty
   * then we try to be kind to them and remove possible
   * limiting modes.
   */
  chptr->mode.mode &= ~MODE_INVITEONLY;
  chptr->mode.limit = 0;
  /*
   * We do NOT reset a possible key or bans because when
   * the 'channel owners' can't get in because of a key
   * or ban then apparently there was a fight/takeover
   * on the channel and we want them to contact IRC opers
   * who then will educate them on the use of Apass/upass.
   */

   if (feature_bool(FEAT_OPLEVELS)) {
  if (TStime() - chptr->creationtime < 172800)	/* Channel younger than 48 hours? */
    schedule_destruct_event_1m(chptr);		/* Get rid of it in approximately 4-5 minutes */
  else
    schedule_destruct_event_48h(chptr);		/* Get rid of it in approximately 48 hours */
   } else
       destruct_channel(chptr);

  return 0;
}

/** Destroy an empty channel
 * This function destroys an empty channel, removing it from hashtables,
 * and removing any resources it may have consumed.
 *
 * @param chptr The channel to destroy
 *
 * @returns 0 (success)
 *
 * FIXME: Change to return void, this function never fails.
 */
int destruct_channel(struct Channel* chptr)
{
  struct Ban *ban, *next;

  assert(0 == chptr->members);

  /*
   * Now, find all invite links from channel structure
   */
  while (chptr->invites)
    del_invite(chptr->invites->value.cptr, chptr);

  for (ban = chptr->banlist; ban; ban = next)
  {
    next = ban->next;
    free_ban(ban);
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

/** add a ban to a channel
 *
 * `cptr' must be the client adding the ban.
 *
 * If `change' is true then add `banid' to channel `chptr'.
 * Returns 0 if the ban was added.
 * Returns -2 if the ban already existed and was marked BAN_BURST_WIPEOUT.
 * Return -1 otherwise.
 *
 * Those bans that overlapped with `banid' are flagged with BAN_OVERLAPPED
 * when `change' is false, otherwise they will be removed from the banlist.
 * Subsequently calls to next_overlapped_ban() or next_removed_overlapped_ban()
 * respectively will return these bans until NULL is returned.
 *
 * If `firsttime' is true, the ban list as returned by next_overlapped_ban()
 * is reset (unless a non-zero value is returned, in which case the
 * BAN_OVERLAPPED flag might not have been reset!).
 *
 * @author Run
 * @param cptr 	Client adding the ban
 * @param chptr	Channel to add the ban to
 * @param banid The actual ban.
 * @param change True if adding a ban, false if old bans should just be flagged
 * @param firsttime Reset the next_overlapped_ban() iteration.
 * @returns 
 * 	0 if the ban was added
 * 	-2 if the ban already existed and was marked BAN_BURST_WIPEOUT
 * 	-1 otherwise
 */
int add_banid(struct Client *cptr, struct Channel *chptr, char *banid,
                     int change, int firsttime)
{
  struct Ban*    ban;
  struct Ban**   banp;
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
    len += strlen((*banp)->banstr);
    ++cnt;
    if (((*banp)->flags & BAN_BURST_WIPEOUT))
    {
      if (!strcmp((*banp)->banstr, banid))
      {
        (*banp)->flags &= ~BAN_BURST_WIPEOUT;
        return -2;
      }
    }
    else if (!mmatch((*banp)->banstr, banid))
      return -1;
    if (!mmatch(banid, (*banp)->banstr))
    {
      struct Ban *tmp = *banp;
      if (change)
      {
        if (MyUser(cptr))
        {
          cnt--;
          len -= strlen(tmp->banstr);
        }
        *banp = tmp->next;
        /* These will be sent to the user later as -b */
        tmp->next = removed_bans_list;
        removed_bans_list = tmp;
        removed_bans = 1;
      }
      else if (!(tmp->flags & BAN_BURST_WIPEOUT))
      {
        tmp->flags |= BAN_OVERLAPPED;
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
        (*banp)->flags &= ~BAN_OVERLAPPED;
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
    ban = make_ban(banid);
    ban->next = chptr->banlist;

    if (IsServer(cptr) && feature_bool(FEAT_HIS_BANWHO))
      DupString(ban->who, cli_name(&me));
    else
      DupString(ban->who, cli_name(cptr));
    assert(0 != ban->who);

    ban->when = TStime();
    if ((ip_start = strrchr(banid, '@')) && check_if_ipmask(ip_start + 1))
      ban->flags |= BAN_IPMASK;
    chptr->banlist = ban;

    /*
     * Erase ban-valid-bit
     */
    for (member = chptr->members; member; member = member->next_member)
      ClearBanValid(member);     /* `ban' == channel member ! */
  }
  return 0;
}

/** return the next ban that is removed 
 * @returns the next ban that is removed because of overlapping
 */
struct Ban *next_removed_overlapped_ban(void)
{
  if (prev_ban)
  {
    free_ban(prev_ban);
    prev_ban = 0;
  }
  if ((prev_ban = removed_bans_list))
    removed_bans_list = removed_bans_list->next;
  return prev_ban;
}

/** returns Membership * if a person is joined and not a zombie
 * @param cptr Client
 * @param chptr Channel
 * @returns pointer to the client's struct Membership * on the channel if that
 *          user is a full member of the channel, or NULL otherwise.
 *
 * @see find_member_link()
 */
struct Membership* find_channel_member(struct Client* cptr, struct Channel* chptr)
{
  struct Membership* member;
  assert(0 != chptr);

  member = find_member_link(chptr, cptr);
  return (member && !IsZombie(member)) ? member : 0;
}

/** return true if banned else false.
 *
 * This function returns true if the user is banned on the said channel.
 * This function will check the ban cache if applicable, otherwise will
 * do the comparisons and cache the result.
 *
 * @param cptr  The client to test
 * @param chptr The channel
 * @param member The Membership * of this client on this channel 
 *               (may be NULL if the member is not on the channel).
 */
static int is_banned(struct Client *cptr, struct Channel *chptr,
                     struct Membership* member)
{
  struct Ban*   tmp;
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
  if (IsAccount(cptr))
  {
    if (HasHiddenHost(cptr))
    {
      sr = make_nick_user_host(nu_realhost, cli_name(cptr),
                               (cli_user(cptr))->username,
                               cli_user(cptr)->realhost);
    }
    else
    {
      ircd_snprintf(0, tmphost, HOSTLEN, "%s.%s",
                    cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));
      sr = make_nick_user_host(nu_realhost, cli_name(cptr),
                               cli_user(cptr)->username,
                               tmphost);      
    }
  }

  for (tmp = chptr->banlist; tmp; tmp = tmp->next) {
    if ((tmp->flags & BAN_IPMASK)) {
      if (!ip_s)
        ip_s = make_nick_user_ip(nu_ip, cli_name(cptr),
				 (cli_user(cptr))->username, &cli_ip(cptr));
      if (match(tmp->banstr, ip_s) == 0)
        break;
    }
    if (match(tmp->banstr, s) == 0)
      break;
    else if (sr && match(tmp->banstr, sr) == 0)
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

/** add a user to a channel.
 * adds a user to a channel by adding another link to the channels member
 * chain.
 *
 * @param chptr The channel to add to.
 * @param who   The user to add.
 * @param flags The flags the user gets initially.
 * @param oplevel The oplevel the user starts with.
 */
void add_user_to_channel(struct Channel* chptr, struct Client* who,
                                unsigned int flags, int oplevel)
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
    member->oplevel      = oplevel;

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

    if (chptr->destruct_event)
      remove_destruct_event(chptr);
    ++chptr->users;
    ++((cli_user(who))->joined);
  }
}

/** Remove a person from a channel, given their Membership*
 *
 * @param member A member of a channel.
 *
 * @returns true if there are more people in the channel.
 */
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
   * If this is the last delayed-join user, may have to clear WASDELJOINS.
   */
  if (IsDelayedJoin(member))
    CheckDelayedJoins(chptr);

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

/** Check if all the remaining members on the channel are zombies
 *
 * @returns False if the channel has any non zombie members, True otherwise.
 * @see \ref zombie
 */
static int channel_all_zombies(struct Channel* chptr)
{
  struct Membership* member;

  for (member = chptr->members; member; member = member->next_member) {
    if (!IsZombie(member))
      return 0;
  }
  return 1;
}
      

/** Remove a user from a channel
 * This is the generic entry point for removing a user from a channel, this
 * function will remove the client from the channel, and destory the channel
 * if there are no more normal users left.
 *
 * @param cptr		The client
 * @param chptr		The channel
 */
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

/** Remove a user from all channels they are on.
 *
 * This function removes a user from all channels they are on.
 *
 * @param cptr	The client to remove.
 */
void remove_user_from_all_channels(struct Client* cptr)
{
  struct Membership* chan;
  assert(0 != cptr);
  assert(0 != cli_user(cptr));

  while ((chan = (cli_user(cptr))->channel))
    remove_user_from_channel(cptr, chan->channel);
}

/** Check if this user is a legitimate chanop
 *
 * @param cptr	Client to check
 * @param chptr	Channel to check
 *
 * @returns True if the user is a chanop (And not a zombie), False otherwise.
 * @see \ref zombie
 */
int is_chan_op(struct Client *cptr, struct Channel *chptr)
{
  struct Membership* member;
  assert(chptr);
  if ((member = find_member_link(chptr, cptr)))
    return (!IsZombie(member) && IsChanOp(member));

  return 0;
}

/** Check if a user is a Zombie on a specific channel.
 *
 * @param cptr		The client to check.
 * @param chptr		The channel to check.
 *
 * @returns True if the client (cptr) is a zombie on the channel (chptr),
 * 	    False otherwise.
 *
 * @see \ref zombie
 */
int is_zombie(struct Client *cptr, struct Channel *chptr)
{
  struct Membership* member;

  assert(0 != chptr);

  if ((member = find_member_link(chptr, cptr)))
      return IsZombie(member);
  return 0;
}

/** Returns if a user has voice on a channel.
 *
 * @param cptr 	The client
 * @param chptr	The channel
 *
 * @returns True if the client (cptr) is voiced on (chptr) and is not a zombie.
 * @see \ref zombie
 */
int has_voice(struct Client* cptr, struct Channel* chptr)
{
  struct Membership* member;

  assert(0 != chptr);
  if ((member = find_member_link(chptr, cptr)))
    return (!IsZombie(member) && HasVoice(member));

  return 0;
}

/** Can this member send to a channel
 *
 * A user can speak on a channel iff:
 * <ol>
 *  <li> They didn't use the Apass to gain ops.
 *  <li> They are op'd or voice'd.
 *  <li> You aren't banned.
 *  <li> The channel isn't +m
 *  <li> The channel isn't +n or you are on the channel.
 * </ol>
 *
 * This function will optionally reveal a user on a delayed join channel if
 * they are allowed to send to the channel.
 *
 * @param member	The membership of the user
 * @param reveal	If true, the user will be "revealed" on a delayed
 * 			joined channel. 
 *
 * @returns True if the client can speak on the channel.
 */
int member_can_send_to_channel(struct Membership* member, int reveal)
{
  assert(0 != member);

  /* Discourage using the Apass to get op.  They should use the upass. */
  if (IsChannelManager(member) && *member->channel->mode.upass)
    return 0;

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

  if (IsDelayedJoin(member) && reveal)
    RevealDelayedJoin(member);

  return 1;
}

/** Check if a client can send to a channel.
 *
 * Has the added check over member_can_send_to_channel() of servers can
 * always speak.
 *
 * @param cptr	The client to check
 * @param chptr	The channel to check
 * @param reveal If the user should be revealed (see 
 * 		member_can_send_to_channel())
 *
 * @returns true if the client is allowed to speak on the channel, false 
 * 		otherwise
 *
 * @see member_can_send_to_channel()
 */
int client_can_send_to_channel(struct Client *cptr, struct Channel *chptr, int reveal)
{
  struct Membership *member;
  assert(0 != cptr); 
  /*
   * Servers can always speak on channels.
   */
  if (IsServer(cptr))
    return 1;

  member = find_channel_member(cptr, chptr);

  /*
   * You can't speak if you're off channel, and it is +n (no external messages)
   * or +m (moderated).
   */
  if (!member) {
    if ((chptr->mode.mode & (MODE_NOPRIVMSGS|MODE_MODERATED)) ||
	((chptr->mode.mode & MODE_REGONLY) && !IsAccount(cptr)))
      return 0;
    else
      return !is_banned(cptr, chptr, NULL);
  }
  return member_can_send_to_channel(member, reveal);
}

/** Returns the name of a channel that prevents the user from changing nick.
 * if a member and not (opped or voiced) and (banned or moderated), return
 * the name of the first channel banned on.
 *
 * @param cptr 	The client
 *
 * @returns the name of the first channel banned on, or NULL if the user
 *          can change nicks.
 */
const char* find_no_nickchange_channel(struct Client* cptr)
{
  if (MyUser(cptr)) {
    struct Membership* member;
    for (member = (cli_user(cptr))->channel; member;
	 member = member->next_channel) {
        if (!IsVoicedOrOpped(member) &&
            (is_banned(cptr, member->channel, member) ||
             (member->channel->mode.mode & MODE_MODERATED)))
        return member->channel->chname;
    }
  }
  return 0;
}


/** Fill mbuf/pbuf with modes from chptr
 * write the "simple" list of channel modes for channel chptr onto buffer mbuf
 * with the parameters in pbuf as visible by cptr.
 *
 * This function will hide keys from non-op'd, non-server clients.
 *
 * @param cptr	The client to generate the mode for.
 * @param mbuf	The buffer to write the modes into.
 * @param pbuf  The buffer to write the mode parameters into.
 * @param buflen The length of the buffers.
 * @param chptr	The channel to get the modes from.
 * @param member The membership of this client on this channel (or NULL
 * 		if this client isn't on this channel)
 *
 */
void channel_modes(struct Client *cptr, char *mbuf, char *pbuf, int buflen,
                          struct Channel *chptr, struct Membership *member)
{
  int previous_parameter = 0;

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
  if (chptr->mode.mode & MODE_DELJOINS)
    *mbuf++ = 'D';
  else if (MyUser(cptr) && (chptr->mode.mode & MODE_WASDELJOINS))
    *mbuf++ = 'd';
  if (chptr->mode.limit) {
    *mbuf++ = 'l';
    ircd_snprintf(0, pbuf, buflen, "%u", chptr->mode.limit);
    previous_parameter = 1;
  }

  if (*chptr->mode.key) {
    *mbuf++ = 'k';
    if (previous_parameter)
      strcat(pbuf, " ");
    if (is_chan_op(cptr, chptr) || IsServer(cptr)) {
      strcat(pbuf, chptr->mode.key);
    } else
      strcat(pbuf, "*");
    previous_parameter = 1;
  }
  if (*chptr->mode.apass) {
    *mbuf++ = 'A';
    if (previous_parameter)
      strcat(pbuf, " ");
    if (IsServer(cptr)) {
      strcat(pbuf, chptr->mode.apass);
    } else
      strcat(pbuf, "*");
    previous_parameter = 1;
  }
  if (*chptr->mode.upass) {
    *mbuf++ = 'U';
    if (previous_parameter)
      strcat(pbuf, " ");
    if (IsServer(cptr) || (member && IsChanOp(member) && OpLevel(member) == 0)) {
      strcat(pbuf, chptr->mode.upass);
    } else
      strcat(pbuf, "*");
  }
  *mbuf = '\0';
}

/** Compare two members oplevel
 *
 * @param mp1	Pointer to a pointer to a membership
 * @param mp2	Pointer to a pointer to a membership
 *
 * @returns 0 if equal, -1 if mp1 is lower, +1 otherwise.
 *
 * Used for qsort(3).
 */
int compare_member_oplevel(const void *mp1, const void *mp2)
{
  struct Membership const* member1 = *(struct Membership const**)mp1;
  struct Membership const* member2 = *(struct Membership const**)mp2;
  if (member1->oplevel == member2->oplevel)
    return 0;
  return (member1->oplevel < member2->oplevel) ? -1 : 1;
}

/* send "cptr" a full list of the modes for channel chptr.
 *
 * Sends a BURST line to cptr, bursting all the modes for the channel.
 *
 * @param cptr	Client pointer
 * @param chptr	Channel pointer
 */
void send_channel_modes(struct Client *cptr, struct Channel *chptr)
{
  /* The order in which modes are generated is now mandatory */
  static unsigned int current_flags[4] =
      { 0, CHFL_VOICE, CHFL_CHANOP, CHFL_CHANOP | CHFL_VOICE };
  int                first = 1;
  int                full  = 1;
  int                flag_cnt = 0;
  int                new_mode = 0;
  size_t             len;
  struct Membership* member;
  struct Ban*        lp2;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  struct MsgBuf *mb;
  int                 number_of_ops = 0;
  int                 opped_members_index = 0;
  struct Membership** opped_members = NULL;
  int                 last_oplevel = 0;
  int                 feat_oplevels = (chptr->mode.mode & MODE_APASS) != 0;

  assert(0 != cptr);
  assert(0 != chptr); 

  if (IsLocalChannel(chptr->chname))
    return;

  member = chptr->members;
  lp2 = chptr->banlist;

  *modebuf = *parabuf = '\0';
  channel_modes(cptr, modebuf, parabuf, sizeof(parabuf), chptr, 0);

  for (first = 1; full; first = 0)      /* Loop for multiple messages */
  {
    full = 0;                   /* Assume by default we get it
                                 all in one message */

    /* (Continued) prefix: "<Y> B <channel> <TS>" */
    /* is there any better way we can do this? */
    mb = msgq_make(&me, "%C " TOK_BURST " %H %Tu", &me, chptr,
		   chptr->creationtime);

    if (first && modebuf[1])    /* Add simple modes (Aiklmnpstu)
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
     * First find all opless members.
     * Run 2 times over all members, to group the members with
     * and without voice together.
     * Then run 2 times over all opped members (which are ordered
     * by op-level) to also group voice and non-voice together.
     */
    for (first = 1; flag_cnt < 4; new_mode = 1, ++flag_cnt)
    {
      while (member)
      {
	if (flag_cnt < 2 && IsChanOp(member))
	{
	  /*
	   * The first loop (to find all non-voice/op), we count the ops.
	   * The second loop (to find all voiced non-ops), store the ops
	   * in a dynamic array.
	   */
	  if (flag_cnt == 0)
	    ++number_of_ops;
	  else
	    opped_members[opped_members_index++] = member;
	}
	/* Only handle the members with the flags that we are interested in. */
        if ((member->status & CHFL_VOICED_OR_OPPED) == current_flags[flag_cnt])
	{
	  if (msgq_bufleft(mb) < NUMNICKLEN + 3 + MAXOPLEVELDIGITS)
	    /* The 3 + MAXOPLEVELDIGITS is a possible ",:v999". */
	  {
	    full = 1;           /* Make sure we continue after
				   sending it so far */
	    /* Ensure the new BURST line contains the current
	     * ":mode", except when there is no mode yet. */
	    new_mode = (flag_cnt > 0) ? 1 : 0;
	    break;              /* Do not add this member to this message */
	  }
	  msgq_append(&me, mb, "%c%C", first ? ' ' : ',', member->user);
	  first = 0;              /* From now on, use commas to add new nicks */

	  /*
	   * Do we have a nick with a new mode ?
	   * Or are we starting a new BURST line?
	   */
	  if (new_mode || !feat_oplevels)
	  {
	    /*
	     * This means we are at the _first_ member that has only
	     * voice, or the first member that has only ops, or the
	     * first member that has voice and ops (so we get here
	     * at most three times, plus once for every start of
	     * a continued BURST line where only these modes is current.
	     * In the two cases where the current mode includes ops,
	     * we need to add the _absolute_ value of the oplevel to the mode.
	     */
	    char tbuf[3 + MAXOPLEVELDIGITS] = ":";
	    int loc = 1;

	    if (HasVoice(member))	/* flag_cnt == 1 or 3 */
	      tbuf[loc++] = 'v';
	    if (IsChanOp(member))	/* flag_cnt == 2 or 3 */
	    {
              /* append the absolute value of the oplevel */
              if (feat_oplevels)
                loc += ircd_snprintf(0, tbuf + loc, sizeof(tbuf) - loc, "%u", last_oplevel = member->oplevel);
              else
                tbuf[loc++] = 'o';
	    }
	    tbuf[loc] = '\0';
	    msgq_append(&me, mb, tbuf);
	    new_mode = 0;
	  }
	  else if (flag_cnt > 1 && last_oplevel != member->oplevel)
	  {
	    /*
	     * This can't be the first member of a (continued) BURST
	     * message because then either flag_cnt == 0 or new_mode == 1
	     * Now we need to append the incremental value of the oplevel.
	     */
            char tbuf[2 + MAXOPLEVELDIGITS];
	    ircd_snprintf(0, tbuf, sizeof(tbuf), ":%u", member->oplevel - last_oplevel);
	    last_oplevel = member->oplevel;
	    msgq_append(&me, mb, tbuf);
	  }
	}
	/* Go to the next `member'. */
	if (flag_cnt < 2)
	  member = member->next_member;
	else
	  member = opped_members[++opped_members_index];
      }
      if (full)
	break;

      /* Point `member' at the start of the list again. */
      if (flag_cnt == 0)
      {
	member = chptr->members;
	/* Now, after one loop, we know the number of ops and can
	 * allocate the dynamic array with pointer to the ops. */
	opped_members = (struct Membership**)
	  MyMalloc((number_of_ops + 1) * sizeof(struct Membership*));
	opped_members[number_of_ops] = NULL;	/* Needed for loop termination */
      }
      else
      {
	/* At the end of the second loop, sort the opped members with
	 * increasing op-level, so that we will output them in the
	 * correct order (and all op-level increments stay positive) */
	if (flag_cnt == 1)
	  qsort(opped_members, number_of_ops,
	        sizeof(struct Membership*), compare_member_oplevel);
	/* The third and fourth loop run only over the opped members. */
	member = opped_members[(opped_members_index = 0)];
      }

    } /* loop over 0,+v,+o,+ov */

    if (!full)
    {
      /* Attach all bans, space seperated " :%ban ban ..." */
      for (first = 2; lp2; lp2 = lp2->next)
      {
        len = strlen(lp2->banstr);
	if (msgq_bufleft(mb) < len + 1 + first)
          /* The +1 stands for the added ' '.
           * The +first stands for the added ":%".
           */
        {
          full = 1;
          break;
        }
	msgq_append(&me, mb, " %s%s", first ? ":%" : "",
		    lp2->banstr);
	first = 0;
      }
    }

    send_buffer(cptr, mb, 0);  /* Send this message */
    msgq_clean(mb);
  }                             /* Continue when there was something
                                 that didn't fit (full==1) */
  if (opped_members)
    MyFree(opped_members);
  if (feature_bool(FEAT_TOPIC_BURST) && (chptr->topic[0] != '\0'))
      sendcmdto_one(&me, CMD_TOPIC, cptr, "%H %Tu %Tu :%s", chptr,
                    chptr->creationtime, chptr->topic_time, chptr->topic);
}

/** Canonify a mask.
 * pretty_mask
 *
 * @author Carlo Wood (Run), 
 * 05 Oct 1998.
 *
 * When the nick is longer then NICKLEN, it is cut off (its an error of course).
 * When the user name or host name are too long (USERLEN and HOSTLEN
 * respectively) then they are cut off at the start with a '*'.
 *
 * The following transformations are made:
 *
 * 1)   xxx             -> nick!*@*
 * 2)   xxx.xxx         -> *!*\@host
 * 3)   xxx\!yyy         -> nick!user\@*
 * 4)   xxx\@yyy         -> *!user\@host
 * 5)   xxx!yyy\@zzz     -> nick!user\@host
 *
 * @param mask	The uncanonified mask.
 * @returns The updated mask in a static buffer.
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

/** send a banlist to a client for a channel
 *
 * @param cptr	Client to send the banlist to.
 * @param chptr	Channel whose banlist to send.
 */
static void send_ban_list(struct Client* cptr, struct Channel* chptr)
{
  struct Ban* lp;

  assert(0 != cptr);
  assert(0 != chptr);

  for (lp = chptr->banlist; lp; lp = lp->next)
    send_reply(cptr, RPL_BANLIST, chptr->chname, lp->banstr,
	       lp->who, lp->when);

  send_reply(cptr, RPL_ENDOFBANLIST, chptr->chname);
}

/** Check a key against a keyring.
 * We are now treating the key part of /join channellist key as a key
 * ring; that is, we try one key against the actual channel key, and if that
 * doesn't work, we try the next one, and so on. -Kev -Texaco
 * Returns: 0 on match, 1 otherwise
 * This version contributed by SeKs \<intru@info.polymtl.ca\>
 *
 * @param key		Key to check
 * @param keyring	Comma seperated list of keys
 *
 * @returns True if the key was found and matches, false otherwise.
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

/** Returns if a user can join a channel with a specific key.
 *
 * @param sptr	The client trying to join
 * @param chptr	The channel to join
 * @param key	The key to use
 *
 * @returns any error that occured bitwised OR'd with MAGIC_OPER_OVERRIDE
 *  	    if the oper used the magic key, 0 if no error occured.
 */
int can_join(struct Client *sptr, struct Channel *chptr, char *key)
{
  int overrideJoin = 0;  
  
  /*
   * Now a banned user CAN join if invited -- Nemesi
   * Now a user CAN escape channel limit if invited -- bfriendly
   * Now a user CAN escape anything if invited -- Isomer
   */

  if (IsInvited(sptr, chptr))
    return 0;
  
  /* An oper can force a join on a local channel using "OVERRIDE" as the key. 
     a HACK(4) notice will be sent if he would not have been supposed
     to join normally. */ 
  if (IsLocalChannel(chptr->chname) && HasPriv(sptr, PRIV_WALK_LCHAN) &&
      !BadPtr(key) && compall("OVERRIDE",chptr->mode.key) != 0 &&
      compall("OVERRIDE",key) == 0)
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

/** Remove bells and commas from channel name
 *
 * @param cn	Channel name to clean, modified in place.
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

/** Get a channel block, creating if necessary.
 *  Get Channel block for chname (and allocate a new channel
 *  block, if it didn't exists before).
 *
 * @param cptr		Client joining the channel.
 * @param chname	The name of the channel to join.
 * @param flag		set to CGT_CREATE to create the channel if it doesn't 
 * 			exist
 *
 * @returns NULL if the channel is invalid, doesn't exist and CGT_CREATE 
 * 	wasn't specified or a pointer to the channel structure
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

/** invite a user to a channel.
 *
 * Adds an invite for a user to a channel.  Limits the number of invites
 * to FEAT_MAXCHANNELSPERUSER.  Does not sent notification to the user.
 *
 * @param cptr	The client to be invited.
 * @param chptr	The channel to be invited to.
 */
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

/** Delete an invite
 * Delete Invite block from channel invite list and client invite list
 *
 * @param cptr	Client pointer
 * @param chptr	Channel pointer
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

/** @page zombie Explaination of Zombies
 *
 * Consider:
 * <pre>
 *                     client
 *                       |
 *                       c
 *                       |
 *     X --a--> A --b--> B --d--> D
 *                       |
 *                      who
 * </pre>
 *
 * Where `who' is being KICK-ed by a "KICK" message received by server 'A'
 * via 'a', or on server 'B' via either 'b' or 'c', or on server D via 'd'.
 *
 * a) On server A : set CHFL_ZOMBIE for `who' (lp) and pass on the KICK.
 *    Remove the user immediately when no users are left on the channel.
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
 * <pre>
 *              6
 *              |
 *  1 --- 2 --- 3 --- 4 --- 5
 *        |           |
 *      kicker       who
 * </pre>
 *
 * We also need to turn 'who' into a zombie on servers 1 and 6,
 * because a KICK from 'who' (kicking someone else in that direction)
 * can arrive there afterwards - which should not be bounced itself.
 * Therefore case a) also applies for servers 1 and 6.
 *
 * --Run
 */

/** Turn a user on a channel into a zombie
 * This function turns a user into a zombie (see \ref zombie)
 *
 * @param member  The structure representing this user on this channel.
 * @param who	  The client that is being kicked.
 * @param cptr	  The connection the kick came from.
 * @param sptr    The client that is doing the kicking.
 * @param chptr	  The channel the user is being kicked from.
 */
void make_zombie(struct Membership* member, struct Client* who, 
		struct Client* cptr, struct Client* sptr, struct Channel* chptr)
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

/** returns the number of zombies on a channel
 * @param chptr	Channel to count zombies in.
 *
 * @returns The number of zombies on the channel.
 */
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

/** Concatenate some strings together.
 * This helper function builds an argument string in strptr, consisting
 * of the original string, a space, and str1 and str2 concatenated (if,
 * of course, str2 is not NULL)
 *
 * @param strptr	The buffer to concatenate into
 * @param strptr_i	modified offset to the position to modify
 * @param str1		The string to contatenate from.
 * @param str2		The second string to contatenate from.
 * @param c		Charactor to seperate the string from str1 and str2.
 */
static void
build_string(char *strptr, int *strptr_i, const char *str1,
             const char *str2, char c)
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

/** Flush out the modes
 * This is the workhorse of our ModeBuf suite; this actually generates the
 * output MODE commands, HACK notices, or whatever.  It's pretty complicated.
 *
 * @param mbuf	The mode buffer to flush
 * @param all	If true, flush all modes, otherwise leave partial modes in the
 * 		buffer.
 *
 * @returns 0
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
    MODE_DELJOINS,      'D',
    MODE_WASDELJOINS,   'd',
/*  MODE_KEY,		'k', */
/*  MODE_BAN,		'b', */
    MODE_LIMIT,		'l',
/*  MODE_APASS,		'A', */
/*  MODE_UPASS,		'U', */
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

  /* Ok, if we were given the OPMODE flag, or its a server, hide the source.
   */
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
    } else if (MB_TYPE(mbuf, i) & (MODE_BAN | MODE_APASS | MODE_UPASS)) {
      tmp = strlen(MB_STRING(mbuf, i));

      if ((totalbuflen - tmp) <= 0) /* don't overflow buffer */
	MB_TYPE(mbuf, i) |= MODE_SAVE; /* save for later */
      else {
	char mode_char;
	switch(MB_TYPE(mbuf, i) & (MODE_BAN | MODE_APASS | MODE_UPASS))
	{
	  case MODE_APASS:
	    mode_char = 'A';
	    break;
	  case MODE_UPASS:
	    mode_char = 'U';
	    break;
	  default:
	    mode_char = 'b';
	    break;
	}
	bufptr[(*bufptr_i)++] = mode_char;
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

      /* deal with invisible passwords */
      else if (MB_TYPE(mbuf, i) & (MODE_APASS | MODE_UPASS))
	build_string(strptr, strptr_i, "*", 0, ' ');

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
      sendcmdto_channel_butserv_butone(app_source, CMD_MODE, mbuf->mb_channel, NULL, 0,
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
      else if (MB_TYPE(mbuf, i) & (MODE_KEY | MODE_BAN | MODE_APASS | MODE_UPASS))
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

/** Initialise a modebuf
 * This routine just initializes a ModeBuf structure with the information
 * needed and the options given.
 *
 * @param mbuf		The mode buffer to initialise.
 * @param source	The client that is performing the mode.
 * @param connect	?
 * @param chan		The channel that the mode is being performed upon.
 * @param dest		?
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

  if (IsLocalChannel(chan->chname)) dest &= ~MODEBUF_DEST_SERVER;

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

/** Append a new mode to a modebuf
 * This routine simply adds modes to be added or deleted; do a binary OR
 * with either MODE_ADD or MODE_DEL
 *
 * @param mbuf		Mode buffer
 * @param mode		MODE_ADD or MODE_DEL OR'd with MODE_PRIVATE etc.
 */
void
modebuf_mode(struct ModeBuf *mbuf, unsigned int mode)
{
  assert(0 != mbuf);
  assert(0 != (mode & (MODE_ADD | MODE_DEL)));

  mode &= (MODE_ADD | MODE_DEL | MODE_PRIVATE | MODE_SECRET | MODE_MODERATED |
	   MODE_TOPICLIMIT | MODE_INVITEONLY | MODE_NOPRIVMSGS | MODE_REGONLY |
           MODE_DELJOINS | MODE_WASDELJOINS);

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

/** Append a mode that takes an int argument to the modebuf
 *
 * This routine adds a mode to be added or deleted that takes a unsigned
 * int parameter; mode may *only* be the relevant mode flag ORed with one
 * of MODE_ADD or MODE_DEL
 *
 * @param mbuf		The mode buffer to append to.
 * @param mode		The mode to append.
 * @param uint		The argument to the mode.
 */
void
modebuf_mode_uint(struct ModeBuf *mbuf, unsigned int mode, unsigned int uint)
{
  assert(0 != mbuf);
  assert(0 != (mode & (MODE_ADD | MODE_DEL)));

  if (mode == (MODE_LIMIT | MODE_DEL)) {
      mbuf->mb_rem |= mode;
      return;
  }
  MB_TYPE(mbuf, mbuf->mb_count) = mode;
  MB_UINT(mbuf, mbuf->mb_count) = uint;

  /* when we've reached the maximal count, flush the buffer */
  if (++mbuf->mb_count >=
      (MAXMODEPARAMS - (mbuf->mb_dest & MODEBUF_DEST_DEOP ? 1 : 0)))
    modebuf_flush_int(mbuf, 0);
}

/** append a string mode
 * This routine adds a mode to be added or deleted that takes a string
 * parameter; mode may *only* be the relevant mode flag ORed with one of
 * MODE_ADD or MODE_DEL
 *
 * @param mbuf		The mode buffer to append to.
 * @param mode		The mode to append.
 * @param string	The string parameter to append.
 * @param free		If the string should be free'd later.
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

/** Append a mode on a client to a modebuf.
 * This routine adds a mode to be added or deleted that takes a client
 * parameter; mode may *only* be the relevant mode flag ORed with one of
 * MODE_ADD or MODE_DEL
 *
 * @param mbuf		The modebuf to append the mode to.
 * @param mode		The mode to append.
 * @param client	The client argument to append.
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

/** The exported binding for modebuf_flush()
 *
 * @param mbuf	The mode buffer to flush.
 * 
 * @see modebuf_flush_int()
 */
int
modebuf_flush(struct ModeBuf *mbuf)
{
  struct Membership *memb;

  /* Check if MODE_WASDELJOINS should be set */
  if (!(mbuf->mb_channel->mode.mode & (MODE_DELJOINS | MODE_WASDELJOINS))
      && (mbuf->mb_rem & MODE_DELJOINS)) {
    for (memb = mbuf->mb_channel->members; memb; memb = memb->next_member) {
      if (IsDelayedJoin(memb)) {
          mbuf->mb_channel->mode.mode |= MODE_WASDELJOINS;
          mbuf->mb_add |= MODE_WASDELJOINS;
          mbuf->mb_rem &= ~MODE_WASDELJOINS;
          break;
      }
    }
  }

  return modebuf_flush_int(mbuf, 1);
}

/* This extracts the simple modes contained in mbuf
 *
 * @param mbuf		The mode buffer to extract the modes from.
 * @param buf		The string buffer to write the modes into.
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
    MODE_APASS,		'A',
    MODE_UPASS,		'U',
/*  MODE_BAN,		'b', */
    MODE_LIMIT,		'l',
    MODE_REGONLY,	'r',
    MODE_DELJOINS,      'D',
    0x0, 0x0
  };
  unsigned int add;
  int i, bufpos = 0, len;
  int *flag_p;
  char *key = 0, limitbuf[20];
  char *apass = 0, *upass = 0;

  assert(0 != mbuf);
  assert(0 != buf);

  buf[0] = '\0';

  add = mbuf->mb_add;

  for (i = 0; i < mbuf->mb_count; i++) { /* find keys and limits */
    if (MB_TYPE(mbuf, i) & MODE_ADD) {
      add |= MB_TYPE(mbuf, i) & (MODE_KEY | MODE_LIMIT | MODE_APASS | MODE_UPASS);

      if (MB_TYPE(mbuf, i) & MODE_KEY) /* keep strings */
	key = MB_STRING(mbuf, i);
      else if (MB_TYPE(mbuf, i) & MODE_LIMIT)
	ircd_snprintf(0, limitbuf, sizeof(limitbuf), "%u", MB_UINT(mbuf, i));
      else if (MB_TYPE(mbuf, i) & MODE_UPASS)
	upass = MB_STRING(mbuf, i);
      else if (MB_TYPE(mbuf, i) & MODE_APASS)
	apass = MB_STRING(mbuf, i);
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
    else if (buf[i] == 'U')
      build_string(buf, &bufpos, upass, 0, ' ');
    else if (buf[i] == 'A')
      build_string(buf, &bufpos, apass, 0, ' ');
  }

  buf[bufpos] = '\0';

  return;
}

/** Simple function to invalidate bans
 *
 * This function sets all bans as being valid.
 *
 * @param chan	The channel to operate on.
 */
void
mode_ban_invalidate(struct Channel *chan)
{
  struct Membership *member;

  for (member = chan->members; member; member = member->next_member)
    ClearBanValid(member);
}

/** Simple function to drop invite structures
 *
 * Remove all the invites on the channel.
 *
 * @param chan		Channel to remove invites from.
 *
 */
void
mode_invite_clear(struct Channel *chan)
{
  while (chan->invites)
    del_invite(chan->invites->value.cptr, chan);
}

/* What we've done for mode_parse so far... */
#define DONE_LIMIT	0x01	/**< We've set the limit */
#define DONE_KEY	0x02	/**< We've set the key */
#define DONE_BANLIST	0x04	/**< We've sent the ban list */
#define DONE_NOTOPER	0x08	/**< We've sent a "Not oper" error */
#define DONE_BANCLEAN	0x10	/**< We've cleaned bans... */
#define DONE_UPASS	0x20	/**< We've set user pass */
#define DONE_APASS	0x40	/**< We've set admin pass */

struct ParseState {
  struct ModeBuf *mbuf;
  struct Client *cptr;
  struct Client *sptr;
  struct Channel *chptr;
  struct Membership *member;
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
  struct Ban banlist[MAXPARA];
  struct {
    unsigned int flag;
    struct Client *client;
  } cli_change[MAXPARA];
};

/** Helper function to send "Not oper" or "Not member" messages
 * Here's a helper function to deal with sending along "Not oper" or
 * "Not member" messages
 *
 * @param state 	Parsing State object
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

/** Parse a limit
 * Helper function to convert limits
 *
 * @param state		Parsing state object.
 * @param flag_p	?
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

    if ((int)t_limit<0) /* don't permit a negative limit */
      return;

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

  /* Can't remove a limit that's not there */
  if (state->dir == MODE_DEL && !state->chptr->mode.limit)
    return;
    
  /* Skip if this is a burst and a lower limit than this is set already */
  if ((state->flags & MODE_PARSE_BURST) &&
      (state->chptr->mode.mode & flag_p[0]) &&
      (state->chptr->mode.limit < t_limit))
    return;

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
  while (*s > ' ' && *s != ':' && *s != ',' && t_len--)
    s++;
  *s = '\0';

  if (!*t_str) { /* warn if empty */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +k" :
		       "MODE -k");
    return;
  }

  if (!state->mbuf)
    return;

  /* Skip if this is a burst, we have a key already and the new key is 
   * after the old one alphabetically */
  if ((state->flags & MODE_PARSE_BURST) &&
      *(state->chptr->mode.key) &&
      ircd_strcmp(state->chptr->mode.key, t_str) <= 0)
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
 * Helper function to convert user passes
 */
static void
mode_parse_upass(struct ParseState *state, int *flag_p)
{
  char *t_str, *s;
  int t_len;

  if (MyUser(state->sptr) && state->max_args <= 0) /* drop if too many args */
    return;

  if (state->parc <= 0) { /* warn if not enough args */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +U" :
		       "MODE -U");
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

  /* If a non-service user is trying to force it, refuse. */
  if (state->flags & MODE_PARSE_FORCE && !IsChannelService(state->sptr)) {
    send_reply(state->sptr, ERR_NOTMANAGER, state->chptr->chname,
               "Use /JOIN", state->chptr->chname, " <AdminPass>.");
    return;
  }

  /* If they are not the channel manager, they are not allowed to change it */
  if (MyUser(state->sptr) && !IsChannelManager(state->member)) {
    if (*state->chptr->mode.apass) {
      send_reply(state->sptr, ERR_NOTMANAGER, state->chptr->chname,
	  "Use /JOIN", state->chptr->chname, "<AdminPass>.");
    } else {
      send_reply(state->sptr, ERR_NOTMANAGER, state->chptr->chname,
	  "Re-create the channel.  The channel must be *empty* for",
	  TStime() - state->chptr->creationtime >= 171000 ? "48 contiguous hours" : "a minute or two",
	  "before it can be recreated.");
    }
    return;
  }
 
  if (state->done & DONE_UPASS) /* allow upass to be set only once */
    return;
  state->done |= DONE_UPASS;

  t_len = PASSLEN + 1;

  /* clean up the upass string */
  s = t_str;
  while (*++s > ' ' && *s != ':' && --t_len)
    ;
  *s = '\0';

  if (!*t_str) { /* warn if empty */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +U" :
		       "MODE -U");
    return;
  }

  if (!state->mbuf)
    return;

  if (!(state->flags & MODE_PARSE_FORCE))
    /* can't add the upass while apass is not set */
    if (state->dir == MODE_ADD && !*state->chptr->mode.apass) {
      send_reply(state->sptr, ERR_UPASSNOTSET, state->chptr->chname, state->chptr->chname);
      return;
    }
    /* can't add a upass if one is set, nor can one remove the wrong upass */
    if ((state->dir == MODE_ADD && *state->chptr->mode.upass) ||
	(state->dir == MODE_DEL &&
	 ircd_strcmp(state->chptr->mode.upass, t_str))) {
      send_reply(state->sptr, ERR_KEYSET, state->chptr->chname);
      return;
    }

  if (!(state->flags & MODE_PARSE_WIPEOUT) && state->dir == MODE_ADD &&
      !ircd_strcmp(state->chptr->mode.upass, t_str))
    return; /* no upass change */

  if (state->flags & MODE_PARSE_BOUNCE) {
    if (*state->chptr->mode.upass) /* reset old upass */
      modebuf_mode_string(state->mbuf, MODE_DEL | flag_p[0],
			  state->chptr->mode.upass, 0);
    else /* remove new bogus upass */
      modebuf_mode_string(state->mbuf, MODE_ADD | flag_p[0], t_str, 0);
  } else /* send new upass */
    modebuf_mode_string(state->mbuf, state->dir | flag_p[0], t_str, 0);

  if (state->flags & MODE_PARSE_SET) {
    if (state->dir == MODE_ADD) /* set the new upass */
      ircd_strncpy(state->chptr->mode.upass, t_str, PASSLEN);
    else /* remove the old upass */
      *state->chptr->mode.upass = '\0';
  }
}

/*
 * Helper function to convert admin passes
 */
static void
mode_parse_apass(struct ParseState *state, int *flag_p)
{
  char *t_str, *s;
  int t_len;

  if (MyUser(state->sptr) && state->max_args <= 0) /* drop if too many args */
    return;

  if (state->parc <= 0) { /* warn if not enough args */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +A" :
		       "MODE -A");
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

  /* If a non-service user is trying to force it, refuse. */
  if (state->flags & MODE_PARSE_FORCE && !IsChannelService(state->sptr)) {
    send_reply(state->sptr, ERR_NOTMANAGER, state->chptr->chname,
               "Use /JOIN", state->chptr->chname, " <AdminPass>.");
    return;
  }

  /* Don't allow to change the Apass if the channel is older than 48 hours. */
  if (TStime() - state->chptr->creationtime >= 172800 && !IsAnOper(state->sptr)) {
    send_reply(state->sptr, ERR_CHANSECURED, state->chptr->chname);
    return;
  }

  /* If they are not the channel manager, they are not allowed to change it */
  if (MyUser(state->sptr) && !IsChannelManager(state->member)) {
    if (*state->chptr->mode.apass) {
      send_reply(state->sptr, ERR_NOTMANAGER, state->chptr->chname,
	  "Use /JOIN", state->chptr->chname, "<AdminPass>.");
    } else {
      send_reply(state->sptr, ERR_NOTMANAGER, state->chptr->chname,
	  "Re-create the channel.  The channel must be *empty* for",
	  "at least a whole minute", "before it can be recreated.");
    }
    return;
  }
 
  if (state->done & DONE_APASS) /* allow apass to be set only once */
    return;
  state->done |= DONE_APASS;

  t_len = PASSLEN + 1;

  /* clean up the apass string */
  s = t_str;
  while (*++s > ' ' && *s != ':' && --t_len)
    ;
  *s = '\0';

  if (!*t_str) { /* warn if empty */
    if (MyUser(state->sptr))
      need_more_params(state->sptr, state->dir == MODE_ADD ? "MODE +A" :
		       "MODE -A");
    return;
  }

  if (!state->mbuf)
    return;

  if (!(state->flags & MODE_PARSE_FORCE)) {
    /* can't remove the apass while upass is still set */
    if (state->dir == MODE_DEL && *state->chptr->mode.upass) {
      send_reply(state->sptr, ERR_UPASSSET, state->chptr->chname, state->chptr->chname);
      return;
    }
    /* can't add an apass if one is set, nor can one remove the wrong apass */
    if ((state->dir == MODE_ADD && *state->chptr->mode.apass) ||
	(state->dir == MODE_DEL && ircd_strcmp(state->chptr->mode.apass, t_str))) {
      send_reply(state->sptr, ERR_KEYSET, state->chptr->chname);
      return;
    }
  }

  if (!(state->flags & MODE_PARSE_WIPEOUT) && state->dir == MODE_ADD &&
      !ircd_strcmp(state->chptr->mode.apass, t_str))
    return; /* no apass change */

  if (state->flags & MODE_PARSE_BOUNCE) {
    if (*state->chptr->mode.apass) /* reset old apass */
      modebuf_mode_string(state->mbuf, MODE_DEL | flag_p[0],
			  state->chptr->mode.apass, 0);
    else /* remove new bogus apass */
      modebuf_mode_string(state->mbuf, MODE_ADD | flag_p[0], t_str, 0);
  } else /* send new apass */
    modebuf_mode_string(state->mbuf, state->dir | flag_p[0], t_str, 0);

  if (state->flags & MODE_PARSE_SET) {
    if (state->dir == MODE_ADD) { /* set the new apass */
      /* Make it VERY clear to the user that this is a one-time password */
      ircd_strncpy(state->chptr->mode.apass, t_str, PASSLEN);
      if (MyUser(state->sptr)) {
	send_reply(state->sptr, RPL_APASSWARN,
	    "Channel Admin password (+A) set to '", state->chptr->mode.apass, "'. ",
	    "Are you SURE you want to use this as Admin password? ",
	    "You will NOT be able to change this password anymore once the channel is more than 48 hours old!");
	send_reply(state->sptr, RPL_APASSWARN,
	    "Use \"/MODE ", state->chptr->chname, " -A ", state->chptr->mode.apass,
	    "\" to remove the password and then immediately set a new one. "
	    "IMPORTANT: YOU CANNOT RECOVER THIS PASSWORD, EVER; "
	    "WRITE THE PASSWORD DOWN (don't store this rescue password on disk)! "
	    "Now set the channel user password (+u).");
      }
    } else { /* remove the old apass */
      *state->chptr->mode.apass = '\0';
      if (MyUser(state->sptr))
	send_reply(state->sptr, RPL_APASSWARN,
	    "WARNING: You removed the channel Admin password MODE (+A). ",
	    "If you would disconnect or leave the channel without setting a new password then you will ",
	    "not be able to set it again and lose ownership of this channel! ",
	    "SET A NEW PASSWORD NOW!", "");
    }
  }
}

/*
 * Helper function to convert bans
 */
static void
mode_parse_ban(struct ParseState *state, int *flag_p)
{
  char *t_str, *s;
  struct Ban *ban, *newban = 0;

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

    DupString(newban->banstr, t_str);
    newban->who = cli_name(state->sptr);
    newban->when = TStime();

    newban->flags = BAN_ADD;

    if ((s = strrchr(t_str, '@')) && check_if_ipmask(s + 1))
      newban->flags |= BAN_IPMASK;
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
      ban->flags &= ~(BAN_ADD | BAN_DEL | BAN_OVERLAPPED);

    /* Bit meanings:
     *
     * BAN_ADD		   - Ban was added; if we're bouncing modes,
     *			     then we'll remove it below; otherwise,
     *			     we'll have to allocate a real ban
     *
     * BAN_DEL		   - Ban was marked for deletion; if we're
     *			     bouncing modes, we'll have to re-add it,
     *			     otherwise, we'll have to remove it
     *
     * BAN_OVERLAPPED	   - The ban we added turns out to overlap
     *			     with a ban already set; if we're
     *			     bouncing modes, we'll have to bounce
     *			     this one; otherwise, we'll just ignore
     *			     it when we process added bans
     */

    if (state->dir == MODE_DEL && !ircd_strcmp(ban->banstr, t_str)) {
      ban->flags |= BAN_DEL; /* delete one ban */

      if (state->done & DONE_BANCLEAN) /* If we're cleaning, finish */
	break;
    } else if (state->dir == MODE_ADD) {
      /* if the ban already exists, don't worry about it */
      if (!ircd_strcmp(ban->banstr, t_str)) {
	newban->flags &= ~BAN_ADD; /* don't add ban at all */
        MyFree(newban->banstr); /* stopper a leak */
	state->numbans--; /* deallocate last ban */
	if (state->done & DONE_BANCLEAN) /* If we're cleaning, finish */
	  break;
      } else if (!mmatch(ban->banstr, t_str)) {
	if (!(ban->flags & BAN_DEL))
	  newban->flags |= BAN_OVERLAPPED; /* our ban overlaps */
      } else if (!mmatch(t_str, ban->banstr))
	ban->flags |= BAN_DEL; /* mark ban for deletion: overlapping */

      if (!ban->next && (newban->flags & BAN_ADD))
      {
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
  struct Ban *ban, *newban, *prevban, *nextban;
  int count = 0;
  int len = 0;
  int banlen;
  int changed = 0;

  for (prevban = 0, ban = state->chptr->banlist; ban; ban = nextban) {
    count++;
    banlen = strlen(ban->banstr);
    len += banlen;
    nextban = ban->next;

    if ((ban->flags & (BAN_DEL | BAN_ADD)) == (BAN_DEL | BAN_ADD)) {
      if (prevban)
	prevban->next = 0; /* Break the list; ban isn't a real ban */
      else
	state->chptr->banlist = 0;

      count--;
      len -= banlen;

      MyFree(ban->banstr);

      continue;
    } else if (ban->flags & BAN_DEL) { /* Deleted a ban? */
      modebuf_mode_string(state->mbuf, MODE_DEL | MODE_BAN,
			  ban->banstr,
			  state->flags & MODE_PARSE_SET);

      if (state->flags & MODE_PARSE_SET) { /* Ok, make it take effect */
	if (prevban) /* clip it out of the list... */
	  prevban->next = ban->next;
	else
	  state->chptr->banlist = ban->next;

	count--;
	len -= banlen;

        ban->banstr = NULL; /* do not free this string */
        free_ban(ban);

	changed++;
	continue; /* next ban; keep prevban like it is */
      } else
	ban->flags &= BAN_IPMASK; /* unset other flags */
    } else if (ban->flags & BAN_ADD) { /* adding a ban? */
      if (prevban)
	prevban->next = 0; /* Break the list; ban isn't a real ban */
      else
	state->chptr->banlist = 0;

      /* If we're supposed to ignore it, do so. */
      if (ban->flags & BAN_OVERLAPPED &&
	  !(state->flags & MODE_PARSE_BOUNCE)) {
	count--;
	len -= banlen;
        MyFree(ban->banstr);
      } else {
	if (state->flags & MODE_PARSE_SET && MyUser(state->sptr) &&
	    (len > (feature_int(FEAT_AVBANLEN) * feature_int(FEAT_MAXBANS)) ||
	     count > feature_int(FEAT_MAXBANS))) {
	  send_reply(state->sptr, ERR_BANLISTFULL, state->chptr->chname,
		     ban->banstr);
	  count--;
	  len -= banlen;
          MyFree(ban->banstr);
	} else {
	  /* add the ban to the buffer */
	  modebuf_mode_string(state->mbuf, MODE_ADD | MODE_BAN,
			      ban->banstr,
			      !(state->flags & MODE_PARSE_SET));

	  if (state->flags & MODE_PARSE_SET) { /* create a new ban */
	    newban = make_ban(ban->banstr);
	    DupString(newban->who, ban->who);
	    newban->when = ban->when;
	    newban->flags = ban->flags & BAN_IPMASK;

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

      /* check deop for local user */
      if (MyUser(state->sptr)) {

	/* don't allow local opers to be deopped on local channels */
	if (state->cli_change[i].client != state->sptr &&
	    IsLocalChannel(state->chptr->chname) &&
	    HasPriv(state->cli_change[i].client, PRIV_DEOP_LCHAN)) {
	  send_reply(state->sptr, ERR_ISOPERLCHAN,
		     cli_name(state->cli_change[i].client),
		     state->chptr->chname);
	  continue;
        }

        if (feature_bool(FEAT_OPLEVELS)) {
	/* don't allow to deop members with an op level that is <= our own level */
	if (state->sptr != state->cli_change[i].client		/* but allow to deop oneself */
	        && state->member
		&& OpLevel(member) <= OpLevel(state->member)) {
	    int equal = (OpLevel(member) == OpLevel(state->member));
	    send_reply(state->sptr, ERR_NOTLOWEROPLEVEL,
		       cli_name(state->cli_change[i].client),
		       state->chptr->chname,
		       OpLevel(state->member), OpLevel(member),
		       "deop", equal ? "the same" : "a higher");
	  continue;
	}
      }
    }
    }

    /* set op-level of member being opped */
    if ((state->cli_change[i].flag & (MODE_ADD | MODE_CHANOP)) ==
	(MODE_ADD | MODE_CHANOP)) {
      /* If on a channel with upass set, someone with level x gives ops to someone else,
         then that person gets level x-1.  On other channels, where upass is not set,
	 the level stays the same. */
      int level_increment = *state->chptr->mode.upass ? 1 : 0;
      /* Someone being opped by a server gets op-level 0 */
      int old_level = (state->member == NULL) ? -level_increment : OpLevel(state->member);
      SetOpLevel(member, old_level == MAXOPLEVEL ? MAXOPLEVEL : (old_level + level_increment));
    }

    /* actually effect the change */
    if (state->flags & MODE_PARSE_SET) {
      if (state->cli_change[i].flag & MODE_ADD) {
        if (IsDelayedJoin(member))
          RevealDelayedJoin(member);
	member->status |= (state->cli_change[i].flag &
			   (MODE_CHANOP | MODE_VOICE));
	if (state->cli_change[i].flag & MODE_CHANOP)
	  ClearDeopped(member);
      } else
	member->status &= ~(state->cli_change[i].flag &
			    (MODE_CHANOP | MODE_VOICE));
    }

    /* accumulate the change */
    modebuf_mode_client(state->mbuf, state->cli_change[i].flag,
			state->cli_change[i].client);
  } /* for (i = 0; state->cli_change[i].flags; i++) */
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
    if (flag_p[0] & MODE_DELJOINS) {
      state->add &= ~MODE_WASDELJOINS;
      state->del |= MODE_WASDELJOINS;
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
	   struct Channel *chptr, int parc, char *parv[], unsigned int flags,
	   struct Membership* member)
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
    MODE_APASS,		'A',
    MODE_UPASS,		'U',
    MODE_BAN,		'b',
    MODE_LIMIT,		'l',
    MODE_REGONLY,	'r',
    MODE_DELJOINS,      'D',
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
  state.member = member;
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
    state.banlist[i].who = 0;
    state.banlist[i].when = 0;
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

      case 'A': /* deal with Admin passes */
        if (feature_bool(FEAT_OPLEVELS))
	mode_parse_apass(&state, flag_p);
	break;

      case 'U': /* deal with user passes */
        if (feature_bool(FEAT_OPLEVELS))
	mode_parse_upass(&state, flag_p);
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
      } /* switch (*modestr) */
    } /* for (; *modestr; modestr++) */

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
  } /* while (*modestr) */

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
    if (*state.chptr->mode.upass && !(state.done & DONE_UPASS))
      modebuf_mode_string(state.mbuf, MODE_DEL | MODE_UPASS,
			  state.chptr->mode.upass, 0);
    if (*state.chptr->mode.apass && !(state.done & DONE_APASS))
      modebuf_mode_string(state.mbuf, MODE_DEL | MODE_APASS,
			  state.chptr->mode.apass, 0);
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
    struct Membership *member = find_member_link(chan, jbuf->jb_source);
    if (IsUserParting(member))
      return;
    SetUserParting(member);

    /* Send notification to channel */
    if (!(flags & (CHFL_ZOMBIE | CHFL_DELAYED)))
      sendcmdto_channel_butserv_butone(jbuf->jb_source, CMD_PART, chan, NULL, 0,
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

    if (jbuf->jb_type == JOINBUF_TYPE_PARTALL ||
	is_local) /* got to remove user here */
      remove_user_from_channel(jbuf->jb_source, chan);
  } else {
    /* Add user to channel */
    if ((chan->mode.mode & MODE_DELJOINS) && !(flags & CHFL_VOICED_OR_OPPED))
      add_user_to_channel(chan, jbuf->jb_source, flags | CHFL_DELAYED, 0);
    else
      add_user_to_channel(chan, jbuf->jb_source, flags, 0);

    /* send notification to all servers */
    if (jbuf->jb_type != JOINBUF_TYPE_CREATE && !is_local)
      sendcmdto_serv_butone(jbuf->jb_source, CMD_JOIN, jbuf->jb_connect,
			    "%H %Tu", chan, chan->creationtime);

    if (!((chan->mode.mode & MODE_DELJOINS) && !(flags & CHFL_VOICED_OR_OPPED))) {
      /* Send the notification to the channel */
      sendcmdto_channel_butserv_butone(jbuf->jb_source, CMD_JOIN, chan, NULL, 0, "%H", chan);

      /* send an op, too, if needed */
      if (!MyUser(jbuf->jb_source) && jbuf->jb_type == JOINBUF_TYPE_CREATE)
	sendcmdto_channel_butserv_butone(jbuf->jb_source, CMD_MODE, chan, NULL, 0, "%H +o %C",
					 chan, jbuf->jb_source);
    } else if (MyUser(jbuf->jb_source))
      sendcmdto_one(jbuf->jb_source, CMD_JOIN, jbuf->jb_source, ":%H", chan);
  }

  if (jbuf->jb_type == JOINBUF_TYPE_PARTALL ||
      jbuf->jb_type == JOINBUF_TYPE_JOIN || is_local)
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
int IsInvited(struct Client* cptr, const void* chptr)
{
  struct SLink *lp;

  for (lp = (cli_user(cptr))->invited; lp; lp = lp->next)
    if (lp->value.chptr == chptr)
      return 1;
  return 0;
}

/* RevealDelayedJoin: sends a join for a hidden user */

void RevealDelayedJoin(struct Membership *member) {
  ClearDelayedJoin(member);
  sendcmdto_channel_butserv_butone(member->user, CMD_JOIN, member->channel, member->user, 0, ":%H",
                                   member->channel);
  CheckDelayedJoins(member->channel);
}

/* CheckDelayedJoins: checks and clear +d if necessary */

void CheckDelayedJoins(struct Channel *chan) {
  struct Membership *memb2;
  
  if (chan->mode.mode & MODE_WASDELJOINS) {
    for (memb2=chan->members;memb2;memb2=memb2->next_member)
      if (IsDelayedJoin(memb2))
        break;
    
    if (!memb2) {
      /* clear +d */
      chan->mode.mode &= ~MODE_WASDELJOINS;
      sendcmdto_channel_butserv_butone(&me, CMD_MODE, chan, NULL, 0,
                                       "%H -d", chan);
    }
  }
}
