/*
 * IRC - Internet Relay Chat, common/send.c
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

#include "send.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numnicks.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "struct.h"
#include "sys.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>


static int sentalong[MAXCONNECTIONS];
static int sentalong_marker;
struct SLink *opsarray[32];     /* don't use highest bit unless you change
				   atoi to strtoul in sendto_op_mask() */
static struct Connection *send_queues = 0;

/*
 * dead_link
 *
 * An error has been detected. The link *must* be closed,
 * but *cannot* call ExitClient (m_bye) from here.
 * Instead, mark it with FLAG_DEADSOCKET. This should
 * generate ExitClient from the main loop.
 *
 * If 'notice' is not NULL, it is assumed to be a format
 * for a message to local opers. It can contain only one
 * '%s', which will be replaced by the sockhost field of
 * the failing link.
 *
 * Also, the notice is skipped for "uninteresting" cases,
 * like Persons and yet unknown connections...
 */

static void dead_link(struct Client *to, char *notice)
{
  SetFlag(to, FLAG_DEADSOCKET);
  /*
   * If because of BUFFERPOOL problem then clean dbuf's now so that
   * notices don't hurt operators below.
   */
  DBufClear(&(cli_recvQ(to)));
  MsgQClear(&(cli_sendQ(to)));
  client_drop_sendq(cli_connect(to));

  /*
   * Keep a copy of the last comment, for later use...
   */
  ircd_strncpy(cli_info(to), notice, REALLEN);

  if (!IsUser(to) && !IsUnknown(to) && !HasFlag(to, FLAG_CLOSING))
    sendto_opmask_butone(0, SNO_OLDSNO, "%s for %s", cli_info(to), cli_name(to));
  Debug((DEBUG_ERROR, cli_info(to)));
}

static int can_send(struct Client* to)
{
  assert(0 != to);
  return (IsDead(to) || IsMe(to) || -1 == cli_fd(to)) ? 0 : 1;
}

/* This helper routine kills the connection with the highest sendq, to
 * try to free up some buffer memory.
 */
void kill_highest_sendq(int servers_too)
{
  int i;
  unsigned int highest_sendq = 0;
  struct Client *highest_client = 0;

  for (i = HighestFd; i >= 0; i--) {
    if (!LocalClientArray[i] || (!servers_too && cli_serv(LocalClientArray[i])))
      continue; /* skip servers */

    /* If this sendq is higher than one we last saw, remember it */
    if (MsgQLength(&(cli_sendQ(LocalClientArray[i]))) > highest_sendq) {
      highest_client = LocalClientArray[i];
      highest_sendq = MsgQLength(&(cli_sendQ(highest_client)));
    }
  }

  if (highest_client)
    dead_link(highest_client, "Buffer allocation error");
}

/*
 * flush_connections
 *
 * Used to empty all output buffers for all connections. Should only
 * be called once per scan of connections. There should be a select in
 * here perhaps but that means either forcing a timeout or doing a poll.
 * When flushing, all we do is empty the obuffer array for each local
 * client and try to send it. if we cant send it, it goes into the sendQ
 * -avalon
 */
void flush_connections(struct Client* cptr)
{
  if (cptr) {
    send_queued(cptr);
  }
  else {
    struct Connection* con;
    for (con = send_queues; con; con = con_next(con)) {
      assert(0 < MsgQLength(&(con_sendQ(con))));
      send_queued(con_client(con));
    }
  }
}

/*
 * send_queued
 *
 * This function is called from the main select-loop (or whatever)
 * when there is a chance that some output would be possible. This
 * attempts to empty the send queue as far as possible...
 */
void send_queued(struct Client *to)
{
  assert(0 != to);
  assert(0 != cli_local(to));

  if (IsBlocked(to) || !can_send(to))
    return;                     /* Don't bother */

  while (MsgQLength(&(cli_sendQ(to))) > 0) {
    unsigned int len;

    if ((len = deliver_it(to, &(cli_sendQ(to))))) {
      msgq_delete(&(cli_sendQ(to)), len);
      cli_lastsq(to) = MsgQLength(&(cli_sendQ(to))) / 1024;
      if (IsBlocked(to)) {
	update_write(to);
        return;
      }
    }
    else {
      if (IsDead(to)) {
        char tmp[512];
        sprintf(tmp,"Write error: %s",(strerror(cli_error(to))) ? (strerror(cli_error(to))) : "Unknown error" );
        dead_link(to, tmp);
      }
      return;
    }
  }

  /* Ok, sendq is now empty... */
  client_drop_sendq(cli_connect(to));
  update_write(to);
}

void send_buffer(struct Client* to, struct MsgBuf* buf, int prio)
{
  assert(0 != to);
  assert(0 != buf);

  if (cli_from(to))
    to = cli_from(to);

  if (!can_send(to))
    /*
     * This socket has already been marked as dead
     */
    return;

  if (MsgQLength(&(cli_sendQ(to))) > get_sendq(to)) {
    if (IsServer(to))
      sendto_opmask_butone(0, SNO_OLDSNO, "Max SendQ limit exceeded for %C: "
			   "%zu > %zu", to, MsgQLength(&(cli_sendQ(to))),
			   get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  Debug((DEBUG_SEND, "Sending [%p] to %s", buf, cli_name(to)));

  msgq_add(&(cli_sendQ(to)), buf, prio);
  client_add_sendq(cli_connect(to), &send_queues);
  update_write(to);

  /*
   * Update statistics. The following is slightly incorrect
   * because it counts messages even if queued, but bytes
   * only really sent. Queued bytes get updated in SendQueued.
   */
  ++(cli_sendM(to));
  ++(cli_sendM(&me));
  /*
   * This little bit is to stop the sendQ from growing too large when
   * there is no need for it to. Thus we call send_queued() every time
   * 2k has been added to the queue since the last non-fatal write.
   * Also stops us from deliberately building a large sendQ and then
   * trying to flood that link with data (possible during the net
   * relinking done by servers with a large load).
   */
  if (MsgQLength(&(cli_sendQ(to))) / 1024 > cli_lastsq(to))
    send_queued(to);
}

/*
 * Send a msg to all ppl on servers/hosts that match a specified mask
 * (used for enhanced PRIVMSGs)
 *
 *  addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */

static int match_it(struct Client *from, struct Client *one, const char *mask, int what)
{
  switch (what)
  {
    case MATCH_HOST:
      return (match(mask, cli_user(one)->host) == 0 ||
        (HasHiddenHost(one) && match(mask, cli_user(one)->realhost) == 0));
    case MATCH_SERVER:
    default:
      return (match(mask, cli_name(cli_user(one)->server)) == 0);
  }
}

/*
 * Send a raw command to a single client; use *ONLY* if you absolutely
 * must send a command without a prefix.
 */
void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  struct MsgBuf *mb;
  va_list vl;

  va_start(vl, pattern);
  mb = msgq_vmake(to, pattern, vl);
  va_end(vl);

  send_buffer(to, mb, 0);

  msgq_clean(mb);
}

/*
 * Send a (prefixed) command to a single client; select which of <cmd>
 * <tok> to use depending on if to is a server or not.  <from> is the
 * originator of the command.
 */
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		 &vd);

  va_end(vd.vd_args);

  send_buffer(to, mb, 0);

  msgq_clean(mb);
}

/*
 * Send a (prefixed) command to a single client in the priority queue;
 * select  which of <cmd> <tok> to use depending on if to is a server
 *or not.  <from> is the originator of the command.
 */
void sendcmdto_prio_one(struct Client *from, const char *cmd, const char *tok,
			struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		 &vd);

  va_end(vd.vd_args);

  send_buffer(to, mb, 1);

  msgq_clean(mb);
}

/*
 * Send a (prefixed) command to all servers but one, using tok; cmd
 * is ignored in this particular function.
 */
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
			   const char *tok, struct Client *one,
			   const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct DLink *lp;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* use token */
  mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send it to our downlinks */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    send_buffer(lp->value.cptr, mb, 0);
  }

  msgq_clean(mb);
}

/*
 * Send a (prefix) command originating from <from> to all channels
 * <from> is locally on.  <from> must be a user. <tok> is ignored in
 * this function.
 *
 * Update: don't send to 'one', if any. --Vampire
 */
/* XXX sentalong_marker used XXX
 *
 * There is not an easy way to revoke the need for sentalong_marker
 * from this function.  Thoughts and ideas would be welcome... -Kev
 *
 * One possibility would be to internalize the sentalong array; that
 * could be prohibitively big, though.  We could get around that by
 * making one that's the number of connected servers or something...
 * or perhaps by adding a special flag to the servers we've sent a
 * message to, and then a final loop through the connected servers
 * to delete the flag. -Kev
 */
void sendcmdto_common_channels_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Client *one,
				      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *chan;
  struct Membership *member;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_start(vd.vd_args, pattern);

  /* build the buffer */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  sentalong_marker++;
  if (-1 < cli_fd(cli_from(from)))
    sentalong[cli_fd(cli_from(from))] = sentalong_marker;
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan))
      continue;
    for (member = chan->channel->members; member;
	 member = member->next_member)
      if (MyConnect(member->user) && -1 < cli_fd(cli_from(member->user)) &&
          member->user != one &&
	  sentalong[cli_fd(cli_from(member->user))] != sentalong_marker) {
	sentalong[cli_fd(cli_from(member->user))] = sentalong_marker;
	send_buffer(member->user, mb, 0);
      }
  }

  if (MyConnect(from) && from != one)
    send_buffer(from, mb, 0);

  msgq_clean(mb);
}

/*
 * Send a (prefixed) command to all local users on the channel specified
 * by <to>; <tok> is ignored by this function
 *
 * Update: don't send to 'one', if any. --Vampire
 */
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Channel *to,
				      struct Client *one, const char *pattern,
				      ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *member;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the buffer */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (MyConnect(member->user) && member->user != one && !IsZombie(member))
      send_buffer(member->user, mb, 0);
  }

  msgq_clean(mb);
}

/*
 * Send a (prefixed) command to all users on this channel, including
 * remote users; users to skip may be specified by setting appropriate
 * flags in the <skip> argument.  <one> will also be skipped.
 */
/* XXX sentalong_marker used XXX
 *
 * We can drop sentalong_marker from this function by adding a field to
 * channels and to connections; what we do is make a user's connection
 * a "member" of the channel by adding it to the new list, and we use
 * the struct Membership status as a reference count.  Then, to implement
 * this function, we just walk the list of connections.  Unfortunately,
 * this doesn't account for sending only to channel ops, or for not
 * sending to +d users; we could account for that by splitting those
 * counts out, but that would imply adding two more fields (at least) to
 * the struct Membership... -Kev
 */
void sendcmdto_channel_butone(struct Client *from, const char *cmd,
			      const char *tok, struct Channel *to,
			      struct Client *one, unsigned int skip,
			      const char *pattern, ...)
{
  struct Membership *member;
  struct VarData vd;
  struct MsgBuf *user_mb;
  struct MsgBuf *serv_mb;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  user_mb = msgq_make(0, skip & (SKIP_NONOPS | SKIP_NONVOICES) ? "%:#C %s @%v" : "%:#C %s %v",
     from, skip & (SKIP_NONOPS | SKIP_NONVOICES) ? MSG_NOTICE : cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  sentalong_marker++;
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (cli_from(member->user) == one || IsZombie(member) ||
	(skip & SKIP_DEAF && IsDeaf(member->user)) ||
	(skip & SKIP_NONOPS && !IsChanOp(member)) ||
	(skip & SKIP_NONVOICES && !HasVoice(member) && !IsChanOp(member)) ||
	(skip & SKIP_BURST && IsBurstOrBurstAck(cli_from(member->user))) ||
	cli_fd(cli_from(member->user)) < 0 ||
	sentalong[cli_fd(cli_from(member->user))] == sentalong_marker)
      continue;
    sentalong[cli_fd(cli_from(member->user))] = sentalong_marker;

    if (MyConnect(member->user)) /* pick right buffer to send */
      send_buffer(member->user, user_mb, 0);
    else
      send_buffer(member->user, serv_mb, 0);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/*
 * Send a (prefixed) command to all users except <one> that have
 * <flag> set.
 */
void sendwallto_group_butone(struct Client *from, int type, struct Client *one,
			     const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  struct MsgBuf *mb;
  struct DLink *lp;
  char *prefix=NULL;
  char *tok=NULL;
  int i;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  switch (type) {
    	case WALL_DESYNCH:
	  	prefix="";
		tok=TOK_DESYNCH;
		break;
    	case WALL_WALLOPS:
	  	prefix="* ";
		tok=TOK_WALLOPS;
		break;
    	case WALL_WALLUSERS:
	  	prefix="$ ";
		tok=TOK_WALLUSERS;
		break;
	default:
		assert(0);
  }
  mb = msgq_make(0, "%:#C " MSG_WALLOPS " :%s%v", from, prefix,&vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  for (i = 0; i <= HighestFd; i++) {
    if (!(cptr = LocalClientArray[i]) ||
	(cli_fd(cli_from(cptr)) < 0) ||
	(type == WALL_DESYNCH && !HasFlag(cptr, FLAG_DEBUG)) ||
	(type == WALL_WALLOPS &&
	 (!HasFlag(cptr, FLAG_WALLOP) ||
	  (feature_bool(FEAT_HIS_WALLOPS) && !IsAnOper(cptr)))) ||
        (type == WALL_WALLUSERS && !HasFlag(cptr, FLAG_WALLOP)))
      continue; /* skip it */
    send_buffer(cptr, mb, 1);
  }

  msgq_clean(mb);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  mb = msgq_make(&me, "%C %s :%v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    send_buffer(lp->value.cptr, mb, 1);
  }

  msgq_clean(mb);
}

/*
 * Send a (prefixed) command to all users who match <to>, under control
 * of <who>
 */
/* XXX sentalong_marker used XXX
 *
 * This is also a difficult one to solve.  The basic approach would be
 * to walk the client list of each connected server until we find a
 * match--but then, we also have to walk the client list of all the
 * servers behind that one.  We could implement this recursively--or we
 * could add (yet another) field to the connection struct that would be
 * a linked list of clients introduced through that link, and just walk
 * that, making this into an iterative implementation.  Unfortunately,
 * we probably would not be able to use tail recursion for the recursive
 * solution, so a deep network could exhaust our stack space; therefore
 * I favor the extra linked list, even though that increases the
 * complexity of the database. -Kev
 */
void sendcmdto_match_butone(struct Client *from, const char *cmd,
			    const char *tok, const char *to,
			    struct Client *one, unsigned int who,
			    const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  struct MsgBuf *user_mb;
  struct MsgBuf *serv_mb;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  user_mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along */
  sentalong_marker++;
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!IsRegistered(cptr) || cli_from(cptr) == one || IsServer(cptr) ||
	IsMe(cptr) || !match_it(from, cptr, to, who) || cli_fd(cli_from(cptr)) < 0 ||
	sentalong[cli_fd(cli_from(cptr))] == sentalong_marker)
      continue; /* skip it */
    sentalong[cli_fd(cli_from(cptr))] = sentalong_marker;

    if (MyConnect(cptr)) /* send right buffer */
      send_buffer(cptr, user_mb, 0);
    else
      send_buffer(cptr, serv_mb, 0);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/*
 * Send a server notice to all users subscribing to the indicated <mask>
 * except for <one>
 */
void sendto_opmask_butone(struct Client *one, unsigned int mask,
			  const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_opmask_butone(one, mask, pattern, vl);
  va_end(vl);
}

/*
 * Send a server notice to all users subscribing to the indicated <mask>
 * except for <one> - Ratelimited 1 / 30sec
 */
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
				      time_t *rate, const char *pattern, ...)
{
  va_list vl;

  if ((CurrentTime - *rate) < 30) 
    return;
  else 
    *rate = CurrentTime;

  va_start(vl, pattern);
  vsendto_opmask_butone(one, mask, pattern, vl);
  va_end(vl);
    
}


/*
 * Same as above, except called with a variable argument list
 */
void vsendto_opmask_butone(struct Client *one, unsigned int mask,
			   const char *pattern, va_list vl)
{
  struct VarData vd;
  struct MsgBuf *mb;
  int i = 0; /* so that 1 points to opsarray[0] */
  struct SLink *opslist;

  while ((mask >>= 1))
    i++;

  if (!(opslist = opsarray[i]))
    return;

  /*
   * build string; I don't want to bother with client nicknames, so I hope
   * this is ok...
   */
  vd.vd_format = pattern;
  vd.vd_args = vl;
  mb = msgq_make(0, ":%s " MSG_NOTICE " * :*** Notice -- %v", cli_name(&me),
		 &vd);

  for (; opslist; opslist = opslist->next)
    if (opslist->value.cptr != one)
      send_buffer(opslist->value.cptr, mb, 0);

  msgq_clean(mb);
}
