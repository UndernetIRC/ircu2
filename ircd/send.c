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
 */
/** @file
 * @brief Send messages to certain targets.
 * @version $Id$
 */
#include "config.h"

#include "send.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
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

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>

/** Last used marker value. */
static int sentalong_marker;
/** Array of users with the corresponding server notice mask bit set. */
struct SLink *opsarray[32];     /* don't use highest bit unless you change
				   atoi to strtoul in sendto_op_mask() */
/** Linked list of all connections with data queued to send. */
static struct Connection *send_queues;

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
/** Mark a client as dead, even if they are not the current message source.
 * This is done by setting the DEADSOCKET flag on the user and letting the
 * main loop perform the actual exit logic.
 * @param[in,out] to Client being killed.
 * @param[in] notice Message for local opers.
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

/** Test whether we can send to a client.
 * @param[in] to Client we want to send to.
 * @return Non-zero if we can send to the client.
 */
static int can_send(struct Client* to)
{
  assert(0 != to);
  return (IsDead(to) || IsMe(to) || IsNotConn(to) || -1 == cli_fd(to)) ? 0 : 1;
}

/** Close the connection with the highest sendq.
 * This should be called when we need to free buffer memory.
 * @param[in] servers_too If non-zero, consider killing servers, too.
 */
void
kill_highest_sendq(int servers_too)
{
  int i;
  unsigned int highest_sendq = 0;
  struct Client *highest_client = 0;

  for (i = HighestFd; i >= 0; i--)
  {
    if (!LocalClientArray[i] || (!servers_too && cli_serv(LocalClientArray[i])))
      continue; /* skip servers */
    
    /* If this sendq is higher than one we last saw, remember it */
    if (MsgQLength(&(cli_sendQ(LocalClientArray[i]))) > highest_sendq)
    {
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
/** Flush data queued for one or all connections.
 * @param[in] cptr Client to flush (if NULL, do all).
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
/** Attempt to send data queued for a client.
 * @param[in] to Client to send data to.
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

/** Try to send a buffer to a client, queueing it if needed.
 * @param[in,out] to Client to send message to.
 * @param[in] buf Message to send.
 * @param[in] prio If non-zero, send as high priority.
 */
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

/** Check whether a client matches a target mask.
 * @param[in] from Client trying to send a message (ignored).
 * @param[in] one Client being considered as a target.
 * @param[in] mask Mask for matching against.
 * @param[in] what Type of match (either MATCH_HOST or MATCH_SERVER).
 * @return Non-zero if \a one matches, zero if not.
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

/** Send an unprefixed line to a client.
 * @param[in] to Client receiving message.
 * @param[in] pattern Format string of message.
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

/** Send a (prefixed) command to a single client.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
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

/**
 * Send a (prefixed) command to a single client in the priority queue.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
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

/**
 * Send a (prefixed) command to all servers matching or not matching a
 * flag but one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] require Only send to servers with this Flag bit set.
 * @param[in] forbid Do not send to servers with this Flag bit set.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
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
    if ((require < FLAG_LAST_FLAG) && !HasFlag(lp->value.cptr, require))
      continue;
    if ((forbid < FLAG_LAST_FLAG) && HasFlag(lp->value.cptr, forbid))
      continue;
    send_buffer(lp->value.cptr, mb, 0);
  }

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to all servers but one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
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

/** Safely increment the sentalong marker.
 * This increments the sentalong marker.  Since new connections will
 * have con_sentalong() == 0, and to avoid confusion when the counter
 * wraps, we reset all sentalong markers to zero when the sentalong
 * marker hits zero.
 * @param[in,out] one Client to mark with new sentalong marker (if any).
 */
static void
bump_sentalong(struct Client *one)
{
  if (!++sentalong_marker)
  {
    int ii;
    for (ii = 0; ii < HighestFd; ++ii)
      if (LocalClientArray[ii])
        cli_sentalong(LocalClientArray[ii]) = 0;
    ++sentalong_marker;
  }
  if (one)
    cli_sentalong(one) = sentalong_marker;
}

/** Send a (prefixed) command to all channels that \a from is on.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
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

  bump_sentalong(from);
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;
    for (member = chan->channel->members; member;
	 member = member->next_member)
      if (MyConnect(member->user)
          && -1 < cli_fd(cli_from(member->user))
          && member->user != one
          && cli_sentalong(member->user) != sentalong_marker) {
	cli_sentalong(member->user) = sentalong_marker;
	send_buffer(member->user, mb, 0);
      }
  }

  if (MyConnect(from) && from != one)
    send_buffer(from, mb, 0);

  msgq_clean(mb);
}

/** Send a (prefixed) command to all local users on a channel.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (ignored).
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_DEAF, SKIP_NONOPS, SKIP_NONVOICES indicating which clients to skip.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Channel *to,
				      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
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
    if (!MyConnect(member->user)
        || member->user == one 
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member)))
        continue;
      send_buffer(member->user, mb, 0);
  }

  msgq_clean(mb);
}

/** Send a (prefixed) command to all servers with users on \a to.
 * Skip \a from and \a one plus those indicated in \a skip.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS and SKIP_NONVOICES indicating which clients to skip.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_servers_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *serv_mb;
  struct Membership *member;

  /* build the buffer */
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%:#C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send the buffer to each server */
  bump_sentalong(one);
  cli_sentalong(from) = sentalong_marker;
  for (member = to->members; member; member = member->next_member) {
    if (MyConnect(member->user)
        || IsZombie(member)
        || cli_fd(cli_from(member->user)) < 0
        || cli_sentalong(member->user) == sentalong_marker
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member)))
      continue;
    cli_sentalong(member->user) = sentalong_marker;
    send_buffer(member->user, serv_mb, 0);
  }
  msgq_clean(serv_mb);
}


/** Send a (prefixed) command to all users on this channel, except for
 * \a one and those matching \a skip.
 * @warning \a pattern must not contain %v.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS, SKIP_NONVOICES, SKIP_DEAF, SKIP_BURST.
 * @param[in] pattern Format string for command arguments.
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
  bump_sentalong(one);
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (IsZombie(member) ||
        (skip & SKIP_DEAF && IsDeaf(member->user)) ||
        (skip & SKIP_NONOPS && !IsChanOp(member)) ||
        (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member)) ||
        (skip & SKIP_BURST && IsBurstOrBurstAck(cli_from(member->user))) ||
        cli_fd(cli_from(member->user)) < 0 ||
        cli_sentalong(member->user) == sentalong_marker)
      continue;
    cli_sentalong(member->user) = sentalong_marker;

    if (MyConnect(member->user)) /* pick right buffer to send */
      send_buffer(member->user, user_mb, 0);
    else
      send_buffer(member->user, serv_mb, 0);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/** Send a (prefixed) WALL of type \a type to all users except \a one.
 * @warning \a pattern must not contain %v.
 * @param[in] from Source of the command.
 * @param[in] type One of WALL_DESYNCH, WALL_WALLOPS or WALL_WALLUSERS.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
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
  int his_wallops;
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
  his_wallops = feature_bool(FEAT_HIS_WALLOPS);
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(cptr = LocalClientArray[i]) ||
	(cli_fd(cli_from(cptr)) < 0) ||
	(type == WALL_DESYNCH && !SendDebug(cptr)) ||
	(type == WALL_WALLOPS &&
         (!SendWallops(cptr) || (his_wallops && !IsAnOper(cptr)))) ||
        (type == WALL_WALLUSERS && !SendWallops(cptr)))
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

/** Send a (prefixed) command to all users matching \a to as \a who.
 * @warning \a pattern must not contain %v.
 * @param[in] from Source of the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination host/server mask.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] who Type of match for \a to (either MATCH_HOST or MATCH_SERVER).
 * @param[in] pattern Format string for command arguments.
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
  bump_sentalong(one);
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!IsRegistered(cptr) || IsServer(cptr) || cli_fd(cli_from(cptr)) < 0 ||
        cli_sentalong(cptr) == sentalong_marker ||
        !match_it(from, cptr, to, who))
      continue; /* skip it */
    cli_sentalong(cptr) = sentalong_marker;

    if (MyConnect(cptr)) /* send right buffer */
      send_buffer(cptr, user_mb, 0);
    else
      send_buffer(cptr, serv_mb, 0);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone(struct Client *one, unsigned int mask,
			  const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_opmask_butone(one, mask, pattern, vl);
  va_end(vl);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one, rate-limited to once per 30 seconds.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in,out] rate Pointer to the last time the message was sent.
 * @param[in] pattern Format string for server notice.
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


/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 * @param[in] vl Argument list for format string.
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
  va_copy(vd.vd_args, vl);
  mb = msgq_make(0, ":%s " MSG_NOTICE " * :*** Notice -- %v", cli_name(&me),
		 &vd);

  for (; opslist; opslist = opslist->next)
    if (opslist->value.cptr != one)
      send_buffer(opslist->value.cptr, mb, 0);

  msgq_clean(mb);
}
