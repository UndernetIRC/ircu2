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
#include "send.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "sprintf_irc.h"
#include "struct.h"
#include "sys.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>


char sendbuf[2048];
static int sentalong[MAXCONNECTIONS];
static int sentalong_marker;
struct SLink *opsarray[32];     /* don't use highest bit unless you change
                                   atoi to strtoul in sendto_op_mask() */
#ifdef GODMODE
char sendbuf2[2048];
int sdbflag;
#endif /* GODMODE */

/*
 * dead_link
 *
 * An error has been detected. The link *must* be closed,
 * but *cannot* call ExitClient (m_bye) from here.
 * Instead, mark it with FLAGS_DEADSOCKET. This should
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
  to->flags |= FLAGS_DEADSOCKET;
  /*
   * If because of BUFFERPOOL problem then clean dbuf's now so that
   * notices don't hurt operators below.
   */
  DBufClear(&to->recvQ);
  DBufClear(&to->sendQ);

  /*
   * Keep a copy of the last comment, for later use...
   */
  ircd_strncpy(to->info, notice, REALLEN);

  if (!IsUser(to) && !IsUnknown(to) && !(to->flags & FLAGS_CLOSING))
    sendto_opmask_butone(0, SNO_OLDSNO, "%s for %s", to->info, to->name);
  Debug((DEBUG_ERROR, to->info));
}

static int can_send(struct Client* to)
{
  assert(0 != to);
  return (IsDead(to) || IsMe(to) || -1 == to->fd) ? 0 : 1;
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
    int i;
    for (i = HighestFd; i >= 0; i--) {
      if ((cptr = LocalClientArray[i]))
        send_queued(cptr);
    }
  }
}

/*
 * flush_sendq_except - run through local client array and flush
 * the sendq for each client, if the address of the client sendq
 * is the same as the one specified, it is skipped. This is used
 * by dbuf_put to try to get some more memory before bailing and
 * causing the client to be disconnected.
 */
void flush_sendq_except(const struct DBuf* one)
{
  int i;
  struct Client* cptr;
  for (i = HighestFd; i >= 0; i--) {
    if ( (cptr = LocalClientArray[i]) && one != &cptr->sendQ)
      send_queued(cptr);
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
  assert(0 != to->local);

  if (IsBlocked(to) || !can_send(to))
    return;                     /* Don't bother */

  while (DBufLength(&to->sendQ) > 0) {
    unsigned int len;
    const char* msg = dbuf_map(&to->sendQ, &len);

    if ((len = deliver_it(to, msg, len))) {
      dbuf_delete(&to->sendQ, len);
      to->lastsq = DBufLength(&to->sendQ) / 1024;
      if (IsBlocked(to))
        break;
    }
    else {
      if (IsDead(to)) {
        char tmp[512];
        sprintf(tmp,"Write error: %s",(strerror(to->error)) ? (strerror(to->error)) : "Unknown error" );
        dead_link(to, tmp);
      }
      break;
    }
  }
}

/*
 *  send message to single client
 */
/* See sendcmdto_one, below */
void sendto_one(struct Client *to, const char* pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_one(to, pattern, vl);
  va_end(vl);
}

/* See vsendcmdto_one, below */
void vsendto_one(struct Client *to, const char* pattern, va_list vl)
{
  vsprintf_irc(sendbuf, pattern, vl);
  sendbufto_one(to);
}

#ifdef GODMODE
static void send_to_god(struct Client* to, const char* buf)
{
  if (!sdbflag && !IsUser(to)) {
    char sbuf2[BUFSIZE + 1];
    unsigned int len = strlen(buf) - 2;   /* Remove "\r\n" */

    sdbflag = 1;
    len = IRCD_MIN(len, BUFSIZE);
    ircd_strncpy(sbuf2, buf, len);
    sbuf2[len] = '\0';

    if (len > 402) {
      char c = sbuf2[200];
      sbuf2[200] = '\0';
      sendto_ops("SND:%-8.8s(%.4d): \"%s...%s\"",
                 to->name, len, sbuf2, &sbuf2[len - 200]);
    }
    else
      sendto_ops("SND:%-8.8s(%.4d): \"%s\"", to->name, len, sbuf2);
    sdbflag = 0;
  }
}
#endif /* GODMODE */

void send_buffer(struct Client* to, char* buf)
{
  unsigned int len;
  assert(0 != to);
  assert(0 != buf);

  if (to->from)
    to = to->from;

  if (!can_send(to))
    /*
     * This socket has already been marked as dead
     */
    return;

  if (DBufLength(&to->sendQ) > get_sendq(to)) {
    if (IsServer(to))
      sendto_opmask_butone(0, SNO_OLDSNO, "Max SendQ limit exceeded for %C: "
			   "%zu > %zu", to, DBufLength(&to->sendQ),
			   get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  Debug((DEBUG_SEND, "Sending [%s] to %s", buf, to->name));

  len = strlen(buf);
  if (buf[len - 1] != '\n') {
    if (len > 510)
      len = 510;
    buf[len++] = '\r';
    buf[len++] = '\n';
    buf[len] = '\0';
  }

  if (0 == dbuf_put(&to->sendQ, buf, len)) {
    dead_link(to, "Buffer allocation error");
    return;
  }

#ifdef GODMODE
  send_to_god(to, buf);
#endif /* GODMODE */
  /*
   * Update statistics. The following is slightly incorrect
   * because it counts messages even if queued, but bytes
   * only really sent. Queued bytes get updated in SendQueued.
   */
  ++to->sendM;
  ++me.sendM;
  /*
   * This little bit is to stop the sendQ from growing too large when
   * there is no need for it to. Thus we call send_queued() every time
   * 2k has been added to the queue since the last non-fatal write.
   * Also stops us from deliberately building a large sendQ and then
   * trying to flood that link with data (possible during the net
   * relinking done by servers with a large load).
   */
  if (DBufLength(&to->sendQ) / 1024 > to->lastsq)
    send_queued(to);
}

void sendbufto_one(struct Client* to)
{
  send_buffer(to, sendbuf);
}

/* See vsendcmdto_one, below */
static void vsendto_prefix_one(struct Client *to, struct Client *from,
    const char* pattern, va_list vl)
{
  if (to && from && MyUser(to) && IsUser(from))
  {
    static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
    char *par;
    int flag = 0;
    struct User *user = from->user;

    par = va_arg(vl, char *);
    strcpy(sender, from->name);
    if (user)
    {
      if (*user->username)
      {
        strcat(sender, "!");
        strcat(sender, user->username);
      }
      if (*user->host && !MyConnect(from))
      {
        strcat(sender, "@");
        strcat(sender, user->host);
        flag = 1;
      }
    }
    /*
     * Flag is used instead of strchr(sender, '@') for speed and
     * also since username/nick may have had a '@' in them. -avalon
     */
    if (!flag && MyConnect(from) && *user->host)
    {
      strcat(sender, "@");
      strcat(sender, from->sockhost);
    }
    *sendbuf = ':';
    strcpy(&sendbuf[1], sender);
    /* Assuming 'pattern' always starts with ":%s ..." */
    vsprintf_irc(sendbuf + strlen(sendbuf), &pattern[3], vl);
  }
  else
    vsprintf_irc(sendbuf, pattern, vl);
  sendbufto_one(to);
}

/* See sendcmdto_channel_butone, below */
void sendto_channel_butone(struct Client *one, struct Client *from, struct Channel *chptr,
    const char* pattern, ...)
{
  va_list vl;
  struct Membership* member;
  struct Client *acptr;
  int i;

  va_start(vl, pattern);

  ++sentalong_marker;
  for (member = chptr->members; member; member = member->next_member)
  {
    acptr = member->user;
    /* ...was the one I should skip */
    if (acptr->from == one || IsZombie(member) || IsDeaf(acptr))
      continue;
    if (MyConnect(acptr))       /* (It is always a client) */
      vsendto_prefix_one(acptr, from, pattern, vl);
    else if (-1 < (i = acptr->from->fd) && sentalong[i] != sentalong_marker)
    {
      sentalong[i] = sentalong_marker;
      /*
       * Don't send channel messages to links that are still eating
       * the net.burst: -- Run 2/1/1997
       */
      if (!IsBurstOrBurstAck(acptr->from))
        vsendto_prefix_one(acptr, from, pattern, vl);
    }
  }
  va_end(vl);
}

/* See sendcmdto_channel_butone, below */
void sendmsgto_channel_butone(struct Client *one, struct Client *from,
                              struct Channel *chptr, const char *sender,
                              const char *cmd, const char *chname, const char *msg)
{
 /*
  * Sends a PRIVMSG/NOTICE to all members on a channel but 'one', translating
  * TOKENS to full messages when sent to local clients. --Gte (12/12/99)
  */
  struct Membership* member;
  struct Client *acptr;
  char userbuf[2048];
  char servbuf[2048];
  int i;
  int flag=-1;

  assert(0 != cmd);
  /* 
   * Precalculate the buffers we sent to the clients instead of doing an
   * expensive sprintf() per member that we send to.  We still have to
   * use strcpy() which is evil.
   */
  if (IsServer(from)) {
    sprintf(userbuf,":%s %s %s :%s",
            from->name, ('P' == *cmd) ? MSG_PRIVATE : MSG_NOTICE, chname, msg);
    sprintf(servbuf,"%s %s %s :%s", NumServ(from), cmd, chname, msg);
  }
  else {
    sprintf(userbuf,":%s!%s@%s %s %s :%s",
            from->name, from->user->username, from->user->host,
            ('P' == *cmd) ? MSG_PRIVATE : MSG_NOTICE, chname, msg);
    sprintf(servbuf,"%s%s %s %s :%s", NumNick(from), cmd, chname, msg);
  }

  ++sentalong_marker;
  for (member = chptr->members; member; member = member->next_member)
  {
    acptr = member->user;
    /* ...was the one I should skip */
    if (acptr->from == one || IsZombie(member) || IsDeaf(acptr))
      continue;
    if (MyConnect(acptr)) {      /* (It is always a client) */
        if (flag!=0)
          strcpy(sendbuf,userbuf);
        flag=0;
        sendbufto_one(acptr);
    }
    else if (-1 < (i = acptr->from->fd) && sentalong[i] != sentalong_marker)
    {
      sentalong[i] = sentalong_marker;
      if (!IsBurstOrBurstAck(acptr->from)) {
        if (flag != 1)
          strcpy(sendbuf,servbuf);
        flag = 1;
        sendbufto_one(acptr);
  }
    } /* of if MyConnect() */
  } /* of for(members) */
}

/* See sendcmdto_channel_butone, below */
void sendto_lchanops_butone(struct Client *one, struct Client *from, struct Channel *chptr,
    const char* pattern, ...)
{
  va_list vl;
  struct Membership* member;
  struct Client *acptr;

  va_start(vl, pattern);

  for (member = chptr->members; member; member = member->next_member)
  {
    acptr = member->user;
    /* ...was the one I should skip */
    if (acptr == one || !IsChanOp(member) || IsZombie(member) || IsDeaf(acptr))
      continue;
    if (MyConnect(acptr))       /* (It is always a client) */
      vsendto_prefix_one(acptr, from, pattern, vl);
  }
  va_end(vl);
  return;
}

/* See sendcmdto_channel_butone, below */
void sendto_chanopsserv_butone(struct Client *one, struct Client *from, struct Channel *chptr,
    const char* pattern, ...)
{
  va_list vl;
  struct Membership* member;
  struct Client *acptr;
  int i;
#ifndef NO_PROTOCOL9
  char  target[128];
  char* source;
  char* tp;
  char* msg;
#endif

  va_start(vl, pattern);

  ++sentalong_marker;
  for (member = chptr->members; member; member = member->next_member)
  {
    acptr = member->user;
    if (acptr->from == acptr || /* Skip local clients */
#ifndef NO_PROTOCOL9
        Protocol(acptr->from) < 10 ||   /* Skip P09 links */
#endif
        acptr->from == one ||   /* ...was the one I should skip */
        !IsChanOp(member) ||   /* Skip non chanops */
        IsZombie(member) || IsDeaf(acptr))
      continue;
    if (-1 < (i = acptr->from->fd) && sentalong[i] != sentalong_marker)
    {
      sentalong[i] = sentalong_marker;
      /* Don't send channel messages to links that are
         still eating the net.burst: -- Run 2/1/1997 */
      if (!IsBurstOrBurstAck(acptr->from))
        vsendto_prefix_one(acptr, from, pattern, vl);
    }
  }

#ifndef NO_PROTOCOL9
  /* Send message to all 2.9 servers */
  /* This is a hack, because it assumes that we know how `vl' is build up */
  source = va_arg(vl, char *);
  tp = va_arg(vl, char *);      /* Channel */
  msg = va_arg(vl, char *);
  for (member = chptr->members; member; member = member->next_member)
  {
    acptr = member->user;
    if (acptr->from == acptr || /* Skip local clients */
        Protocol(acptr->from) > 9 ||    /* Skip P10 servers */
        acptr->from == one ||   /* ...was the one I should skip */
        !IsChanOp(member) ||   /* Skip non chanops */
        IsZombie(member) || IsDeaf(acptr))
      continue;
    if (-1 < (i = acptr->from->fd) && sentalong[i] != sentalong_marker)
    {
      sentalong[i] = sentalong_marker;
      /* Don't send channel messages to links that are
         still eating the net.burst: -- Run 2/1/1997 */
      if (!IsBurstOrBurstAck(acptr->from))
      {
        struct Membership* other_member;
        struct Client* acptr2;
        tp = target;
        *tp = 0;
        /* Find all chanops in this direction: */
        for (other_member = chptr->members; other_member; other_member = other_member->next_member)
        {
          acptr2 = other_member->user;
          if (acptr2->from == acptr->from && acptr2->from != one &&
              IsChanOp(other_member) && !IsZombie(other_member) &&
              !IsDeaf(acptr2))
          {
            int len = strlen(acptr2->name);
            if (tp + len + 2 > target + sizeof(target))
            {
              sendto_prefix_one(acptr, from,
                  ":%s NOTICE %s :%s", source, target, msg);
              tp = target;
              *tp = 0;
            }
            if (*target)
              strcpy(tp++, ",");
            strcpy(tp, acptr2->name);
            tp += len;
          }
        }
        sendto_prefix_one(acptr, from,
            ":%s NOTICE %s :%s", source, target, msg);
      }
    }
  }
#endif

  va_end(vl);
  return;
}

/*
 * sendto_serv_butone
 *
 * Send a message to all connected servers except the client 'one'.
 */
/* See sendcmdto_serv_butone, below */
void sendto_serv_butone(struct Client *one, const char* pattern, ...)
{
  va_list vl;
  struct DLink *lp;

  va_start(vl, pattern);
  vsprintf_irc(sendbuf, pattern, vl);
  va_end(vl);

  for (lp = me.serv->down; lp; lp = lp->next)
  {
    if (one && lp->value.cptr == one->from)
      continue;
    sendbufto_one(lp->value.cptr);
  }

}

/*
 * sendbufto_serv_butone()
 *
 * Send prepared sendbuf to all connected servers except the client 'one'
 *  -Ghostwolf 18-May-97
 */
void sendbufto_serv_butone(struct Client *one)
{
  struct DLink *lp;

  for (lp = me.serv->down; lp; lp = lp->next)
  {
    if (one && lp->value.cptr == one->from)
      continue;
    sendbufto_one(lp->value.cptr);
  }
}


/*
 * sendto_common_channels()
 *
 * Sends a message to all people (inclusing `acptr') on local server
 * who are in same channel with client `acptr'.
 */
/* See sendcmdto_common_channels, below */
void sendto_common_channels(struct Client *acptr, const char* pattern, ...)
{
  va_list vl;
  struct Membership* chan;
  struct Membership* member;

  assert(0 != acptr);
  assert(0 != acptr->from);
  assert(0 != pattern);

  va_start(vl, pattern);

  ++sentalong_marker;
  if (-1 < acptr->from->fd)
    sentalong[acptr->from->fd] = sentalong_marker;
  /*
   * loop through acptr's channels, and the members on their channels
   */
  if (acptr->user) {
    for (chan = acptr->user->channel; chan; chan = chan->next_channel) {
      for (member = chan->channel->members; member; member = member->next_member) {
        struct Client *cptr = member->user;
        int    i;
        if (MyConnect(cptr) && 
            -1 < (i = cptr->fd) && sentalong[i] != sentalong_marker) {
          sentalong[i] = sentalong_marker;
          vsendto_prefix_one(cptr, acptr, pattern, vl);
        }
      }
    }
  }
  if (MyConnect(acptr))
    vsendto_prefix_one(acptr, acptr, pattern, vl);
  va_end(vl);
  return;
}

/*
 * sendto_channel_butserv
 *
 * Send a message to all members of a channel that
 * are connected to this server.
 *
 * This contains a subtle bug; after the first call to vsendto_prefix_one()
 * below, vl is in an indeterminate state, according to ANSI; we'd have to
 * move va_start() and va_end() into the loop to correct the problem.  It's
 * easier, however, just to use sendcmdto_channel_butserv(), which builds a
 * buffer and sends that prepared buffer to each channel member.
 */
/* See sendcmdto_channel_butserv, below */
void sendto_channel_butserv(struct Channel *chptr, struct Client *from, const char* pattern, ...)
{
  va_list vl;
  struct Membership* member;
  struct Client *acptr;
  
  va_start(vl, pattern);

  for (member = chptr->members; member; member = member->next_member) {
    acptr = member->user;
    if (MyConnect(acptr) && !IsZombie(member))
      vsendto_prefix_one(acptr, from, pattern, vl);
  }
  va_end(vl);
  return;
}

/*
 * Send a msg to all ppl on servers/hosts that match a specified mask
 * (used for enhanced PRIVMSGs)
 *
 *  addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */

static int match_it(struct Client *one, const char *mask, int what)
{
  switch (what)
  {
    case MATCH_HOST:
      return (match(mask, one->user->host) == 0);
    case MATCH_SERVER:
    default:
      return (match(mask, one->user->server->name) == 0);
  }
}

/*
 * sendto_match_butone
 *
 * Send to all clients which match the mask in a way defined on 'what';
 * either by user hostname or user servername.
 */
/* See sendcmdto_match_butone, below */
void sendto_match_butone(struct Client *one, struct Client *from,
    const char *mask, int what, const char* pattern, ...)
{
  va_list vl;
  int i;
  struct Client *cptr, *acptr;

  va_start(vl, pattern);
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(cptr = LocalClientArray[i]))
      continue;                 /* that clients are not mine */
    if (cptr == one)            /* must skip the origin !! */
      continue;
    if (IsServer(cptr))
    {
      for (acptr = GlobalClientList; acptr; acptr = acptr->next)
        if (IsUser(acptr) && match_it(acptr, mask, what) && acptr->from == cptr)
          break;
      /* a person on that server matches the mask, so we
       *  send *one* msg to that server ...
       */
      if (acptr == NULL)
        continue;
      /* ... but only if there *IS* a matching person */
    }
    /* my client, does he match ? */
    else if (!(IsUser(cptr) && match_it(cptr, mask, what)))
      continue;
    vsendto_prefix_one(cptr, from, pattern, vl);
  }
  va_end(vl);

  return;
}

/*
 * sendto_lops_butone
 *
 * Send to *local* ops but one.
 */
/* See sendto_opmask_butone, below */
void sendto_lops_butone(struct Client* one, const char* pattern, ...)
{
  va_list         vl;
  struct Client*  cptr;
  struct Client** clients = me.serv->client_list;
  int             i;
  char            nbuf[1024];

  assert(0 != clients);

  sprintf_irc(nbuf, ":%s NOTICE %%s :*** Notice -- ", me.name);
  va_start(vl, pattern);
  vsprintf_irc(nbuf + strlen(nbuf), pattern, vl);
  va_end(vl);

  for (i = 0; i <= me.serv->nn_mask; ++i) {
    if ((cptr = clients[i]) && cptr != one && SendServNotice(cptr)) {
      sprintf_irc(sendbuf, nbuf, cptr->name);
      sendbufto_one(cptr);
    }
  }
}

/*
 * sendto_op_mask
 *
 * Sends message to the list indicated by the bitmask field.
 * Don't try to send to more than one list! That is not supported.
 * Xorath 5/1/97
 */
#ifdef OLD_VSENDTO_OP_MASK
void vsendto_op_mask(unsigned int mask, const char *pattern, va_list vl)
{
  static char fmt[1024];
  char *fmt_target;
  int i = 0;            /* so that 1 points to opsarray[0] */
  struct SLink *opslist;

  while ((mask >>= 1))
    i++;
  if (!(opslist = opsarray[i]))
    return;

  fmt_target = sprintf_irc(fmt, ":%s NOTICE ", me.name);
  do
  {
    strcpy(fmt_target, opslist->value.cptr->name);
    strcat(fmt_target, " :*** Notice -- ");
    strcat(fmt_target, pattern);
    vsendto_one(opslist->value.cptr, fmt, vl);
    opslist = opslist->next;
  }
  while (opslist);
}
#else /* !OLD_VSENDTO_OP_MASK */
void vsendto_op_mask(unsigned int mask, const char *pattern, va_list vl)
{
  vsendto_opmask_butone(0, mask, pattern, vl);
}
#endif /* OLD_VSENDTO_OP_MASK */

/*
 * sendbufto_op_mask
 *
 * Send a prepared sendbuf to the list indicated by the bitmask field.
 * Ghostwolf 16-May-97
 */
void sendbufto_op_mask(unsigned int mask)
{
  int i = 0;            /* so that 1 points to opsarray[0] */
  struct SLink *opslist;
  while ((mask >>= 1))
    i++;
  if (!(opslist = opsarray[i]))
    return;
  do
  {
    sendbufto_one(opslist->value.cptr);
    opslist = opslist->next;
  }
  while (opslist);
}


/*
 * sendto_ops
 *
 * Send to *local* ops only.
 */
/* See vsendto_opmask_butone, below */
void vsendto_ops(const char *pattern, va_list vl)
{
  struct Client *cptr;
  int i;
  char fmt[1024];
  char *fmt_target;

  fmt_target = sprintf_irc(fmt, ":%s NOTICE ", me.name);

  for (i = 0; i <= HighestFd; i++)
    if ((cptr = LocalClientArray[i]) && !IsServer(cptr) &&
        SendServNotice(cptr))
    {
      strcpy(fmt_target, cptr->name);
      strcat(fmt_target, " :*** Notice -- ");
      strcat(fmt_target, pattern);
      vsendto_one(cptr, fmt, vl);
    }
}

/* See sendto_opmask_butone, below */
void sendto_op_mask(unsigned int mask, const char *pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_op_mask(mask, pattern, vl);
  va_end(vl);
}

/* See sendto_opmask_butone, below */
void sendto_ops(const char *pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_op_mask(SNO_OLDSNO, pattern, vl);
  va_end(vl);
}

/*
 * sendto_ops_butone
 *
 * Send message to all operators.
 * one - client not to send message to
 * from- client which message is from *NEVER* NULL!!
 */
void sendto_ops_butone(struct Client *one, struct Client *from, const char *pattern, ...)
{
  va_list vl;
  int i;
  struct Client *cptr;

  va_start(vl, pattern);
  ++sentalong_marker;
  for (cptr = GlobalClientList; cptr; cptr = cptr->next)
  {
    if (!SendWallops(cptr))
      continue;
    i = cptr->from->fd;         /* find connection oper is on */
    if (i < 0 || sentalong[i] == sentalong_marker)       /* sent message along it already ? */
      continue;
    if (cptr->from == one)
      continue;                 /* ...was the one I should skip */
    sentalong[i] = sentalong_marker;
    vsendto_prefix_one(cptr->from, from, pattern, vl);
  }
  va_end(vl);

  return;
}

/*
 * sendto_g_serv_butone
 *
 * Send message to all remote +g users (server links).
 *
 * one - server not to send message to.
 */
void sendto_g_serv_butone(struct Client *one, const char *pattern, ...)
{
  va_list vl;
  struct Client *cptr;
  int i;

  va_start(vl, pattern);
  ++sentalong_marker;
  vsprintf_irc(sendbuf, pattern, vl);
  for (cptr = GlobalClientList; cptr; cptr = cptr->next)
  {
    if (!SendDebug(cptr))
      continue;
    i = cptr->from->fd;         /* find connection user is on */
    if (i < 0 || sentalong[i] == sentalong_marker)       /* sent message along it already ? */
      continue;
    if (MyConnect(cptr))
      continue;
    sentalong[i] = sentalong_marker;
    if (cptr->from == one)
      continue;
    sendbufto_one(cptr);
  }
  va_end(vl);

  return;
}

/*
 * sendto_prefix_one
 *
 * to - destination client
 * from - client which message is from
 *
 * NOTE: NEITHER OF THESE SHOULD *EVER* BE NULL!!
 * -avalon
 */
/* See sendcmdto_one, below */
void sendto_prefix_one(struct Client *to, struct Client *from, const char *pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_prefix_one(to, from, pattern, vl);
  va_end(vl);
}

/*
 * sendto_realops
 *
 * Send to *local* ops only but NOT +s nonopers.
 */
/* See sendto_opmask_butone, below */
void sendto_realops(const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_op_mask(SNO_OLDREALOP, pattern, vl);

  va_end(vl);
  return;
}

/*
 * Send message to all servers of protocol 'p' and lower.
 */
/* See sendcmdto_serv_butone, below */
void sendto_lowprot_butone(struct Client *cptr, int p, const char *pattern, ...)
{
  va_list vl;
  struct DLink *lp;
  va_start(vl, pattern);
  for (lp = me.serv->down; lp; lp = lp->next)
    if (lp->value.cptr != cptr && Protocol(lp->value.cptr) <= p)
      vsendto_one(lp->value.cptr, pattern, vl);
  va_end(vl);
}

/*
 * Send message to all servers of protocol 'p' and higher.
 */
/* See sendcmdto_serv_butone, below */
void sendto_highprot_butone(struct Client *cptr, int p, const char *pattern, ...)
{
  va_list vl;
  struct DLink *lp;
  va_start(vl, pattern);
  for (lp = me.serv->down; lp; lp = lp->next)
    if (lp->value.cptr != cptr && Protocol(lp->value.cptr) >= p)
      vsendto_one(lp->value.cptr, pattern, vl);
  va_end(vl);
}

/*
 * Send a raw command to a single client; use *ONLY* if you absolutely
 * must send a command without a prefix.
 */
void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  char sndbuf[IRC_BUFSIZE];
  va_list vl;

  va_start(vl, pattern);
  ircd_vsnprintf(to, sndbuf, sizeof(sndbuf) - 2, pattern, vl);
  va_end(vl);

  send_buffer(to, sndbuf);
}

/*
 * Send a (prefixed) command to a single client; select which of <cmd>
 * <tok> to use depending on if to is a server or not.  <from> is the
 * originator of the command.
 */
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendcmdto_one(from, cmd, tok, to, pattern, vl);
  va_end(vl);
}

void vsendcmdto_one(struct Client *from, const char *cmd, const char *tok,
		    struct Client *to, const char *pattern, va_list vl)
{
  struct VarData vd;
  char sndbuf[IRC_BUFSIZE];

  to = to->from;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  vd.vd_args = vl;

  ircd_snprintf(to, sndbuf, sizeof(sndbuf) - 2, "%:#C %s %v", from,
		IsServer(to) || IsMe(to) ? tok : cmd, &vd);

  send_buffer(to, sndbuf);
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
  char sndbuf[IRC_BUFSIZE];
  struct DLink *lp;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* use token */
  ircd_snprintf(&me, sndbuf, sizeof(sndbuf) - 2, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send it to our downlinks */
  for (lp = me.serv->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == one->from)
      continue;
    send_buffer(lp->value.cptr, sndbuf);
  }
}

/*
 * Send a (prefix) command originating from <from> to all channels
 * <from> is locally on.  <from> must be a user. <tok> is ignored in
 * this function.
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
void sendcmdto_common_channels(struct Client *from, const char *cmd,
			       const char *tok, const char *pattern, ...)
{
  struct VarData vd;
  char sndbuf[IRC_BUFSIZE];
  struct Membership *chan;
  struct Membership *member;

  assert(0 != from);
  assert(0 != from->from);
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_start(vd.vd_args, pattern);

  /* build the buffer */
  ircd_snprintf(0, sndbuf, sizeof(sndbuf) - 2, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  sentalong_marker++;
  if (-1 < from->from->fd)
    sentalong[from->from->fd] = sentalong_marker;
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = from->user->channel; chan; chan = chan->next_channel)
    for (member = chan->channel->members; member;
	 member = member->next_member)
      if (MyConnect(member->user) && -1 < member->user->from->fd &&
	  sentalong[member->user->from->fd] != sentalong_marker) {
	sentalong[member->user->from->fd] = sentalong_marker;
	send_buffer(member->user, sndbuf);
      }

  if (MyConnect(from))
    send_buffer(from, sndbuf);
}

/*
 * Send a (prefixed) command to all local users on the channel specified
 * by <to>; <tok> is ignored by this function
 */
void sendcmdto_channel_butserv(struct Client *from, const char *cmd,
			       const char *tok, struct Channel *to,
			       const char *pattern, ...)
{
  struct VarData vd;
  char sndbuf[IRC_BUFSIZE];
  struct Membership *member;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the buffer */
  ircd_snprintf(0, sndbuf, sizeof(sndbuf) - 2, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (MyConnect(member->user) && !IsZombie(member))
      send_buffer(member->user, sndbuf);
  }
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
  char userbuf[IRC_BUFSIZE];
  char servbuf[IRC_BUFSIZE];

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  ircd_snprintf(0, userbuf, sizeof(userbuf) - 2,
		skip & SKIP_NONOPS ? "%:#C %s @%v" : "%:#C %s %v", from,
		skip & SKIP_NONOPS ? MSG_NOTICE : cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  ircd_snprintf(&me, servbuf, sizeof(servbuf) - 2, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  sentalong_marker++;
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (member->user->from == one || IsZombie(member) ||
	(skip & SKIP_DEAF && IsDeaf(member->user)) ||
	(skip & SKIP_NONOPS && !IsChanOp(member)) ||
	(skip & SKIP_BURST && IsBurstOrBurstAck(member->user->from)) ||
	member->user->from->fd < 0 ||
	sentalong[member->user->from->fd] == sentalong_marker)
      continue;
    sentalong[member->user->from->fd] = sentalong_marker;

    if (MyConnect(member->user)) /* pick right buffer to send */
      send_buffer(member->user, userbuf);
    else
      send_buffer(member->user, servbuf);
  }
}

/*
 * Send a (prefixed) command to all users except <one> that have
 * <flag> set.
 */
/* XXX sentalong_marker used XXX
 *
 * Again, we can solve this use of sentalong_marker by adding a field
 * to connections--a count of the number of +w users, and another count
 * of +g users.  Then, just walk through the local clients to send
 * those messages, and another walk through the connected servers list,
 * sending only if there's a non-zero count.  No caveats here, either,
 * beyond remembering to decrement the count when a user /quit's or is
 * killed, or a server is squit. -Kev
 */
void sendcmdto_flag_butone(struct Client *from, const char *cmd,
			   const char *tok, struct Client *one,
			   unsigned int flag, const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  char userbuf[IRC_BUFSIZE];
  char servbuf[IRC_BUFSIZE];

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  ircd_snprintf(0, userbuf, sizeof(userbuf) - 2, "%:#C " MSG_WALLOPS " %v",
		from, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  ircd_snprintf(&me, servbuf, sizeof(servbuf) - 2, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  sentalong_marker++;
  for (cptr = GlobalClientList; cptr; cptr = cptr->next) {
    if (cptr->from == one || IsServer(cptr) || !(cptr->flags & flag) ||
	cptr->from->fd < 0 || sentalong[cptr->from->fd] == sentalong_marker)
      continue; /* skip it */
    sentalong[cptr->from->fd] = sentalong_marker;

    if (MyConnect(cptr)) /* send right buffer */
      send_buffer(cptr, userbuf);
    else
      send_buffer(cptr, servbuf);
  }
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
  char userbuf[IRC_BUFSIZE];
  char servbuf[IRC_BUFSIZE];

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  ircd_snprintf(0, userbuf, sizeof(userbuf) - 2, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  ircd_snprintf(&me, servbuf, sizeof(servbuf) - 2, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along */
  sentalong_marker++;
  for (cptr = GlobalClientList; cptr; cptr = cptr->next) {
    if (cptr->from == one || IsServer(cptr) || IsMe(cptr) ||
	!match_it(cptr, to, who) || cptr->from->fd < 0 ||
	sentalong[cptr->from->fd] == sentalong_marker)
      continue; /* skip it */
    sentalong[cptr->from->fd] = sentalong_marker;

    if (MyConnect(cptr)) /* send right buffer */
      send_buffer(cptr, userbuf);
    else
      send_buffer(cptr, servbuf);
  }
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
 * Same as above, except called with a variable argument list
 */
void vsendto_opmask_butone(struct Client *one, unsigned int mask,
			   const char *pattern, va_list vl)
{
  struct VarData vd;
  char sndbuf[IRC_BUFSIZE];
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
  ircd_snprintf(0, sndbuf, sizeof(sndbuf) - 2, ":%s " MSG_NOTICE
		" * :*** Notice -- %v", me.name, &vd);

  for (; opslist; opslist = opslist->next)
    send_buffer(opslist->value.cptr, sndbuf);
}
