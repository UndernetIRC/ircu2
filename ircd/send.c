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
 * for a message to local opers. I can contain only one
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

  /* Keep a copy of the last comment, for later use... */
  ircd_strncpy(LastDeadComment(to), notice, sizeof(LastDeadComment(to) - 1));
  LastDeadComment(to)[sizeof(LastDeadComment(to)) - 1] = '\0';

  if (!IsUser(to) && !IsUnknown(to) && !(to->flags & FLAGS_CLOSING))
    sendto_ops("%s for %s", LastDeadComment(to), to->name);
  Debug((DEBUG_ERROR, LastDeadComment(to)));
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
    size_t len;
    const char* msg = dbuf_map(&to->sendQ, &len);

    if ((len = deliver_it(to, msg, len))) {
      dbuf_delete(&to->sendQ, len);
      to->lastsq = DBufLength(&to->sendQ) / 1024;
      if (IsBlocked(to))
        break;
    }
    else {
      if (IsDead(to))
        dead_link(to, "Write error, closing link");
      break;
    }
  }
}

/*
 *  send message to single client
 */
void sendto_one(struct Client *to, const char* pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_one(to, pattern, vl);
  va_end(vl);
}


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
    size_t len = strlen(buf) - 2;   /* Remove "\r\n" */

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
  size_t len;
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
      sendto_ops("Max SendQ limit exceeded for %s: " SIZE_T_FMT " > " SIZE_T_FMT,
                 to->name, DBufLength(&to->sendQ), get_sendq(to));
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

  /* 
   * Precalculate the buffers we sent to the clients instead of doing an
   * expensive sprintf() per member that we send to.  We still have to
   * use strcpy() which is evil.
   */
  if (IsServer(from)) {
    sprintf(userbuf,":%s %s %s :%s",
        from->name, 
        ((cmd[0] == 'P') ? MSG_PRIVATE : MSG_NOTICE),
        chname, msg);
    sprintf(servbuf,"%s " TOK_PRIVATE " %s :%s",
        NumServ(from), chname, msg);
  } else {
    sprintf(userbuf,":%s!%s@%s %s %s :%s",
      from->name, from->username, from->user->host,
      ((cmd[0] == 'P') ? MSG_PRIVATE : MSG_NOTICE),
      chname, msg);
    sprintf(servbuf,"%s%s %s %s :%s",
      NumNick(from), 
       ((cmd[0] == 'P') ? TOK_PRIVATE : TOK_NOTICE),
     chname, msg);
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
 * sendto_server_butone
 *
 * Send a message to all connected servers except the client 'one'.
 */
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
 */
void sendto_channel_butserv(struct Channel *chptr, struct Client *from, const char* pattern, ...)
{
  va_list vl;
  struct Membership* member;
  struct Client *acptr;
  
  va_start(vl, pattern);

  for (member = chptr->members; member; member = member->next_member) {
    if (MyConnect(acptr = member->user) && !IsZombie(member))
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

void sendto_op_mask(unsigned int mask, const char *pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_op_mask(mask, pattern, vl);
  va_end(vl);
}

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
