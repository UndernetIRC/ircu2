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

#include "sys.h"
#include <stdio.h>
#include "h.h"
#include "struct.h"
#include "s_bsd.h"
#include "s_serv.h"
#include "send.h"
#include "s_misc.h"
#include "common.h"
#include "match.h"
#include "s_bsd.h"
#include "list.h"
#include "ircd.h"
#include "channel.h"
#include "bsd.h"
#include "class.h"
#include "s_user.h"
#include "sprintf_irc.h"

RCSTAG_CC("$Id$");

char sendbuf[2048];
static int sentalong[MAXCONNECTIONS];
static int sentalong_marker;
struct SLink *opsarray[32];	/* don't use highest bit unless you change
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

static void dead_link(aClient *to, char *notice)
{
  to->flags |= FLAGS_DEADSOCKET;
  /*
   * If because of BUFFERPOOL problem then clean dbuf's now so that
   * notices don't hurt operators below.
   */
  DBufClear(&to->recvQ);
  DBufClear(&to->sendQ);

  /* Keep a copy of the last comment, for later use... */
  strncpy(LastDeadComment(to), notice, sizeof(LastDeadComment(to)));
  LastDeadComment(to)[sizeof(LastDeadComment(to)) - 1] = 0;

  if (!IsUser(to) && !IsUnknown(to) && !(to->flags & FLAGS_CLOSING))
    sendto_ops("%s for %s", LastDeadComment(to), get_client_name(to, FALSE));
  Debug((DEBUG_ERROR, LastDeadComment(to)));
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
void flush_connections(int fd)
{
  Reg1 int i;
  Reg2 aClient *cptr;

  if (fd == me.fd)
  {
    for (i = highest_fd; i >= 0; i--)
      if ((cptr = loc_clients[i]) && DBufLength(&cptr->sendQ) > 0)
	send_queued(cptr);
  }
  else if (fd >= 0 && (cptr = loc_clients[fd]) && DBufLength(&cptr->sendQ) > 0)
    send_queued(cptr);
}

/*
 * send_queued
 *
 * This function is called from the main select-loop (or whatever)
 * when there is a chance that some output would be possible. This
 * attempts to empty the send queue as far as possible...
 */
void send_queued(aClient *to)
{
#ifndef pyr
  if (to->flags & FLAGS_BLOCKED)
    return;			/* Don't bother */
#endif
  /*
   * Once socket is marked dead, we cannot start writing to it,
   * even if the error is removed...
   */
  if (IsDead(to))
  {
    /*
     * Actually, we should *NEVER* get here--something is
     * not working correct if send_queued is called for a
     * dead socket... --msa
     *
     * But we DO get here since flush_connections() is called
     * from the main loop when a server still had remaining data
     * in its buffer (not ending on a new-line).
     * I rather leave the test here then move it to the main loop
     * though: It wouldn't save cpu and it might introduce a bug :/.
     * --Run
     */
    return;
  }
  while (DBufLength(&to->sendQ) > 0)
  {
    const char *msg;
    size_t len, rlen;
    int tmp;

    msg = dbuf_map(&to->sendQ, &len);
    /* Returns always len > 0 */
    if ((tmp = deliver_it(to, msg, len)) < 0)
    {
      dead_link(to, "Write error, closing link");
      return;
    }
    rlen = tmp;
    dbuf_delete(&to->sendQ, rlen);
    to->lastsq = DBufLength(&to->sendQ) / 1024;
    if (rlen < len)
    {
      to->flags |= FLAGS_BLOCKED;	/* Wait till select() says
					   we can write again */
      break;
    }
  }

  return;
}

/*
 *  send message to single client
 */
void sendto_one(aClient *to, char *pattern, ...)
{
  va_list vl;
  va_start(vl, pattern);
  vsendto_one(to, pattern, vl);
  va_end(vl);
}

void vsendto_one(aClient *to, char *pattern, va_list vl)
{
  vsprintf_irc(sendbuf, pattern, vl);
  sendbufto_one(to);
}

void sendbufto_one(aClient *to)
{
  int len;

  Debug((DEBUG_SEND, "Sending [%s] to %s", sendbuf, to->name));

  if (to->from)
    to = to->from;
  if (IsDead(to))
    return;			/* This socket has already
				   been marked as dead */
  if (to->fd < 0)
  {
    /* This is normal when 'to' was being closed (via exit_client
     *  and close_connection) --Run
     * Print the debug message anyway...
     */
    Debug((DEBUG_ERROR, "Local socket %s with negative fd %d... AARGH!",
	to->name, to->fd));
    return;
  }

  len = strlen(sendbuf);
  if (sendbuf[len - 1] != '\n')
  {
    if (len > 510)
      len = 510;
    sendbuf[len++] = '\r';
    sendbuf[len++] = '\n';
    sendbuf[len] = '\0';
  }

  if (IsMe(to))
  {
    char tmp_sendbuf[sizeof(sendbuf)];

    strcpy(tmp_sendbuf, sendbuf);
    sendto_ops("Trying to send [%s] to myself!", tmp_sendbuf);
    return;
  }

  if (DBufLength(&to->sendQ) > get_sendq(to))
  {
    if (IsServer(to))
      sendto_ops("Max SendQ limit exceeded for %s: "
	  SIZE_T_FMT " > " SIZE_T_FMT,
	  get_client_name(to, FALSE), DBufLength(&to->sendQ), get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  else if (!dbuf_put(&to->sendQ, sendbuf, len))
  {
    dead_link(to, "Buffer allocation error");
    return;
  }
#ifdef GODMODE

  if (!sdbflag && !IsUser(to))
  {
    size_t len = strlen(sendbuf) - 2;	/* Remove "\r\n" */
    sdbflag = 1;
    strncpy(sendbuf2, sendbuf, len);
    sendbuf2[len] = '\0';
    if (len > 402)
    {
      char c = sendbuf2[200];
      sendbuf2[200] = 0;
      sendto_ops("SND:%-8.8s(%.4d): \"%s...%s\"",
	  to->name, len, sendbuf2, &sendbuf2[len - 200]);
      sendbuf2[200] = c;
    }
    else
      sendto_ops("SND:%-8.8s(%.4d): \"%s\"", to->name, len, sendbuf2);
    strcpy(sendbuf, sendbuf2);
    strcat(sendbuf, "\r\n");
    sdbflag = 0;
  }

#endif /* GODMODE */
  /*
   * Update statistics. The following is slightly incorrect
   * because it counts messages even if queued, but bytes
   * only really sent. Queued bytes get updated in SendQueued.
   */
  to->sendM += 1;
  me.sendM += 1;
  if (to->acpt != &me)
    to->acpt->sendM += 1;
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

static void vsendto_prefix_one(register aClient *to, register aClient *from,
    char *pattern, va_list vl)
{
  if (to && from && MyUser(to) && IsUser(from))
  {
    static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
    char *par;
    int flag = 0;
    Reg3 anUser *user = from->user;

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
      if (IsUnixSocket(from))
	strcat(sender, user->host);
      else
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

void sendto_channel_butone(aClient *one, aClient *from, aChannel *chptr,
    char *pattern, ...)
{
  va_list vl;
  Reg1 Link *lp;
  Reg2 aClient *acptr;
  Reg3 int i;

  va_start(vl, pattern);

  ++sentalong_marker;
  for (lp = chptr->members; lp; lp = lp->next)
  {
    acptr = lp->value.cptr;
    if (acptr->from == one ||	/* ...was the one I should skip */
	(lp->flags & CHFL_ZOMBIE) || IsDeaf(acptr))
      continue;
    if (MyConnect(acptr))	/* (It is always a client) */
      vsendto_prefix_one(acptr, from, pattern, vl);
    else if (sentalong[(i = acptr->from->fd)] != sentalong_marker)
    {
      sentalong[i] = sentalong_marker;
      /* Don't send channel messages to links that are still eating
         the net.burst: -- Run 2/1/1997 */
      if (!IsBurstOrBurstAck(acptr->from))
	vsendto_prefix_one(acptr, from, pattern, vl);
    }
  }
  va_end(vl);
  return;
}

void sendto_lchanops_butone(aClient *one, aClient *from, aChannel *chptr,
    char *pattern, ...)
{
  va_list vl;
  Reg1 Link *lp;
  Reg2 aClient *acptr;

  va_start(vl, pattern);

  for (lp = chptr->members; lp; lp = lp->next)
  {
    acptr = lp->value.cptr;
    if (acptr == one ||		/* ...was the one I should skip */
	!(lp->flags & CHFL_CHANOP) ||	/* Skip non chanops */
	(lp->flags & CHFL_ZOMBIE) || IsDeaf(acptr))
      continue;
    if (MyConnect(acptr))	/* (It is always a client) */
      vsendto_prefix_one(acptr, from, pattern, vl);
  }
  va_end(vl);
  return;
}

void sendto_chanopsserv_butone(aClient *one, aClient *from, aChannel *chptr,
    char *pattern, ...)
{
  va_list vl;
  Reg1 Link *lp;
  Reg2 aClient *acptr;
  Reg3 int i;
#ifndef NO_PROTOCOL9
  char target[128];
  char *source, *tp, *msg;
#endif

  va_start(vl, pattern);

  ++sentalong_marker;
  for (lp = chptr->members; lp; lp = lp->next)
  {
    acptr = lp->value.cptr;
    if (acptr->from == acptr ||	/* Skip local clients */
#ifndef NO_PROTOCOL9
	Protocol(acptr->from) < 10 ||	/* Skip P09 links */
#endif
	acptr->from == one ||	/* ...was the one I should skip */
	!(lp->flags & CHFL_CHANOP) ||	/* Skip non chanops */
	(lp->flags & CHFL_ZOMBIE) || IsDeaf(acptr))
      continue;
    if (sentalong[(i = acptr->from->fd)] != sentalong_marker)
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
  tp = va_arg(vl, char *);	/* Channel */
  msg = va_arg(vl, char *);
  for (lp = chptr->members; lp; lp = lp->next)
  {
    acptr = lp->value.cptr;
    if (acptr->from == acptr ||	/* Skip local clients */
	Protocol(acptr->from) > 9 ||	/* Skip P10 servers */
	acptr->from == one ||	/* ...was the one I should skip */
	!(lp->flags & CHFL_CHANOP) ||	/* Skip non chanops */
	(lp->flags & CHFL_ZOMBIE) || IsDeaf(acptr))
      continue;
    if (sentalong[(i = acptr->from->fd)] != sentalong_marker)
    {
      sentalong[i] = sentalong_marker;
      /* Don't send channel messages to links that are
         still eating the net.burst: -- Run 2/1/1997 */
      if (!IsBurstOrBurstAck(acptr->from))
      {
	Link *lp2;
	aClient *acptr2;
	tp = target;
	*tp = 0;
	/* Find all chanops in this direction: */
	for (lp2 = chptr->members; lp2; lp2 = lp2->next)
	{
	  acptr2 = lp2->value.cptr;
	  if (acptr2->from == acptr->from && acptr2->from != one &&
	      (lp2->flags & CHFL_CHANOP) && !(lp2->flags & CHFL_ZOMBIE) &&
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
void sendto_serv_butone(aClient *one, char *pattern, ...)
{
  va_list vl;
  Reg1 Dlink *lp;

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
void sendbufto_serv_butone(aClient *one)
{
  Reg1 Dlink *lp;

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
void sendto_common_channels(aClient *acptr, char *pattern, ...)
{
  va_list vl;
  Reg1 Link *chan;
  Reg2 Link *member;

  va_start(vl, pattern);

  ++sentalong_marker;
  if (acptr->fd >= 0)
    sentalong[acptr->fd] = sentalong_marker;
  /* loop through acptr's channels, and the members on their channels */
  if (acptr->user)
    for (chan = acptr->user->channel; chan; chan = chan->next)
      for (member = chan->value.chptr->members; member; member = member->next)
      {
	Reg3 aClient *cptr = member->value.cptr;
	if (MyConnect(cptr) && sentalong[cptr->fd] != sentalong_marker)
	{
	  sentalong[cptr->fd] = sentalong_marker;
	  vsendto_prefix_one(cptr, acptr, pattern, vl);
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
void sendto_channel_butserv(aChannel *chptr, aClient *from, char *pattern, ...)
{
  va_list vl;
  Reg1 Link *lp;
  Reg2 aClient *acptr;

  for (va_start(vl, pattern), lp = chptr->members; lp; lp = lp->next)
    if (MyConnect(acptr = lp->value.cptr) && !(lp->flags & CHFL_ZOMBIE))
      vsendto_prefix_one(acptr, from, pattern, vl);
  va_end(vl);
  return;
}

/*
 * Send a msg to all ppl on servers/hosts that match a specified mask
 * (used for enhanced PRIVMSGs)
 *
 *  addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */

static int match_it(aClient *one, char *mask, int what)
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
void sendto_match_butone(aClient *one, aClient *from,
    char *mask, int what, char *pattern, ...)
{
  va_list vl;
  Reg1 int i;
  Reg2 aClient *cptr, *acptr;

  va_start(vl, pattern);
  for (i = 0; i <= highest_fd; i++)
  {
    if (!(cptr = loc_clients[i]))
      continue;			/* that clients are not mine */
    if (cptr == one)		/* must skip the origin !! */
      continue;
    if (IsServer(cptr))
    {
      for (acptr = client; acptr; acptr = acptr->next)
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
void sendto_lops_butone(aClient *one, char *pattern, ...)
{
  va_list vl;
  Reg1 aClient *cptr;
  aClient **cptrp;
  int i;
  char nbuf[1024];

  sprintf_irc(nbuf, ":%s NOTICE %%s :*** Notice -- ", me.name);
  va_start(vl, pattern);
  vsprintf_irc(nbuf + strlen(nbuf), pattern, vl);
  va_end(vl);
  for (cptrp = me.serv->client_list, i = 0; i <= me.serv->nn_mask; ++cptrp, ++i)
    if ((cptr = *cptrp) && cptr != one && SendServNotice(cptr))
    {
      sprintf_irc(sendbuf, nbuf, cptr->name);
      sendbufto_one(cptr);
    }
  return;
}

/*
 * sendto_op_mask
 *
 * Sends message to the list indicated by the bitmask field.
 * Don't try to send to more than one list! That is not supported.
 * Xorath 5/1/97
 */
void vsendto_op_mask(register snomask_t mask, const char *pattern, va_list vl)
{
  static char fmt[1024];
  char *fmt_target;
  register int i = 0;		/* so that 1 points to opsarray[0] */
  Link *opslist;

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
void sendbufto_op_mask(snomask_t mask)
{
  register int i = 0;		/* so that 1 points to opsarray[0] */
  Link *opslist;
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
  Reg1 aClient *cptr;
  Reg2 int i;
  char fmt[1024];
  char *fmt_target;

  fmt_target = sprintf_irc(fmt, ":%s NOTICE ", me.name);

  for (i = 0; i <= highest_fd; i++)
    if ((cptr = loc_clients[i]) && !IsServer(cptr) && !IsMe(cptr) &&
	SendServNotice(cptr))
    {
      strcpy(fmt_target, cptr->name);
      strcat(fmt_target, " :*** Notice -- ");
      strcat(fmt_target, pattern);
      vsendto_one(cptr, fmt, vl);
    }

  return;
}

void sendto_op_mask(snomask_t mask, const char *pattern, ...)
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
void sendto_ops_butone(aClient *one, aClient *from, char *pattern, ...)
{
  va_list vl;
  Reg1 int i;
  Reg2 aClient *cptr;

  va_start(vl, pattern);
  ++sentalong_marker;
  for (cptr = client; cptr; cptr = cptr->next)
  {
    /*if (!IsAnOper(cptr)) */
    if (!SendWallops(cptr))
      continue;
    i = cptr->from->fd;		/* find connection oper is on */
    if (sentalong[i] == sentalong_marker)	/* sent message along it already ? */
      continue;
    if (cptr->from == one)
      continue;			/* ...was the one I should skip */
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
void sendto_g_serv_butone(aClient *one, char *pattern, ...)
{
  va_list vl;
  aClient *cptr;
  int i;

  va_start(vl, pattern);
  ++sentalong_marker;
  vsprintf_irc(sendbuf, pattern, vl);
  for (cptr = client; cptr; cptr = cptr->next)
  {
    if (!SendDebug(cptr))
      continue;
    i = cptr->from->fd;		/* find connection user is on */
    if (sentalong[i] == sentalong_marker)	/* sent message along it already ? */
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
void sendto_prefix_one(Reg1 aClient *to, Reg2 aClient *from, char *pattern, ...)
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
void sendto_lowprot_butone(aClient *cptr, int p, char *pattern, ...)
{
  va_list vl;
  Dlink *lp;
  va_start(vl, pattern);
  for (lp = me.serv->down; lp; lp = lp->next)
    if (lp->value.cptr != cptr && Protocol(lp->value.cptr) <= p)
      vsendto_one(lp->value.cptr, pattern, vl);
  va_end(vl);
}

/*
 * Send message to all servers of protocol 'p' and higher.
 */
void sendto_highprot_butone(aClient *cptr, int p, char *pattern, ...)
{
  va_list vl;
  Dlink *lp;
  va_start(vl, pattern);
  for (lp = me.serv->down; lp; lp = lp->next)
    if (lp->value.cptr != cptr && Protocol(lp->value.cptr) >= p)
      vsendto_one(lp->value.cptr, pattern, vl);
  va_end(vl);
}
