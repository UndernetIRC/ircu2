/*
 * IRC - Internet Relay Chat, ircd/s_auth.c
 * Copyright (C) 1992 Darren Reed
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
#include <sys/socket.h>
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef	UNIXPORT
#include <sys/un.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HPUX
#include <arpa/inet.h>
#endif /* HPUX */
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include "h.h"
#include "res.h"
#include "struct.h"
#include "common.h"
#include "send.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "support.h"
#include "ircd.h"
#include "s_auth.h"
#include "sprintf_irc.h"

RCSTAG_CC("$Id$");

/*
 * start_auth
 *
 * Flag the client to show that an attempt to contact the ident server on
 * the client's host.  The connect and subsequently the socket are all put
 * into 'non-blocking' mode.  Should the connect or any later phase of the
 * identifing process fail, it is aborted and the user is given a username
 * of "unknown".
 */
void start_auth(aClient *cptr)
{
  struct sockaddr_in sock;
  int err;

  Debug((DEBUG_NOTICE, "start_auth(%p) fd %d status %d",
      cptr, cptr->fd, cptr->status));

  alarm(2);
  cptr->authfd = socket(AF_INET, SOCK_STREAM, 0);
  err = errno;
  alarm(0);

  if (cptr->authfd < 0)
  {
#ifdef	USE_SYSLOG
    syslog(LOG_ERR, "Unable to create auth socket for %s:%m",
	get_client_name(cptr, FALSE));
#endif
    Debug((DEBUG_ERROR, "Unable to create auth socket for %s:%s",
	get_client_name(cptr, FALSE), strerror(get_sockerr(cptr))));
    if (!DoingDNS(cptr))
      SetAccess(cptr);
    ircstp->is_abad++;
    return;
  }
  if (cptr->authfd >= (MAXCONNECTIONS - 2))
  {
    close(cptr->authfd);
    cptr->authfd = -1;
    return;
  }

  set_non_blocking(cptr->authfd, cptr);

#ifdef VIRTUAL_HOST
  if (bind(cptr->authfd, (struct sockaddr *)&vserv, sizeof(vserv)) == -1)
  {
    report_error("binding auth stream socket %s: %s", cptr);
    close(cptr->authfd);
    cptr->authfd = -1;
    return;
  }
#endif
  memcpy(&sock.sin_addr, &cptr->ip, sizeof(struct in_addr));

  sock.sin_port = htons(113);
  sock.sin_family = AF_INET;

  alarm((unsigned)4);
  if (connect(cptr->authfd, (struct sockaddr *)&sock,
      sizeof(sock)) == -1 && errno != EINPROGRESS)
  {
    ircstp->is_abad++;
    /*
     * No error report from this...
     */
    alarm((unsigned)0);
    close(cptr->authfd);
    cptr->authfd = -1;
    if (!DoingDNS(cptr))
      SetAccess(cptr);
    return;
  }
  alarm((unsigned)0);
  cptr->flags |= (FLAGS_WRAUTH | FLAGS_AUTH);
  if (cptr->authfd > highest_fd)
    highest_fd = cptr->authfd;
  return;
}

/*
 * send_authports
 *
 * Send the ident server a query giving "theirport , ourport".
 * The write is only attempted *once* so it is deemed to be a fail if the
 * entire write doesn't write all the data given.  This shouldnt be a
 * problem since the socket should have a write buffer far greater than
 * this message to store it in should problems arise. -avalon
 */
void send_authports(aClient *cptr)
{
  struct sockaddr_in us, them;
  char authbuf[32];
  size_t ulen, tlen;

  Debug((DEBUG_NOTICE, "write_authports(%p) fd %d authfd %d stat %d",
      cptr, cptr->fd, cptr->authfd, cptr->status));
  tlen = ulen = sizeof(us);
  if (getsockname(cptr->fd, (struct sockaddr *)&us, &ulen) ||
      getpeername(cptr->fd, (struct sockaddr *)&them, &tlen))
  {
#ifdef	USE_SYSLOG
    syslog(LOG_ERR, "auth get{sock,peer}name error for %s:%m",
	get_client_name(cptr, FALSE));
#endif
    goto authsenderr;
  }

  sprintf_irc(authbuf, "%u , %u\r\n", (unsigned int)ntohs(them.sin_port),
      (unsigned int)ntohs(us.sin_port));

  Debug((DEBUG_SEND, "sending [%s] to auth port %s.113",
      authbuf, inetntoa(them.sin_addr)));
  if (write(cptr->authfd, authbuf, strlen(authbuf)) != (int)strlen(authbuf))
  {
  authsenderr:
    ircstp->is_abad++;
    close(cptr->authfd);
    if (cptr->authfd == highest_fd)
      while (!loc_clients[highest_fd])
	highest_fd--;
    cptr->authfd = -1;
    cptr->flags &= ~FLAGS_AUTH;
    if (!DoingDNS(cptr))
      SetAccess(cptr);
  }
  cptr->flags &= ~FLAGS_WRAUTH;
  return;
}

/*
 * read_authports
 *
 * read the reply (if any) from the ident server we connected to.
 * The actual read processijng here is pretty weak - no handling of the reply
 * if it is fragmented by IP.
 */
void read_authports(aClient *cptr)
{
  Reg1 char *s, *t;
  Reg2 int len;
  char ruser[USERLEN + 1], system[8];
  unsigned short int remp = 0, locp = 0;

  *system = *ruser = '\0';
  Debug((DEBUG_NOTICE, "read_authports(%p) fd %d authfd %d stat %d",
      cptr, cptr->fd, cptr->authfd, cptr->status));
  /*
   * Nasty.  Cant allow any other reads from client fd while we're
   * waiting on the authfd to return a full valid string.  Use the
   * client's input buffer to buffer the authd reply.
   * Oh. this is needed because an authd reply may come back in more
   * than 1 read! -avalon
   */
  if ((len = read(cptr->authfd, cptr->buffer + cptr->count,
      sizeof(cptr->buffer) - 1 - cptr->count)) >= 0)
  {
    cptr->count += len;
    cptr->buffer[cptr->count] = '\0';
  }

  cptr->lasttime = now;
  if ((len > 0) && (cptr->count != (sizeof(cptr->buffer) - 1)) &&
      (sscanf(cptr->buffer, "%hd , %hd : USERID : %*[^:]: %10s",
      &remp, &locp, ruser) == 3))
  {
    s = strrchr(cptr->buffer, ':');
    *s++ = '\0';
    for (t = (strrchr(cptr->buffer, ':') + 1); *t; t++)
      if (!isSpace(*t))
	break;
    strncpy(system, t, sizeof(system) - 1);
    system[sizeof(system) - 1] = 0;
    for (t = ruser; *s && (t < ruser + sizeof(ruser)); s++)
      if (!isSpace(*s) && *s != ':' && *s != '@')
	*t++ = *s;
    *t = '\0';
    Debug((DEBUG_INFO, "auth reply ok [%s] [%s]", system, ruser));
  }
  else if (len != 0)
  {
    if (!strchr(cptr->buffer, '\n') && !strchr(cptr->buffer, '\r'))
      return;
    Debug((DEBUG_ERROR, "local %d remote %d", locp, remp));
    Debug((DEBUG_ERROR, "bad auth reply in [%s]", cptr->buffer));
    *ruser = '\0';
  }
  close(cptr->authfd);
  if (cptr->authfd == highest_fd)
    while (!loc_clients[highest_fd])
      highest_fd--;
  cptr->count = 0;
  cptr->authfd = -1;
  ClearAuth(cptr);
  if (!DoingDNS(cptr))
    SetAccess(cptr);
  if (len > 0)
    Debug((DEBUG_INFO, "ident reply: [%s]", cptr->buffer));

  if (!locp || !remp || !*ruser)
  {
    ircstp->is_abad++;
    return;
  }
  ircstp->is_asuc++;
  strncpy(cptr->username, ruser, USERLEN);
  cptr->username[USERLEN] = 0;	/* This is the LA bug --Run */
  if (strncmp(system, "OTHER", 5))
    cptr->flags |= FLAGS_GOTID;
  Debug((DEBUG_INFO, "got username [%s]", ruser));
  return;
}
