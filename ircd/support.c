/*
 * IRC - Internet Relay Chat, common/support.c
 * Copyright (C) 1990, 1991 Armin Gruner
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
#ifdef _SEQUENT_
#include <sys/timers.h>
#include <stddef.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdarg.h>
#include <signal.h>
#include "h.h"
#include "send.h"
#include "ircd.h"
#include "s_bsd.h"
#include "support.h"
#include "sprintf_irc.h"
#include "common.h"
#include "fileio.h"

RCSTAG_CC("$Id$");

#ifndef HAVE_STRTOKEN
/*
 * strtoken.c
 *
 * Walk through a string of tokens, using a set of separators.
 * -argv 9/90
 */
char *strtoken(char **save, char *str, char *fs)
{
  char *pos = *save;		/* keep last position across calls */
  Reg1 char *tmp;

  if (str)
    pos = str;			/* new string scan */

  while (pos && *pos && strchr(fs, *pos) != NULL)
    pos++;			/* skip leading separators */

  if (!pos || !*pos)
    return (pos = *save = NULL);	/* string contains only sep's */

  tmp = pos;			/* now, keep position of the token */

  while (*pos && strchr(fs, *pos) == NULL)
    pos++;			/* skip content of the token */

  if (*pos)
    *pos++ = '\0';		/* remove first sep after the token */
  else
    pos = NULL;			/* end of string */

  *save = pos;
  return (tmp);
}
#endif /* !HAVE_STRTOKEN */

#ifndef HAVE_STRERROR
/*
 * strerror
 *
 * Returns an appropriate system error string to a given errno.
 * -argv 11/90
 */

char *strerror(int err_no)
{
  static char buff[40];
  char *errp;

  errp = (err_no > sys_nerr ? (char *)NULL : sys_errlist[err_no]);

  if (errp == (char *)NULL)
  {
    errp = buff;
    sprintf_irc(errp, "Unknown Error %d", err_no);
  }
  return errp;
}

#endif /* !HAVE_STRERROR */

/*
 * inetntoa --    Changed the parameter to NOT take a pointer.
 *                -Run 4/8/97
 * inetntoa --    Changed name to remove collision possibility and
 *                so behaviour is garanteed to take a pointer arg.
 *                -avalon 23/11/92
 * inet_ntoa --   Returned the dotted notation of a given
 *                internet number (some ULTRIX don't have this)
 *                -argv 11/90.
 * inet_ntoa --   Its broken on some Ultrix/Dynix too. -avalon
 */
char *inetntoa(struct in_addr in)
{
  static char buf[16];
  Reg1 unsigned char *s = (unsigned char *)&in.s_addr;
  Reg2 unsigned char a, b, c, d;

  a = *s++;
  b = *s++;
  c = *s++;
  d = *s++;
  sprintf_irc(buf, "%u.%u.%u.%u", a, b, c, d);

  return buf;
}

#ifndef HAVE_INET_NETOF
/*
 *    inet_netof --   return the net portion of an internet number
 *                    argv 11/90
 */
int inet_netof(struct in_addr in)
{
  int addr = in.s_net;

  if (addr & 0x80 == 0)
    return ((int)in.s_net);

  if (addr & 0x40 == 0)
    return ((int)in.s_net * 256 + in.s_host);

  return ((int)in.s_net * 256 + in.s_host * 256 + in.s_lh);
}

#endif /* !HAVE_INET_NETOF */

#ifndef HAVE_GETTIMEOFDAY
/* This is copied from ircu3.0.0 (with permission), not vica versa. */
int gettimeofday(struct timeval *tv, void * /*UNUSED*/)
{
  register int ret;
  static struct timespec tp;

  if ((ret = getclock(TIMEOFDAY, &tp)))
    return ret;
  tv->tv_sec = (long)tp.tv_sec;
  tv->tv_usec = (tp.tv_nsec + 500) / 1000;
  return 0;
}
#endif /* !HAVE_GETTIMEOFDAY */

#ifdef DEBUGMODE

void dumpcore(const char *pattern, ...)
{
  va_list vl;
  static time_t lastd = 0;
  static int dumps = 0;
  char corename[12];
  time_t now;
  int p;

  va_start(vl, pattern);

  now = time(NULL);

  if (!lastd)
    lastd = now;
  else if (now - lastd < 60 && dumps > 2)
#ifdef __cplusplus
    s_die(0);
#else
    s_die();
#endif
  if (now - lastd > 60)
  {
    lastd = now;
    dumps = 1;
  }
  else
    dumps++;
  p = getpid();
  if (fork() > 0)
  {
    kill(p, 3);
    kill(p, 9);
  }
  write_pidfile();
  sprintf_irc(corename, "core.%d", p);
  rename("core", corename);
  Debug((DEBUG_FATAL, "Dumped core : core.%d", p));
  sendto_ops("Dumped core : core.%d", p);
  vdebug(DEBUG_FATAL, pattern, vl);
  vsendto_ops(pattern, vl);
#ifdef __cplusplus
  s_die(0);
#else
  s_die();
#endif

  va_end(vl);
}
#endif

int check_if_ipmask(const char *mask)
{
  int has_digit = 0;
  register const char *p;

  for (p = mask; *p; ++p)
    if (*p != '*' && *p != '?' && *p != '.')
    {
      if (!isDigit(*p))
	return 0;
      has_digit = -1;
    }

  return has_digit;
}

/* Moved from logf() in whocmds.c to here. Modified a 
 * bit and used for most logging now.
 *  -Ghostwolf 12-Jul-99
 */

extern void write_log(const char *filename, const char *pattern, ...)
{
  FBFILE *logfile;
  va_list vl;
  static char logbuf[1024];

  logfile = fbopen(filename, "a");

  if (logfile)
  {
    va_start(vl, pattern);
    vsprintf_irc(logbuf, pattern, vl);
    va_end(vl);

    fbputs(logbuf, logfile);
    fbclose(logfile);
  }
}
