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
 *
 * $Id$
 */
#include "support.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "send.h"
#include "sprintf_irc.h"
#include "sys.h"

#include <signal.h>   /* kill */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
    server_die("too many core dumps");
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
  sprintf_irc(corename, "core.%d", p);
  rename("core", corename);
  Debug((DEBUG_FATAL, "Dumped core : core.%d", p));
  sendto_ops("Dumped core : core.%d", p);
  vdebug(DEBUG_FATAL, pattern, vl);
  vsendto_ops(pattern, vl);
  va_end(vl);

  server_die("debug core dump");

}
#endif

int check_if_ipmask(const char *mask)
{
  int has_digit = 0;
  const char *p;

  for (p = mask; *p; ++p)
    if (*p != '*' && *p != '?' && *p != '.')
    {
      if (!IsDigit(*p))
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
