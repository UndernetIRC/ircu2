/************************************************************************
 *   IRC - Internet Relay Chat, src/ircd_log.c
 *   Copyright (C) 1999 Thomas Helvey (BleepSoft)
 *                     
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers. 
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   $Id$
 */
#include "ircd_log.h"
#include "client.h"
#include "config.h"
#include "ircd_string.h"
#include "s_debug.h"
#include "struct.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#define LOG_BUFSIZE 2048 

static int logLevel = L_INFO;

#ifdef USE_SYSLOG
static int sysLogLevel[] = {
  LOG_CRIT,
  LOG_ERR,
  LOG_WARNING,
  LOG_NOTICE,
  LOG_INFO,
  LOG_INFO,
  LOG_INFO
};
#endif

void ircd_log(int priority, const char* fmt, ...)
{
#if defined(USE_SYSLOG) || defined(DEBUGMODE)
  char    buf[LOG_BUFSIZE];
  va_list args;
  assert(-1 < priority);
  assert(priority < L_LAST_LEVEL);
  assert(0 != fmt);

  if (priority > logLevel)
    return;

  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
#endif
#ifdef USE_SYSLOG
  syslog(sysLogLevel[priority], "%s", buf);
#endif
#ifdef DEBUGMODE
  Debug((DEBUG_INFO, "LOG: %s", buf));
#endif
}

void open_log(const char* process_name)
{
#ifdef USE_SYSLOG
  if (EmptyString(process_name))
    process_name = "ircd";
  openlog(process_name, LOG_PID | LOG_NDELAY, LOG_USER);
#endif
}

void close_log(void)
{
#ifdef USE_SYSLOG
  closelog();
#endif
}

void set_log_level(int level)
{
  if (L_ERROR < level && level < L_LAST_LEVEL)
    logLevel = level;
}

int get_log_level(void)
{
  return(logLevel);
}

/*
 * ircd_log_kill - log information about a kill
 */
void ircd_log_kill(const struct Client* victim, const struct Client* killer,
                   const char* inpath, const char* path)
{
  if (MyUser(victim)) {
    /*
     * get more infos when your local clients are killed -- _dl
     */
    if (IsServer(killer))
      ircd_log(L_TRACE,
               "A local client %s!%s@%s KILLED from %s [%s] Path: %s!%s)",
               victim->name, victim->user->username, victim->user->host,
               killer->name, killer->name, inpath, path);
    else
      ircd_log(L_TRACE,
               "A local client %s!%s@%s KILLED by %s [%s!%s@%s] (%s!%s)",
               victim->name, victim->user->username, victim->user->host,
               killer->name, killer->name, killer->user->username, killer->user->host,
               inpath, path);
  }
  else
    ircd_log(L_TRACE, "KILL From %s For %s Path %s!%s",
             killer->name, victim->name, inpath, path);
}


