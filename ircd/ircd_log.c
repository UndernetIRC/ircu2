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
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd.h"
#include "s_debug.h"
#include "struct.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define LOG_BUFSIZE 2048 

/* These constants are present even if we don't use syslog */
#ifndef LOG_CRIT
# define LOG_CRIT 0
#endif
#ifndef LOG_ERR
# define LOG_ERR 0
#endif
#ifndef LOG_WARNING
# define LOG_WARNING 0
#endif
#ifndef LOG_NOTICE
# define LOG_NOTICE 0
#endif
#ifndef LOG_INFO
# define LOG_INFO 0
#endif

/* Map severity levels to strings and syslog levels */
static struct LevelData {
  enum LogLevel level;
  char	       *string;
  int		syslog;
} levelData[] = {
#define L(level, syslog)   { L_ ## level, #level, (syslog) }
  L(CRIT, LOG_CRIT),
  L(ERROR, LOG_ERR),
  L(WARNING, LOG_WARNING),
  L(NOTICE, LOG_NOTICE),
  L(TRACE, LOG_INFO),
  L(INFO, LOG_INFO),
  L(DEBUG, LOG_INFO),
#undef L
  { L_LAST_LEVEL, 0 }
};

/* Descriptions of all logging subsystems */
static struct LogDesc {
  enum LogSys	  subsys;   /* number for subsystem */
  char		 *name;	    /* subsystem name */
  struct LogFile *file;	    /* file descriptor for subsystem */
  int		  facility; /* -1 means don't use syslog */
} logDesc[] = {
#define S(system, defprio) { LS_ ## system, #system, 0, (defprio) }
  S(GLINE, -1),
#undef S
  { LS_LAST_SYSTEM, 0, 0, -1 }
};

struct LogFile {
  struct LogFile *next;	/* next log file descriptor */
  int		  fd;	/* file's descriptor-- -1 if not open */
  char		 *file;	/* file name */
};

static struct LogFile *logFileList = 0; /* list of log files */

static const char *procname = "ircd"; /* process's name */

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


void
log_init(const char *process_name)
{
  /* store the process name; probably belongs in ircd.c, but oh well... */
  if (!EmptyString(process_name))
    procname = process_name;

#ifdef USE_SYSLOG
  /* ok, open syslog; default facility: LOG_USER */
  openlog(procname, LOG_PID | LOG_NDELAY, LOG_USER);
#endif
}

void
log_reopen(void)
{
  log_close(); /* close everything...we reopen on demand */

#ifdef USE_SYSLOG
  /* reopen syslog, if needed; default facility: LOG_USER */
  openlog(procname, LOG_PID | LOG_NDELAY, LOG_USER);
#endif
}

/* close the log files */
void
log_close(void)
{
  struct LogFile *ptr;

#ifdef USE_SYSLOG
  closelog(); /* close syslog */
#endif

  for (ptr = logFileList; ptr; ptr = ptr->next) {
    if (ptr->fd >= 0)
      close(ptr->fd);

    ptr->fd = -1;
  }
}

static void
log_open(struct LogFile *lf)
{
  /* only open the file if we haven't already */
  if (lf && lf->fd < 0) {
    alarm(3);
    lf->fd = open(lf->file, O_WRONLY | O_CREAT | O_APPEND,
		     S_IREAD | S_IWRITE);
    alarm(0);
  }
}

/* This writes an entry to a log file */
void
log_write(enum LogSys subsys, enum LogLevel severity, const char *fmt, ...)
{
  struct VarData vd;
  struct LogDesc *desc;
  struct LevelData *ldata;
  struct tm *tstamp;
  struct iovec vector[3];
  time_t curtime;
  char buf[LOG_BUFSIZE];
  /* 1234567890123456789012 3 */
  /* [2000-11-28 16:11:20] \0 */
  char timebuf[23];

  /* check basic assumptions */
  assert(-1 < subsys);
  assert(subsys < LS_LAST_SYSTEM);
  assert(-1 < severity);
  assert(severity < L_LAST_LEVEL);
  assert(0 != fmt);

  /* find the log data and the severity data */
  desc = &logDesc[subsys];
  ldata = &levelData[severity];

  /* check the set of ordering assumptions */
  assert(desc->subsys == subsys);
  assert(ldata->level == severity);

  /* if we don't have anything to log to, short-circuit */
  if (!desc->file
#ifdef USE_SYSLOG
      && desc->facility < 0
#endif
      )
    return;

  /* Build the basic log string */
  vd.vd_format = fmt;
  va_start(vd.vd_args, fmt);

  /* save the length for writev */
  /* Log format: "SYSTEM [SEVERITY] log message */
  vector[1].iov_len =
    ircd_snprintf(0, buf, sizeof(buf), "%s [%s] %v", desc->name,
		  ldata->string, &vd) - 1;

  va_end(vd.vd_args);

  /* open the log file if we haven't already */
  log_open(desc->file);
  /* if we have something to write to... */
  if (desc->file && desc->file->fd >= 0) {
    curtime = TStime();
    tstamp = localtime(&curtime); /* build the timestamp */

    vector[0].iov_len =
      ircd_snprintf(0, timebuf, sizeof(timebuf), "[%d-%d-%d %d:%02d:%02d] ",
		    tstamp->tm_year + 1900, tstamp->tm_mon + 1,
		    tstamp->tm_mday, tstamp->tm_hour, tstamp->tm_min,
		    tstamp->tm_sec) - 1;

    /* set up the remaining parts of the writev vector... */
    vector[0].iov_base = timebuf;
    vector[1].iov_base = buf;

    vector[2].iov_base = "\n"; /* terminate lines with a \n */
    vector[2].iov_len = 1;

    /* write it out to the log file */
    writev(desc->file->fd, vector, 3);
  }

#ifdef USE_SYSLOG
  /* oh yeah, syslog it too... */
  if (desc->facility >= 0)
    syslog(ldata->syslog | desc->facility, "%s", buf);
#endif
}
