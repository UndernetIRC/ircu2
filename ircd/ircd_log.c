/************************************************************************
 *   IRC - Internet Relay Chat, src/ircd_log.c
 *   Copyright (C) 1999 Thomas Helvey (BleepSoft)
 *   Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
#include "config.h"

#include "ircd_log.h"
#include "client.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd.h"
#include "numeric.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define LOG_BUFSIZE 2048 

/* select default log level cutoff */
#ifdef DEBUGMODE
# define L_DEFAULT	L_DEBUG
#else
# define L_DEFAULT	L_INFO
#endif

#define LOG_DOSYSLOG	0x10
#define LOG_DOFILELOG	0x20
#define LOG_DOSNOTICE	0x40

#define LOG_DOMASK	(LOG_DOSYSLOG | LOG_DOFILELOG | LOG_DOSNOTICE)

/* Map severity levels to strings and syslog levels */
static struct LevelData {
  enum LogLevel level;
  char	       *string;
  int		syslog;
  unsigned int	snomask; /* 0 means use default in LogDesc */
} levelData[] = {
#define L(level, syslog, mask) { L_ ## level, #level, (syslog), (mask) }
  L(CRIT, LOG_CRIT, SNO_OLDSNO),
  L(ERROR, LOG_ERR, 0),
  L(WARNING, LOG_WARNING, 0),
  L(NOTICE, LOG_NOTICE, 0),
  L(TRACE, LOG_INFO, 0),
  L(INFO, LOG_INFO, 0),
  L(DEBUG, LOG_INFO, SNO_DEBUG),
#undef L
  { L_LAST_LEVEL, 0, 0, 0 }
};

/* Just in case some implementation of syslog has them... */
#undef LOG_NONE
#undef LOG_DEFAULT
#undef LOG_NOTFOUND

#define LOG_NONE     -1 /* don't syslog */
#define LOG_DEFAULT   0 /* syslog to logInfo.facility */
#define LOG_NOTFOUND -2 /* didn't find a facility corresponding to name */

/* Map names to syslog facilities--allows syslog configuration from .conf */
static struct {
  char *name;
  int facility;
} facilities[] = {
#define F(fac) { #fac, LOG_ ## fac }
  F(NONE),    F(DEFAULT), F(AUTH),
#ifdef LOG_AUTHPRIV
  F(AUTHPRIV),
#endif
  F(CRON),    F(DAEMON),  F(LOCAL0),  F(LOCAL1),  F(LOCAL2),  F(LOCAL3),
  F(LOCAL4),  F(LOCAL5),  F(LOCAL6),  F(LOCAL7),  F(LPR),     F(MAIL),
  F(NEWS),    F(USER),    F(UUCP),
#undef F
  { 0, 0 }
};

#define SNO_NONE     0x00000000 /* don't send server notices */
#define SNO_NOTFOUND 0xffffffff /* didn't find a SNO_MASK value for name */

/* Map names to snomask values--allows configuration from .conf */
static struct {
  char *name;
  unsigned int snomask;
} masks[] = {
#define M(mask) { #mask, SNO_ ## mask }
  M(NONE),       M(OLDSNO),     M(SERVKILL),   M(OPERKILL),   M(HACK2),
  M(HACK3),      M(UNAUTH),     M(TCPCOMMON),  M(TOOMANY),    M(HACK4),
  M(GLINE),      M(NETWORK),    M(IPMISMATCH), M(THROTTLE),   M(OLDREALOP),
  M(CONNEXIT),   M(DEBUG),
#undef M
  { 0, 0 }
};

#define LOG_MARK_FILE		0x0001	/* file has been changed */
#define LOG_MARK_FACILITY	0x0002	/* facility has been changed */
#define LOG_MARK_SNOMASK	0x0004	/* snomask has been changed */
#define LOG_MARK_LEVEL		0x0008	/* level has been changed */

/* Descriptions of all logging subsystems */
static struct LogDesc {
  enum LogSys	  subsys;   /* number for subsystem */
  char		 *name;	    /* subsystem name */
  struct LogFile *file;	    /* file descriptor for subsystem */
  unsigned int	  mark;     /* subsystem has been changed */
  int		  def_fac;  /* default facility */
  unsigned int	  def_sno;  /* default snomask */
  int		  facility; /* -1 means don't use syslog */
  unsigned int	  snomask;  /* 0 means no server message */
  enum LogLevel	  level;    /* logging level */
} logDesc[] = {
#define S(sys, p, sn) { LS_##sys, #sys, 0, 0, (p), (sn), (p), (sn), L_DEFAULT }
  S(SYSTEM, -1, 0),
  S(CONFIG, 0, SNO_OLDSNO),
  S(OPERMODE, -1, SNO_HACK4),
  S(GLINE, -1, SNO_GLINE),
  S(JUPE, -1, SNO_NETWORK),
  S(WHO, -1, 0),
  S(NETWORK, -1, SNO_NETWORK),
  S(OPERKILL, -1, 0),
  S(SERVKILL, -1, 0),
  S(USER, -1, 0),
  S(OPER, -1, SNO_OLDREALOP),
  S(RESOLVER, -1, 0),
  S(SOCKET, -1, 0),
  S(DEBUG, -1, SNO_DEBUG),
  S(OLDLOG, -1, 0),
#undef S
  { LS_LAST_SYSTEM, 0, 0, -1, 0, -1, 0 }
};

/* describes a log file */
struct LogFile {
  struct LogFile  *next;   /* next log file descriptor */
  struct LogFile **prev_p; /* what points to us */
  int		   fd;	   /* file's descriptor-- -1 if not open */
  int		   ref;	   /* how many things refer to us? */
  char		  *file;   /* file name */
};

/* modifiable static information */
static struct {
  struct LogFile *filelist; /* list of log files */
  struct LogFile *freelist; /* list of free'd log files */
  int		  facility; /* default facility */
  const char	 *procname; /* process's name */
  struct LogFile *dbfile;   /* debug file */
} logInfo = { 0, 0, LOG_USER, "ircd", 0 };

/* helper routine to open a log file if needed */
static void
log_open(struct LogFile *lf)
{
  /* only open the file if we haven't already */
  if (lf && lf->fd < 0) {
    alarm(3); /* if NFS hangs, we hang only for 3 seconds */
    lf->fd = open(lf->file, O_WRONLY | O_CREAT | O_APPEND,
		  S_IREAD | S_IWRITE);
    alarm(0);
  }
}

#ifdef DEBUGMODE

/* reopen debug log */
static void
log_debug_reopen(void)
{
  if (!logInfo.dbfile) /* no open debugging file */
    return;

  if (!logInfo.dbfile->file) { /* using terminal output */
    logInfo.dbfile->fd = 2;
    return;
  }

  /* Ok, it's a real file; close it if necessary and use log_open to open it */
  if (logInfo.dbfile->fd >= 0) {
    close(logInfo.dbfile->fd);
    logInfo.dbfile->fd = -1; /* mark that it's closed for log_open */
  }

  log_open(logInfo.dbfile);

  if (logInfo.dbfile->fd < 0) { /* try again with /dev/null */
    if ((logInfo.dbfile->fd = open("/dev/null", O_WRONLY)) < 0)
      exit(-1);
  }

  /* massage the file descriptor to be stderr */
  if (logInfo.dbfile->fd != 2) {
    int fd;
    fd = dup2(logInfo.dbfile->fd, 2);
    close(logInfo.dbfile->fd);
    logInfo.dbfile->fd = fd;
  }
}

/* initialize debugging log */
void
log_debug_init(int usetty)
{
  logInfo.dbfile = MyMalloc(sizeof(struct LogFile));

  logInfo.dbfile->next = 0; /* initialize debugging filename */
  logInfo.dbfile->prev_p = 0;
  logInfo.dbfile->fd = -1;
  logInfo.dbfile->ref = 1;

  if (usetty) /* store pathname to use */
    logInfo.dbfile->file = 0;
  else
    DupString(logInfo.dbfile->file, LOGFILE);

  log_debug_reopen(); /* open the debug log */

  logDesc[LS_DEBUG].file = logInfo.dbfile; /* remember where it went */
}

#endif /* DEBUGMODE */

/* set the debug log file */
static int
log_debug_file(const char *file)
{
#ifdef DEBUGMODE
  if (!file)
    file = LOGFILE;

  /* If we weren't started with debugging enabled, or if we're using
   * the terminal, don't do anything at all.
   */
  if (!logInfo.dbfile || !logInfo.dbfile->file)
    return 1;

  MyFree(logInfo.dbfile->file); /* free old pathname */
  DupString(logInfo.dbfile->file, file); /* store new pathname */

  log_debug_reopen(); /* reopen the debug log */
#endif /* DEBUGMODE */
  return 0;
}

/* called in place of open_log(), this stores the process name and prepares
 * for syslogging
 */
void
log_init(const char *process_name)
{
  /* store the process name; probably belongs in ircd.c, but oh well... */
  if (!EmptyString(process_name))
    logInfo.procname = process_name;

  /* ok, open syslog; default facility: LOG_USER */
  openlog(logInfo.procname, LOG_PID | LOG_NDELAY, logInfo.facility);
}

/* Files are persistently open; this closes and reopens them to allow
 * log file rotation
 */
void
log_reopen(void)
{
  log_close(); /* close everything...we reopen on demand */

#ifdef DEBUGMODE
  log_debug_reopen(); /* reopen debugging log if necessary */
#endif /* DEBUGMODE */

  /* reopen syslog, if needed; default facility: LOG_USER */
  openlog(logInfo.procname, LOG_PID | LOG_NDELAY, logInfo.facility);
}

/* close the log files */
void
log_close(void)
{
  struct LogFile *ptr;

  closelog(); /* close syslog */

  for (ptr = logInfo.filelist; ptr; ptr = ptr->next) {
    if (ptr->fd >= 0)
      close(ptr->fd); /* close all the files... */

    ptr->fd = -1;
  }

  if (logInfo.dbfile && logInfo.dbfile->file) {
    if (logInfo.dbfile->fd >= 0)
      close(logInfo.dbfile->fd); /* close the debug log file */

    logInfo.dbfile->fd = -1;
  }
}

/* These write entries to a log file */
void
log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
	  const char *fmt, ...)
{
  va_list vl;

  va_start(vl, fmt);
  log_vwrite(subsys, severity, flags, fmt, vl);
  va_end(vl);
}

void
log_vwrite(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
	   const char *fmt, va_list vl)
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
  assert(-1 < (int)subsys);
  assert((int)subsys < LS_LAST_SYSTEM);
  assert(-1 < (int)severity);
  assert((int)severity < L_LAST_LEVEL);
  assert(0 == (flags & ~LOG_NOMASK));
  assert(0 != fmt);

  /* find the log data and the severity data */
  desc = &logDesc[subsys];
  ldata = &levelData[severity];

  /* check the set of ordering assumptions */
  assert(desc->subsys == subsys);
  assert(ldata->level == severity);

  /* check severity... */
  if (severity > desc->level)
    return;

  /* figure out where all we need to log */
  if (!(flags & LOG_NOFILELOG) && desc->file) {
    log_open(desc->file);
    if (desc->file->fd >= 0) /* don't log to file if we can't open the file */
      flags |= LOG_DOFILELOG;
  }

  if (!(flags & LOG_NOSYSLOG) && desc->facility >= 0)
    flags |= LOG_DOSYSLOG; /* will syslog */

  if (!(flags & LOG_NOSNOTICE) && (desc->snomask != 0 || ldata->snomask != 0))
    flags |= LOG_DOSNOTICE; /* will send a server notice */

  /* short-circuit if there's nothing to do... */
  if (!(flags & LOG_DOMASK))
    return;

  /* Build the basic log string */
  vd.vd_format = fmt;
  vd.vd_args = vl;

  /* save the length for writev */
  /* Log format: "SYSTEM [SEVERITY]: log message" */
  vector[1].iov_len =
    ircd_snprintf(0, buf, sizeof(buf), "%s [%s]: %v", desc->name,
		  ldata->string, &vd);

  /* if we have something to write to... */
  if (flags & LOG_DOFILELOG) {
    curtime = TStime();
    tstamp = localtime(&curtime); /* build the timestamp */

    vector[0].iov_len =
      ircd_snprintf(0, timebuf, sizeof(timebuf), "[%d-%d-%d %d:%02d:%02d] ",
		    tstamp->tm_year + 1900, tstamp->tm_mon + 1,
		    tstamp->tm_mday, tstamp->tm_hour, tstamp->tm_min,
		    tstamp->tm_sec);

    /* set up the remaining parts of the writev vector... */
    vector[0].iov_base = timebuf;
    vector[1].iov_base = buf;

    vector[2].iov_base = "\n"; /* terminate lines with a \n */
    vector[2].iov_len = 1;

    /* write it out to the log file */
    writev(desc->file->fd, vector, 3);
  }

  /* oh yeah, syslog it too... */
  if (flags & LOG_DOSYSLOG)
    syslog(ldata->syslog | desc->facility, "%s", buf);

  /* can't forget server notices... */
  if (flags & LOG_DOSNOTICE)
    sendto_opmask_butone(0, ldata->snomask ? ldata->snomask : desc->snomask,
			 "%s", buf);
}

/* log kills for fun and profit */
void
log_write_kill(const struct Client *victim, const struct Client *killer,
	       const char *inpath, const char *path, const char *msg)
{
  if (MyUser(victim))
    log_write(IsServer(killer) ? LS_SERVKILL : LS_OPERKILL, L_TRACE, 0,
	      "A local client %#C KILLED by %#C Path: %s!%s %s",
	      victim, killer, inpath, path, msg);
  else
    log_write(IsServer(killer) ? LS_SERVKILL : LS_OPERKILL, L_TRACE, 0,
	      "KILL from %C For %C Path: %s!%s %s", killer, victim, inpath,
	      path, msg);
}

/* return a struct LogFile for a specific filename--reference counted */
static struct LogFile *
log_file_create(const char *file)
{
  struct LogFile *tmp;

  assert(0 != file);

  /* if one already exists for that file, return it */
  for (tmp = logInfo.filelist; tmp; tmp = tmp->next)
    if (!strcmp(tmp->file, file)) {
      tmp->ref++;
      return tmp;
    }

  if (logInfo.freelist) { /* pop one off the free list */
    tmp = logInfo.freelist;
    logInfo.freelist = tmp->next;
  } else /* allocate a new one */
    tmp = MyMalloc(sizeof(struct LogFile));

  tmp->fd = -1; /* initialize the structure */
  tmp->ref = 1;
  DupString(tmp->file, file);

  tmp->next = logInfo.filelist; /* link it into the list... */
  tmp->prev_p = &logInfo.filelist;
  if (logInfo.filelist)
    logInfo.filelist->prev_p = &tmp->next;
  logInfo.filelist = tmp;

  return tmp;
}

/* destroy a log file descriptor, under the control of the reference count */
static void
log_file_destroy(struct LogFile *lf)
{
  assert(0 != lf);

  if (--lf->ref == 0) {
    if (lf->next) /* clip it out of the list */
      lf->next->prev_p = lf->prev_p;
    *lf->prev_p = lf->next;

    lf->prev_p = 0; /* we won't use it for the free list */
    if (lf->fd >= 0)
      close(lf->fd);
    lf->fd = -1;
    MyFree(lf->file); /* free the file name */

    lf->next = logInfo.freelist; /* stack it onto the free list */
    logInfo.freelist = lf;
  }
}

/* finds a subsystem given its name */
static struct LogDesc *
log_find(const char *subsys)
{
  int i;

  assert(0 != subsys);

  /* find the named subsystem */
  for (i = 0; i < LS_LAST_SYSTEM; i++)
    if (!ircd_strcmp(subsys, logDesc[i].name))
      return &logDesc[i];

  return 0; /* not found */
}

/* canonicalize subsystem names */
char *
log_canon(const char *subsys)
{
  struct LogDesc *desc;

  if (!(desc = log_find(subsys)))
    return 0;

  return desc->name;
}

/* find a level given its name */
static enum LogLevel
log_lev_find(const char *level)
{
  int i;

  assert(0 != level);

  /* find the named level */
  for (i = 0; levelData[i].string; i++)
    if (!ircd_strcmp(level, levelData[i].string))
      return levelData[i].level;

  return L_LAST_LEVEL; /* not found */
}

/* return a name for a level */
static char *
log_lev_name(enum LogLevel lev)
{
  assert(-1 < (int)lev);
  assert((int)lev < L_LAST_LEVEL);
  assert(lev == levelData[lev].level);

  return levelData[lev].string;
}

/* find a facility given its name */
static int
log_fac_find(const char *facility)
{
  int i;

  assert(0 != facility);

  /* find the named facility */
  for (i = 0; facilities[i].name; i++)
    if (!ircd_strcmp(facility, facilities[i].name))
      return facilities[i].facility;

  return LOG_NOTFOUND; /* not found */
}

/* return a name for a facility */
static char *
log_fac_name(int fac)
{
  int i;

  /* find the facility */
  for (i = 0; facilities[i].name; i++)
    if (facilities[i].facility == fac)
      return facilities[i].name;

  return 0; /* not found; should never happen */
}

/* find a snomask value given its name */
static unsigned int
log_sno_find(const char *maskname)
{
  int i;

  assert(0 != maskname);

  /* find the named snomask */
  for (i = 0; masks[i].name; i++)
    if (!ircd_strcmp(maskname, masks[i].name))
      return masks[i].snomask;

  return SNO_NOTFOUND; /* not found */
}

/* return a name for a snomask value */
static char *
log_sno_name(unsigned int sno)
{
  int i;

  /* find the snomask */
  for (i = 0; masks[i].name; i++)
    if (masks[i].snomask == sno)
      return masks[i].name;

  return 0; /* not found; should never happen */
}

/* set the log file for a subsystem */
int
log_set_file(const char *subsys, const char *filename)
{
  struct LogDesc *desc;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 2;

  if (filename)
    desc->mark |= LOG_MARK_FILE; /* mark that file has been changed */
  else
    desc->mark &= ~LOG_MARK_FILE; /* file has been reset to defaults */

  /* no change, don't go to the trouble of destroying and recreating */
  if (desc->file && desc->file->file && filename &&
      !strcmp(desc->file->file, filename))
    return 0;

  /* debug log is special, since it has to be opened on fd 2 */
  if (desc->subsys == LS_DEBUG)
    return log_debug_file(filename);

  if (desc->file) /* destroy previous entry... */
    log_file_destroy(desc->file);

  /* set the file to use */
  desc->file = filename ? log_file_create(filename) : 0;

  return 0;
}

/* get the log file for a subsystem */
char *
log_get_file(const char *subsys)
{
  struct LogDesc *desc;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 0;

  return desc->file ? desc->file->file : 0;
}

/* set the facility for a subsystem */
int
log_set_facility(const char *subsys, const char *facility)
{
  struct LogDesc *desc;
  int fac;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 2;

  /* set syslog facility */
  if (EmptyString(facility)) {
    desc->facility = desc->def_fac;
    desc->mark &= ~LOG_MARK_FACILITY;
  } else if ((fac = log_fac_find(facility)) != LOG_NOTFOUND) {
    desc->facility = fac;
    if (fac == desc->def_fac)
      desc->mark &= ~LOG_MARK_FACILITY;
    else
      desc->mark |= LOG_MARK_FACILITY;
  } else
    return 1;

  return 0;
}

/* get the facility for a subsystem */
char *
log_get_facility(const char *subsys)
{
  struct LogDesc *desc;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 0;

  /* find the facility's name */
  return log_fac_name(desc->facility);
}

/* set the snomask value for a subsystem */
int
log_set_snomask(const char *subsys, const char *snomask)
{
  struct LogDesc *desc;
  unsigned int sno = SNO_DEFAULT;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 2;

  /* set snomask value */
  if (EmptyString(snomask)) {
    desc->snomask = desc->def_sno;
    desc->mark &= ~LOG_MARK_SNOMASK;
  } else if ((sno = log_sno_find(snomask)) != SNO_NOTFOUND) {
    desc->snomask = sno;
    if (sno == desc->def_sno)
      desc->mark &= ~LOG_MARK_SNOMASK;
    else
      desc->mark |= LOG_MARK_SNOMASK;
  } else
    return 1;

  return 0;
}

/* get the snomask value for a subsystem */
char *
log_get_snomask(const char *subsys)
{
  struct LogDesc *desc;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 0;

  /* find the snomask value's name */
  return log_sno_name(desc->snomask);
}

/* set the level for a subsystem */
int
log_set_level(const char *subsys, const char *level)
{
  struct LogDesc *desc;
  enum LogLevel lev;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 2;

  /* set logging level */
  if (EmptyString(level)) {
    desc->level = L_DEFAULT;
    desc->mark &= ~LOG_MARK_LEVEL;
  } else if ((lev = log_lev_find(level)) != L_LAST_LEVEL) {
    desc->level = lev;
    if (lev == L_DEFAULT)
      desc->mark &= ~LOG_MARK_LEVEL;
    else
      desc->mark |= LOG_MARK_LEVEL;
  } else
    return 1;

  return 0;
}

/* get the level for a subsystem */
char *
log_get_level(const char *subsys)
{
  struct LogDesc *desc;

  /* find subsystem */
  if (!(desc = log_find(subsys)))
    return 0;

  /* find the level's name */
  return log_lev_name(desc->level);
}

/* set the overall default syslog facility */
int
log_set_default(const char *facility)
{
  int fac, oldfac;

  oldfac = logInfo.facility;

  if (EmptyString(facility))
    logInfo.facility = LOG_USER;
  else if ((fac = log_fac_find(facility)) != LOG_NOTFOUND &&
	   fac != LOG_NONE && fac != LOG_DEFAULT)
    logInfo.facility = fac;
  else
    return 1;

  if (logInfo.facility != oldfac) {
    closelog(); /* reopen syslog with new facility setting */
    openlog(logInfo.procname, LOG_PID | LOG_NDELAY, logInfo.facility);
  }

  return 0;
}

/* get the overall default syslog facility */
char *
log_get_default(void)
{
  /* find the facility's name */
  return log_fac_name(logInfo.facility);
}

/* Clear the marks... */
void
log_feature_unmark(void)
{
  int i;

  for (i = 0; i < LS_LAST_SYSTEM; i++)
    logDesc[i].mark = 0;
}

/* Reset unmarked fields to defaults... */
int
log_feature_mark(int flag)
{
  int i;

  if (flag)
    log_set_default(0);

  for (i = 0; i < LS_LAST_SYSTEM; i++) {
    if (!(logDesc[i].mark & LOG_MARK_FILE)) {
      if (logDesc[i].subsys != LS_DEBUG) { /* debug is special */
	if (logDesc[i].file) /* destroy previous entry... */
	  log_file_destroy(logDesc[i].file);
	logDesc[i].file = 0;
      }
    }

    if (!(logDesc[i].mark & LOG_MARK_FACILITY)) /* set default facility */
      logDesc[i].facility = logDesc[i].def_fac;

    if (!(logDesc[i].mark & LOG_MARK_SNOMASK)) /* set default snomask */
      logDesc[i].snomask = logDesc[i].def_sno;

    if (!(logDesc[i].mark & LOG_MARK_LEVEL)) /* set default level */
      logDesc[i].level = L_DEFAULT;
  }

  return 0; /* we don't have a notify handler */
}

/* Report feature settings */
void
log_feature_report(struct Client *to, int flag)
{
  int i;

  for (i = 0; i < LS_LAST_SYSTEM; i++) {
    if (logDesc[i].mark & LOG_MARK_FILE) /* report file */
      send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F LOG %s FILE %s",
		 logDesc[i].name, (logDesc[i].file && logDesc[i].file->file ?
				   logDesc[i].file->file : "(terminal)"));

    if (logDesc[i].mark & LOG_MARK_FACILITY) /* report facility */
      send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F LOG %s FACILITY %s",
		 logDesc[i].name, log_fac_name(logDesc[i].facility));

    if (logDesc[i].mark & LOG_MARK_SNOMASK) /* report snomask */
      send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F LOG %s SNOMASK %s",
		 logDesc[i].name, log_sno_name(logDesc[i].snomask));

    if (logDesc[i].mark & LOG_MARK_LEVEL) /* report log level */
      send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F LOG %s LEVEL %s",
		 logDesc[i].name, log_lev_name(logDesc[i].level));
  }

  if (flag) /* report default facility */
    send_reply(to, SND_EXPLICIT | RPL_STATSFLINE, "F LOG %s",
	       log_fac_name(logInfo.facility));
}
