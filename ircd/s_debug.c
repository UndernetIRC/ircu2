/*
 * IRC - Internet Relay Chat, ircd/s_debug.c
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
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if defined(HPUX) && HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HPUX
#include <sys/syscall.h>
#define getrusage(a,b) syscall(SYS_GETRUSAGE, a, b)
#endif
#if HAVE_GETRUSAGE
#include <sys/resource.h>
#else
#if HAVE_TIMES
#include <sys/times.h>
#endif
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdarg.h>
#include "h.h"
#include "struct.h"
#include "numeric.h"
#include "hash.h"
#include "send.h"
#include "s_conf.h"
#include "class.h"
#include "ircd.h"
#include "s_bsd.h"
#include "bsd.h"
#include "whowas.h"
#include "s_serv.h"
#include "res.h"
#include "channel.h"
#include "numnicks.h"

RCSTAG_CC("$Id$");

/* *INDENT-OFF* */

/*
 * Option string.  Must be before #ifdef DEBUGMODE.
 */
char serveropts[] = {
#if BUFFERPOOL < 1000000
    'b',
#if BUFFERPOOL > 99999
    (char)('0' + (BUFFERPOOL/100000)),
#endif
#if BUFFERPOOL > 9999
    (char)('0' + (BUFFERPOOL/10000) % 10),
#endif
    (char)('0' + (BUFFERPOOL/1000) % 10),
#else
    'B',
#if BUFFERPOOL > 99999999
    (char)('0' + (BUFFERPOOL/100000000)),
#endif
#if BUFFERPOOL > 9999999
    (char)('0' + (BUFFERPOOL/10000000) % 10),
#endif
    (char)('0' + (BUFFERPOOL/1000000) % 10),
#endif
#ifdef	CHROOTDIR
    'c',
#endif
#ifdef	CMDLINE_CONFIG
    'C',
#endif
#ifdef	DO_ID
    'd',
#endif
#ifdef	DEBUGMODE
    'D',
#endif
#ifdef	LOCOP_REHASH
    'e',
#endif
#ifdef	OPER_REHASH
    'E',
#endif
#ifdef	HUB
    'H',
#endif
#if defined(SHOW_INVISIBLE_USERS) ||  defined(SHOW_ALL_INVISIBLE_USERS)
#ifdef	SHOW_ALL_INVISIBLE_USERS
    'I',
#else
    'i',
#endif
#endif
#ifdef	OPER_KILL
#ifdef	LOCAL_KILL_ONLY
    'k',
#else
    'K',
#endif
#endif
#ifdef	LEAST_IDLE
    'L',
#endif
#ifdef	IDLE_FROM_MSG
    'M',
#endif
#ifdef	USEONE
    'O',
#endif
#ifdef	CRYPT_OPER_PASSWORD
    'p',
#endif
#ifdef	CRYPT_LINK_PASSWORD
    'P',
#endif
#ifdef	DEBUGMALLOC
#ifdef	MEMLEAKSTATS
    'Q',
#else
    'q',
#endif
#endif
#ifdef	RELIABLE_CLOCK
    'R',
#endif
#ifdef	LOCOP_RESTART
    's',
#endif
#ifdef	OPER_RESTART
    'S',
#endif
#ifdef	OPER_REMOTE
    't',
#endif
#if defined(USE_POLL) && defined(HAVE_POLL_H)
    'U',
#endif
#ifdef	VIRTUAL_HOST
    'v',
#endif
#ifdef	UNIXPORT
    'X',
#endif
#ifdef	USE_SYSLOG
    'Y',
#endif
    '\0'
};

/* *INDENT-ON* */

#ifdef DEBUGMODE
static char debugbuf[1024];

void vdebug(int level, const char *form, va_list vl)
{
  int err = errno;

  if ((debuglevel >= 0) && (level <= debuglevel))
  {
    vsprintf(debugbuf, form, vl);
    if (loc_clients[2])
    {
      loc_clients[2]->sendM++;
      loc_clients[2]->sendB += strlen(debugbuf);
    }
    fprintf(stderr, "%s", debugbuf);
    fputc('\n', stderr);
  }
  errno = err;
}

void debug(int level, const char *form, ...)
{
  va_list vl;
  va_start(vl, form);
  vdebug(level, form, vl);
  va_end(vl);
}

/*
 * This is part of the STATS replies. There is no offical numeric for this
 * since this isnt an official command, in much the same way as HASH isnt.
 * It is also possible that some systems wont support this call or have
 * different field names for "struct rusage".
 * -avalon
 */
void send_usage(aClient *cptr, char *nick)
{

#if HAVE_GETRUSAGE
  struct rusage rus;
  time_t secs, rup;
#ifdef	hz
#define hzz hz
#else
#ifdef HZ
#define hzz HZ
#else
  int hzz = 1;
#ifdef HPUX
  hzz = (int)sysconf(_SC_CLK_TCK);
#endif
#endif
#endif

  if (getrusage(RUSAGE_SELF, &rus) == -1)
  {
    if (MyUser(cptr) || Protocol(cptr->from) < 10)
      sendto_one(cptr, ":%s NOTICE %s :Getruseage error: %s.",
	  me.name, nick, sys_errlist[errno]);
    else
      sendto_one(cptr, "%s NOTICE %s%s :Getruseage error: %s.",
	  NumServ(&me), NumNick(cptr), sys_errlist[errno]);
    return;
  }
  secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
  rup = now - me.since;
  if (secs == 0)
    secs = 1;

#if defined(__sun__) || defined(__bsdi__) || (__GLIBC__ >= 2) || defined(__NetBSD__)
  sendto_one(cptr, ":%s %d %s :CPU Secs %ld:%ld User %ld:%ld System %ld:%ld",
#else
  sendto_one(cptr, ":%s %d %s :CPU Secs %ld:%ld User %d:%d System %d:%d",
#endif
      me.name, RPL_STATSDEBUG, nick, secs / 60, secs % 60,
      rus.ru_utime.tv_sec / 60, rus.ru_utime.tv_sec % 60,
      rus.ru_stime.tv_sec / 60, rus.ru_stime.tv_sec % 60);
  sendto_one(cptr, ":%s %d %s :RSS %ld ShMem %ld Data %ld Stack %ld",
      me.name, RPL_STATSDEBUG, nick, rus.ru_maxrss,
      rus.ru_ixrss / (rup * hzz), rus.ru_idrss / (rup * hzz),
      rus.ru_isrss / (rup * hzz));
  sendto_one(cptr, ":%s %d %s :Swaps %ld Reclaims %ld Faults %ld",
      me.name, RPL_STATSDEBUG, nick, rus.ru_nswap,
      rus.ru_minflt, rus.ru_majflt);
  sendto_one(cptr, ":%s %d %s :Block in %ld out %ld",
      me.name, RPL_STATSDEBUG, nick, rus.ru_inblock, rus.ru_oublock);
  sendto_one(cptr, ":%s %d %s :Msg Rcv %ld Send %ld",
      me.name, RPL_STATSDEBUG, nick, rus.ru_msgrcv, rus.ru_msgsnd);
  sendto_one(cptr, ":%s %d %s :Signals %ld Context Vol. %ld Invol %ld",
      me.name, RPL_STATSDEBUG, nick, rus.ru_nsignals,
      rus.ru_nvcsw, rus.ru_nivcsw);
#else /* HAVE_GETRUSAGE */
#if HAVE_TIMES
  struct tms tmsbuf;
  time_t secs, mins;
  int hzz = 1, ticpermin;
  int umin, smin, usec, ssec;

#ifdef HPUX
  hzz = sysconf(_SC_CLK_TCK);
#endif
  ticpermin = hzz * 60;

  umin = tmsbuf.tms_utime / ticpermin;
  usec = (tmsbuf.tms_utime % ticpermin) / (float)hzz;
  smin = tmsbuf.tms_stime / ticpermin;
  ssec = (tmsbuf.tms_stime % ticpermin) / (float)hzz;
  secs = usec + ssec;
  mins = (secs / 60) + umin + smin;
  secs %= hzz;

  if (times(&tmsbuf) == -1)
  {
    sendto_one(cptr, ":%s %d %s :times(2) error: %s.",
	me.name, RPL_STATSDEBUG, nick, strerror(errno));
    return;
  }
  secs = tmsbuf.tms_utime + tmsbuf.tms_stime;

  sendto_one(cptr, ":%s %d %s :CPU Secs %d:%d User %d:%d System %d:%d",
      me.name, RPL_STATSDEBUG, nick, mins, secs, umin, usec, smin, ssec);
#endif /* HAVE_TIMES */
#endif /* HAVE_GETRUSAGE */
  sendto_one(cptr, ":%s %d %s :Reads %d Writes %d",
      me.name, RPL_STATSDEBUG, nick, readcalls, writecalls);
  sendto_one(cptr, ":%s %d %s :DBUF alloc %d used %d",
      me.name, RPL_STATSDEBUG, nick, DBufAllocCount, DBufUsedCount);
  sendto_one(cptr,
      ":%s %d %s :Writes:  <0 %d 0 %d <16 %d <32 %d <64 %d",
      me.name, RPL_STATSDEBUG, nick,
      writeb[0], writeb[1], writeb[2], writeb[3], writeb[4]);
  sendto_one(cptr,
      ":%s %d %s :<128 %d <256 %d <512 %d <1024 %d >1024 %d",
      me.name, RPL_STATSDEBUG, nick,
      writeb[5], writeb[6], writeb[7], writeb[8], writeb[9]);
  return;
}
#endif /* DEBUGMODE */

void count_memory(aClient *cptr, char *nick)
{
  Reg1 aClient *acptr;
  Reg2 Link *link;
  Reg3 aChannel *chptr;
  Reg4 aConfItem *aconf;
  Reg5 aConfClass *cltmp;

  int lc = 0,			/* local clients */
      ch = 0,			/* channels */
      lcc = 0,			/* local client conf links */
      rc = 0,			/* remote clients */
      us = 0,			/* user structs */
      chu = 0,			/* channel users */
      chi = 0,			/* channel invites */
      chb = 0,			/* channel bans */
      wwu = 0,			/* whowas users */
      cl = 0,			/* classes */
      co = 0;			/* conf lines */

  int usi = 0,			/* users invited */
      usc = 0,			/* users in channels */
      aw = 0,			/* aways set */
      wwa = 0;			/* whowas aways */

  size_t chm = 0,		/* memory used by channels */
      chbm = 0,			/* memory used by channel bans */
      lcm = 0,			/* memory used by local clients */
      rcm = 0,			/* memory used by remote clients */
      awm = 0,			/* memory used by aways */
      wwam = 0,			/* whowas away memory used */
      wwm = 0,			/* whowas array memory used */
      com = 0,			/* memory used by conf lines */
      dbufs_allocated = 0,	/* memory used by dbufs */
      dbufs_used = 0,		/* memory used by dbufs */
      rm = 0,			/* res memory used */
      totcl = 0, totch = 0, totww = 0, tot = 0;

  count_whowas_memory(&wwu, &wwm, &wwa, &wwam);
  wwm += sizeof(aWhowas) * NICKNAMEHISTORYLENGTH;
  wwm += sizeof(aWhowas *) * WW_MAX;

  for (acptr = client; acptr; acptr = acptr->next)
  {
    if (IsPing(acptr))
      continue;
    if (MyConnect(acptr))
    {
      lc++;
      for (link = acptr->confs; link; link = link->next)
	lcc++;
    }
    else
      rc++;
    if (acptr->user)
    {
      us++;
      for (link = acptr->user->invited; link; link = link->next)
	usi++;
      for (link = acptr->user->channel; link; link = link->next)
	usc++;
      if (acptr->user->away)
      {
	aw++;
	awm += (strlen(acptr->user->away) + 1);
      }
    }
  }
  lcm = lc * CLIENT_LOCAL_SIZE;
  rcm = rc * CLIENT_REMOTE_SIZE;

  for (chptr = channel; chptr; chptr = chptr->nextch)
  {
    ch++;
    chm += (strlen(chptr->chname) + sizeof(aChannel));
    for (link = chptr->members; link; link = link->next)
      chu++;
    for (link = chptr->invites; link; link = link->next)
      chi++;
    for (link = chptr->banlist; link; link = link->next)
    {
      chb++;
      chbm += (strlen(link->value.cp) + 1 + sizeof(Link));
    }
  }

  for (aconf = conf; aconf; aconf = aconf->next)
  {
    co++;
    com += aconf->host ? strlen(aconf->host) + 1 : 0;
    com += aconf->passwd ? strlen(aconf->passwd) + 1 : 0;
    com += aconf->name ? strlen(aconf->name) + 1 : 0;
    com += sizeof(aConfItem);
  }

  for (cltmp = classes; cltmp; cltmp = cltmp->next)
    cl++;

  sendto_one(cptr, ":%s %d %s :Client Local %d(" SIZE_T_FMT
      ") Remote %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, lc, lcm, rc, rcm);
  sendto_one(cptr, ":%s %d %s :Users %d(" SIZE_T_FMT
      ") Invites %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, us, us * sizeof(anUser), usi,
      usi * sizeof(Link));
  sendto_one(cptr, ":%s %d %s :User channels %d(" SIZE_T_FMT
      ") Aways %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, usc, usc * sizeof(Link), aw, awm);
  sendto_one(cptr, ":%s %d %s :Attached confs %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, lcc, lcc * sizeof(Link));

  totcl = lcm + rcm + us * sizeof(anUser) + usc * sizeof(Link) + awm;
  totcl += lcc * sizeof(Link) + usi * sizeof(Link);

  sendto_one(cptr, ":%s %d %s :Conflines %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, co, com);

  sendto_one(cptr, ":%s %d %s :Classes %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, cl, cl * sizeof(aConfClass));

  sendto_one(cptr, ":%s %d %s :Channels %d(" SIZE_T_FMT
      ") Bans %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, ch, chm, chb, chbm);
  sendto_one(cptr, ":%s %d %s :Channel membrs %d(" SIZE_T_FMT
      ") invite %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, chu, chu * sizeof(Link),
      chi, chi * sizeof(Link));

  totch = chm + chbm + chu * sizeof(Link) + chi * sizeof(Link);

  sendto_one(cptr, ":%s %d %s :Whowas users %d(" SIZE_T_FMT
      ") away %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, wwu, wwu * sizeof(anUser), wwa, wwam);
  sendto_one(cptr, ":%s %d %s :Whowas array %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, NICKNAMEHISTORYLENGTH, wwm);

  totww = wwu * sizeof(anUser) + wwam + wwm;

  sendto_one(cptr, ":%s %d %s :Hash: client %d(" SIZE_T_FMT
      "), chan is the same",
      me.name, RPL_STATSDEBUG, nick, HASHSIZE, sizeof(void *) * HASHSIZE);

  /*
   * NOTE: this count will be accurate only for the exact instant that this
   * message is being sent, so the count is affected by the dbufs that
   * are being used to send this message out. If this is not desired, move
   * the dbuf_count_memory call to a place before we start sending messages
   * and cache DBufAllocCount and DBufUsedCount in variables until they 
   * are sent.
   */
  dbuf_count_memory(&dbufs_allocated, &dbufs_used);
  sendto_one(cptr,
      ":%s %d %s :DBufs allocated %d(" SIZE_T_FMT ") used %d(" SIZE_T_FMT ")",
      me.name, RPL_STATSDEBUG, nick, DBufAllocCount, dbufs_allocated,
      DBufUsedCount, dbufs_used);

  rm = cres_mem(cptr);

  tot =
      totww + totch + totcl + com + cl * sizeof(aConfClass) + dbufs_allocated +
      rm;
  tot += sizeof(void *) * HASHSIZE * 3;

  sendto_one(cptr, ":%s %d %s :Total: ww " SIZE_T_FMT " ch " SIZE_T_FMT
      " cl " SIZE_T_FMT " co " SIZE_T_FMT " db " SIZE_T_FMT,
      me.name, RPL_STATSDEBUG, nick, totww, totch, totcl, com, dbufs_allocated);
  return;
}

#ifdef MSGLOG_ENABLED

/* Define here what level of messages you want to log */
#define LOG_MASK_LEVEL LEVEL_MODE	/* This that change some data */

static struct log_entry log_table[MSGLOG_SIZE];

static int unused_log_entries = MSGLOG_SIZE;
static int last_log_entry = -1;	/* Nothing stored yet */
static int entry_stored_forlog = 0;	/* Just a flag */

/*
 * RollBackMsgLog
 *
 * Just a little utility function used to retract
 * an half stored Message log entry
 */
void RollBackMsgLog(void)
{
  /* We won't log this, abort and free the entry */
  last_log_entry--;
  unused_log_entries++;
  return;
}

/*
 * Log_Message (macroed as LogMessage)
 *
 * Permanently stores a log entry into the recent log memory area
 * Store_Buffer MUST have been called before calling Log_Message
 */
void Log_Message(aClient *sptr, int msgclass)
{
  register int n = last_log_entry;

  /* Clear our flag, since we are going to
   * finish the processing of this entry */
  entry_stored_forlog = 0;

  /* Check  if the level of this message is high enough */
  if (msgclass < LOG_MASK_LEVEL)
  {
    RollBackMsgLog();
    return;
  }

  /* Check if we wanna log the type of connection from
   * where this message did come from */
  if (!((0x8000 >> (8 + log_table[n].cptr_status)) & LOG_MASK_TYPE))
  {
    RollBackMsgLog();
    return;
  }

  /* Complete the entry */
  if (sptr)
  {
    log_table[n].sptr_status = sptr->status;
    strncpy(log_table[n].sptr_name, sptr->name, HOSTLEN);
    log_table[n].sptr_name[HOSTLEN] = '\0';
    strncpy(log_table[n].sptr_yxx, sptr->yxx, 4);
    log_table[n].sptr = sptr;

    if (sptr->from)
    {
      strncpy(log_table[n].sptr_from_name, sptr->name, HOSTLEN);
      log_table[n].sptr_from_name[HOSTLEN] = '\0';
    }
    else
    {
      memset(log_table[n].sptr_from_name, 0, HOSTLEN);
    }
  }
  else
  {
    log_table[n].sptr_status = 0xFF;	/* Dummy value */
    memset(&log_table[n].sptr_name, 0, HOSTLEN);
    memset(log_table[n].sptr_yxx, 0, 4);

    log_table[n].sptr = 0;
    memset(&log_table[n].sptr_from_name, 0, HOSTLEN);
  }
}

/*
 * Store_Buffer (macroed as StoreBuffer)
 *
 * Saves the buffer and cptr info at the very first stage
 * of parsing, if Log_Message doesn't get called between
 * two Store_Buffer calls this function assumes that the parser
 * has rejected the message and therefore calls Log_Message
 * as if the message class was 0 and the sptr null
 */
void Store_Buffer(char *buf, aClient *cptr)
{
  register int n;

  /* Check if we have an entry pending, if so
   * complete it's processing */
  if (entry_stored_forlog)
    Log_Message((aClient *)NULL, 0);

  /* Update the "half used entry" flag */
  entry_stored_forlog = 1;

  /* First update the free entries counter */
  if (unused_log_entries)
    unused_log_entries--;

  /* Get an entry */
  n = (last_log_entry + 1) % MSGLOG_SIZE;

  /* Update the last_log_entry index */
  last_log_entry = n;

  /* Store what we have by now in it */
  log_table[n].cptr_status = cptr->status;
  strncpy(log_table[n].cptr_name, cptr->name, HOSTLEN);
  log_table[n].cptr_name[HOSTLEN] = '\0';
  strncpy(log_table[n].cptr_yxx, cptr->yxx, 4);
  log_table[n].cptr_fd = cptr->fd;
  log_table[n].cptr = cptr;	/* No checking for this, is lossy */
  strncpy(log_table[n].buffer, buf, 511);
}

#endif /* MSGLOG_ENABLED */
