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
 *
 * $Id$
 *
 */
#include "s_debug.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd.h"
#include "list.h"
#include "numeric.h"
#include "numnicks.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "whowas.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>     /* offsetof */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
#ifdef  CHROOTDIR
    'c',
#endif
#ifdef  CMDLINE_CONFIG
    'C',
#endif
#ifdef  DO_ID
    'd',
#endif
#ifdef  DEBUGMODE
    'D',
#endif
#ifdef  LOCOP_REHASH
    'e',
#endif
#ifdef  OPER_REHASH
    'E',
#endif
#ifdef OPER_NO_CHAN_LIMIT
    'F',
#endif
#ifdef OPER_MODE_LCHAN
    'f',
#endif
#ifdef  HUB
    'H',
#endif
#if defined(SHOW_INVISIBLE_USERS) ||  defined(SHOW_ALL_INVISIBLE_USERS)
#ifdef  SHOW_ALL_INVISIBLE_USERS
    'I',
#else
    'i',
#endif
#endif
#ifdef  OPER_KILL
#ifdef  LOCAL_KILL_ONLY
    'k',
#else
    'K',
#endif
#endif
#ifdef  LEAST_IDLE
    'L',
#endif
#ifdef OPER_WALK_THROUGH_LMODES
    'l',
#endif
#ifdef  IDLE_FROM_MSG
    'M',
#endif
#ifdef  USEONE
    'O',
#endif
#ifdef NO_OPER_DEOP_LCHAN
    'o',
#endif
#ifdef  CRYPT_OPER_PASSWORD
    'p',
#endif
#ifdef  CRYPT_LINK_PASSWORD
    'P',
#endif
#ifdef  DEBUGMALLOC
#ifdef  MEMLEAKSTATS
    'Q',
#else
    'q',
#endif
#endif
#ifdef  RELIABLE_CLOCK
    'R',
#endif
#ifdef  LOCOP_RESTART
    's',
#endif
#ifdef  OPER_RESTART
    'S',
#endif
#ifdef  OPER_REMOTE
    't',
#endif
#if defined(USE_POLL) && defined(HAVE_POLL_H)
    'U',
#endif
#ifdef  VIRTUAL_HOST
    'v',
#endif
#ifdef BADCHAN
    'W',
#ifdef LOCAL_BADCHAN
    'x',
#endif
#endif
    '\0'
};

/* *INDENT-ON* */


/*
 * debug_init
 *
 * If the -t option is not given on the command line when the server is
 * started, all debugging output is sent to the file set by LPATH in config.h
 * Here we just open that file and make sure it is opened to fd 2 so that
 * any fprintf's to stderr also goto the logfile.  If the debuglevel is not
 * set from the command line by -x, use /dev/null as the dummy logfile as long
 * as DEBUGMODE has been defined, else dont waste the fd.
 */
void debug_init(int use_tty)
{
#ifdef  DEBUGMODE
  if (debuglevel >= 0) {
    printf("isatty = %d ttyname = %s\n", isatty(2), ttyname(2));
    log_debug_init(use_tty ? 0 : LOGFILE);
  }
#endif
}

#ifdef DEBUGMODE
void vdebug(int level, const char *form, va_list vl)
{
  static int loop = 0;
  int err = errno;

  if (!loop && (debuglevel >= 0) && (level <= debuglevel))
  {
    loop = 1;
    log_vwrite(LS_DEBUG, L_DEBUG, 0, form, vl);
    loop = 0;
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

static void debug_enumerator(struct Client* cptr, const char* msg)
{
  assert(0 != cptr);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":%s", msg);
}

/*
 * This is part of the STATS replies. There is no offical numeric for this
 * since this isnt an official command, in much the same way as HASH isnt.
 * It is also possible that some systems wont support this call or have
 * different field names for "struct rusage".
 * -avalon
 */
void send_usage(struct Client *cptr, char *nick)
{
  os_get_rusage(cptr, CurrentTime - me.since, debug_enumerator);

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":DBUF alloc %d used %d",
	     DBufAllocCount, DBufUsedCount);
}
#endif /* DEBUGMODE */

void count_memory(struct Client *cptr, char *nick)
{
  struct Client *acptr;
  struct SLink *link;
  struct Channel *chptr;
  struct ConfItem *aconf;
  const struct ConnectionClass* cltmp;
  struct Membership* member;

  int lc = 0,                   /* local clients */
      ch = 0,                   /* channels */
      lcc = 0,                  /* local client conf links */
      rc = 0,                   /* remote clients */
      us = 0,                   /* user structs */
      chi = 0,                  /* channel invites */
      chb = 0,                  /* channel bans */
      wwu = 0,                  /* whowas users */
      cl = 0,                   /* classes */
      co = 0,                   /* conf lines */
      memberships = 0;          /* channel memberships */

  int usi = 0,                  /* users invited */
      aw = 0,                   /* aways set */
      wwa = 0;                  /* whowas aways */

  size_t chm = 0,               /* memory used by channels */
      chbm = 0,                 /* memory used by channel bans */
      lcm = 0,                  /* memory used by local clients */
      rcm = 0,                  /* memory used by remote clients */
      awm = 0,                  /* memory used by aways */
      wwam = 0,                 /* whowas away memory used */
      wwm = 0,                  /* whowas array memory used */
      com = 0,                  /* memory used by conf lines */
      dbufs_allocated = 0,      /* memory used by dbufs */
      dbufs_used = 0,           /* memory used by dbufs */
      rm = 0,                   /* res memory used */
      totcl = 0, totch = 0, totww = 0, tot = 0;

  count_whowas_memory(&wwu, &wwm, &wwa, &wwam);
  wwm += sizeof(struct Whowas) * NICKNAMEHISTORYLENGTH;
  wwm += sizeof(struct Whowas *) * WW_MAX;

  for (acptr = GlobalClientList; acptr; acptr = acptr->next)
  {
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
      for (member = acptr->user->channel; member; member = member->next_channel)
        ++memberships;
      if (acptr->user->away)
      {
        aw++;
        awm += (strlen(acptr->user->away) + 1);
      }
    }
  }
  lcm = lc * CLIENT_LOCAL_SIZE;
  rcm = rc * CLIENT_REMOTE_SIZE;

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
  {
    ch++;
    chm += (strlen(chptr->chname) + sizeof(struct Channel));
#if 0
    /*
     * XXX - Members already counted in clients, don't count twice
     */
    for (member = chptr->members; member; member = member->next_member)
      chu++;
#endif
    for (link = chptr->invites; link; link = link->next)
      chi++;
    for (link = chptr->banlist; link; link = link->next)
    {
      chb++;
      chbm += (strlen(link->value.cp) + 1 + sizeof(struct SLink));
    }
  }

  for (aconf = GlobalConfList; aconf; aconf = aconf->next)
  {
    co++;
    com += aconf->host ? strlen(aconf->host) + 1 : 0;
    com += aconf->passwd ? strlen(aconf->passwd) + 1 : 0;
    com += aconf->name ? strlen(aconf->name) + 1 : 0;
    com += sizeof(struct ConfItem);
  }

  for (cltmp = get_class_list(); cltmp; cltmp = cltmp->next)
    cl++;

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Client Local %d(%zu) Remote %d(%zu)", lc, lcm, rc, rcm);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Users %d(%zu) Invites %d(%zu)", us, us * sizeof(struct User),
	     usi, usi * sizeof(struct SLink));
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":User channels %d(%zu) Aways %d(%zu)", memberships,
	     memberships * sizeof(struct Membership), aw, awm);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Attached confs %d(%zu)",
	     lcc, lcc * sizeof(struct SLink));

  totcl = lcm + rcm + us * sizeof(struct User) + memberships * sizeof(struct Membership) + awm;
  totcl += lcc * sizeof(struct SLink) + usi * sizeof(struct SLink);

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Conflines %d(%zu)", co,
	     com);

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Classes %d(%zu)", cl,
	     cl * sizeof(struct ConnectionClass));

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Channels %d(%zu) Bans %d(%zu)", ch, chm, chb, chbm);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Channel membrs %d(%zu) invite %d(%zu)", memberships,
	     memberships * sizeof(struct Membership), chi,
	     chi * sizeof(struct SLink));

  totch = chm + chbm + chi * sizeof(struct SLink);

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Whowas users %d(%zu) away %d(%zu)", wwu,
	     wwu * sizeof(struct User), wwa, wwam);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Whowas array %d(%zu)",
	     NICKNAMEHISTORYLENGTH, wwm);

  totww = wwu * sizeof(struct User) + wwam + wwm;

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Hash: client %d(%zu), chan is the same", HASHSIZE,
	     sizeof(void *) * HASHSIZE);

  /*
   * NOTE: this count will be accurate only for the exact instant that this
   * message is being sent, so the count is affected by the dbufs that
   * are being used to send this message out. If this is not desired, move
   * the dbuf_count_memory call to a place before we start sending messages
   * and cache DBufAllocCount and DBufUsedCount in variables until they 
   * are sent.
   */
  dbuf_count_memory(&dbufs_allocated, &dbufs_used);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":DBufs allocated %d(%zu) used %d(%zu)", DBufAllocCount,
	     dbufs_allocated, DBufUsedCount, dbufs_used);

  rm = cres_mem(cptr);

  tot =
      totww + totch + totcl + com + cl * sizeof(struct ConnectionClass) + dbufs_allocated +
      rm;
  tot += sizeof(void *) * HASHSIZE * 3;

#if !defined(NDEBUG)
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Allocations: %zu(%zu)",
	     fda_get_block_count(), fda_get_byte_count());
#endif

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Total: ww %zu ch %zu cl %zu co %zu db %zu", totww, totch,
	     totcl, com, dbufs_allocated);
}

