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
#include "config.h"

#include "s_debug.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_reply.h"
#include "ircd.h"
#include "jupe.h"
#include "list.h"
#include "motd.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_stats.h"
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

/*
 * Option string.  Must be before #ifdef DEBUGMODE.
 */
static char serveropts[256]; /* should be large enough for anything */

const char* debug_serveropts(void)
{
  int bp;
  int i = 0;
#define AddC(c)	serveropts[i++] = (c)

  bp = feature_int(FEAT_BUFFERPOOL);
  if (bp < 1000000) {
    AddC('b');
    if (bp > 99999)
      AddC((char)('0' + (bp / 100000)));
    if (bp > 9999)
      AddC((char)('0' + (bp / 10000) % 10));
    AddC((char)('0' + (bp / 1000) % 10));
  } else {
    AddC('B');
    if (bp > 99999999)
      AddC((char)('0' + (bp / 100000000)));
    if (bp > 9999999)
      AddC((char)('0' + (bp / 10000000) % 10));
    AddC((char)('0' + (bp / 1000000) % 10));
  }

#ifndef NDEBUG
  AddC('A');
#endif
#ifdef  DEBUGMODE
  AddC('D');
#endif

  if (feature_bool(FEAT_LOCOP_REHASH))
    AddC('e');

  if (feature_bool(FEAT_OPER_REHASH))
    AddC('E');

  if (feature_bool(FEAT_OPER_NO_CHAN_LIMIT))
    AddC('F');

  if (feature_bool(FEAT_OPER_MODE_LCHAN))
    AddC('f');

  if (feature_bool(FEAT_HUB))
    AddC('H');

  if (feature_bool(FEAT_SHOW_ALL_INVISIBLE_USERS))
    AddC('I');
  else if (feature_bool(FEAT_SHOW_INVISIBLE_USERS))
    AddC('i');

  if (feature_bool(FEAT_OPER_KILL)) {
    if (feature_bool(FEAT_LOCAL_KILL_ONLY))
      AddC('k');
    else
      AddC('K');
  }

  if (feature_bool(FEAT_OPER_WALK_THROUGH_LMODES))
    AddC('l');

  if (feature_bool(FEAT_IDLE_FROM_MSG))
    AddC('M');

  if (feature_bool(FEAT_NO_OPER_DEOP_LCHAN))
    AddC('o');

  if (feature_bool(FEAT_CRYPT_OPER_PASSWORD))
    AddC('p');

  if (feature_bool(FEAT_RELIABLE_CLOCK))
    AddC('R');

  if (feature_bool(FEAT_LOCOP_RESTART))
    AddC('s');

  if (feature_bool(FEAT_OPER_RESTART))
    AddC('S');

#if defined(USE_POLL) && defined(HAVE_POLL_H)
  AddC('U');
#endif

  if (feature_bool(FEAT_VIRTUAL_HOST))
    AddC('v');

  serveropts[i] = '\0';

  return serveropts;
}

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
    log_debug_init(use_tty);
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
void send_usage(struct Client *cptr, struct StatDesc *sd, int stat,
		char *param)
{
  os_get_rusage(cptr, CurrentTime - cli_since(&me), debug_enumerator);

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":DBUF alloc %d used %d",
	     DBufAllocCount, DBufUsedCount);
}
#endif /* DEBUGMODE */

void count_memory(struct Client *cptr, struct StatDesc *sd, int stat,
		  char *param)
{
  struct Client *acptr;
  struct SLink *link;
  struct Channel *chptr;
  struct ConfItem *aconf;
  const struct ConnectionClass* cltmp;
  struct Membership* member;

  int acc = 0,                  /* accounts */
      c = 0,                    /* clients */
      cn = 0,                   /* connections */
      ch = 0,                   /* channels */
      lcc = 0,                  /* local client conf links */
      us = 0,                   /* user structs */
      chi = 0,                  /* channel invites */
      chb = 0,                  /* channel bans */
      wwu = 0,                  /* whowas users */
      cl = 0,                   /* classes */
      co = 0,                   /* conf lines */
      memberships = 0;          /* channel memberships */

  int usi = 0,                  /* users invited */
      aw = 0,                   /* aways set */
      wwa = 0,                  /* whowas aways */
      gl = 0,                   /* glines */
      ju = 0;                   /* jupes */

  size_t chm = 0,               /* memory used by channels */
      chbm = 0,                 /* memory used by channel bans */
      cm = 0,                   /* memory used by clients */
      cnm = 0,                  /* memory used by connections */
      awm = 0,                  /* memory used by aways */
      wwam = 0,                 /* whowas away memory used */
      wwm = 0,                  /* whowas array memory used */
      glm = 0,                  /* memory used by glines */
      jum = 0,                  /* memory used by jupes */
      com = 0,                  /* memory used by conf lines */
      dbufs_allocated = 0,      /* memory used by dbufs */
      dbufs_used = 0,           /* memory used by dbufs */
      msg_allocated = 0,	/* memory used by struct Msg */
      msgbuf_allocated = 0,	/* memory used by struct MsgBuf */
      rm = 0,                   /* res memory used */
      totcl = 0, totch = 0, totww = 0, tot = 0;

  count_whowas_memory(&wwu, &wwm, &wwa, &wwam);
  wwm += sizeof(struct Whowas) * feature_int(FEAT_NICKNAMEHISTORYLENGTH);
  wwm += sizeof(struct Whowas *) * WW_MAX;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    c++;
    if (MyConnect(acptr))
    {
      cn++;
      for (link = cli_confs(acptr); link; link = link->next)
        lcc++;
    }
    if (cli_user(acptr))
    {
      us++;
      for (link = cli_user(acptr)->invited; link; link = link->next)
        usi++;
      for (member = cli_user(acptr)->channel; member; member = member->next_channel)
        ++memberships;
      if (cli_user(acptr)->away)
      {
        aw++;
        awm += (strlen(cli_user(acptr)->away) + 1);
      }
    }
    if (IsAccount(acptr))
      acc++;
  }
  cm = c * sizeof(struct Client);
  cnm = cn * sizeof(struct Connection);

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
  {
    ch++;
    chm += (strlen(chptr->chname) + sizeof(struct Channel));
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
	     ":Clients %d(%zu) Connections %d(%zu)", c, cm, cn, cnm);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Users %d(%zu) Accounts %d(%zu) Invites %d(%zu)",
	     us, us * sizeof(struct User), acc, acc * (ACCOUNTLEN + 1),
	     usi, usi * sizeof(struct SLink));
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":User channels %d(%zu) Aways %d(%zu)", memberships,
	     memberships * sizeof(struct Membership), aw, awm);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Attached confs %d(%zu)",
	     lcc, lcc * sizeof(struct SLink));

  totcl = cm + cnm + us * sizeof(struct User) + memberships * sizeof(struct Membership) + awm;
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
	     feature_int(FEAT_NICKNAMEHISTORYLENGTH), wwm);

  motd_memory_count(cptr);

  gl = gline_memory_count(&glm);
  ju = jupe_memory_count(&jum);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Glines %d(%zu) Jupes %d(%zu)", gl, glm, ju, jum);

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

  /* The DBuf caveats now count for this, but this routine now sends
   * replies all on its own.
   */
  msgq_count_memory(cptr, &msg_allocated, &msgbuf_allocated);

  rm = cres_mem(cptr);

  tot =
      totww + totch + totcl + com + cl * sizeof(struct ConnectionClass) +
      dbufs_allocated + msg_allocated + msgbuf_allocated + rm;
  tot += sizeof(void *) * HASHSIZE * 3;

#if defined(MDEBUG)
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Allocations: %zu(%zu)",
	     fda_get_block_count(), fda_get_byte_count());
#endif

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":Total: ww %zu ch %zu cl %zu co %zu db %zu ms %zu mb %zu",
	     totww, totch, totcl, com, dbufs_allocated, msg_allocated,
	     msgbuf_allocated);
}

