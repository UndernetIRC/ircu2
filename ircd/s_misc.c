/*
 * IRC - Internet Relay Chat, ircd/s_misc.c (formerly ircd/date.c)
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
#include "config.h"

#include "s_misc.h"
#include "IPcheck.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"
#include "uping.h"
#include "userload.h"

#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


static char *months[] = {
  "January", "February", "March", "April",
  "May", "June", "July", "August",
  "September", "October", "November", "December"
};

static char *weekdays[] = {
  "Sunday", "Monday", "Tuesday", "Wednesday",
  "Thursday", "Friday", "Saturday"
};

/*
 * stats stuff
 */
static struct ServerStatistics ircst;
struct ServerStatistics* ServerStats = &ircst;

char *date(time_t clock)
{
  static char buf[80], plus;
  struct tm *lt, *gm;
  struct tm gmbuf;
  int minswest;

  if (!clock)
    clock = CurrentTime;
  gm = gmtime(&clock);
  memcpy(&gmbuf, gm, sizeof(gmbuf));
  gm = &gmbuf;
  lt = localtime(&clock);

  minswest = (gm->tm_hour - lt->tm_hour) * 60 + (gm->tm_min - lt->tm_min);
  if (lt->tm_yday != gm->tm_yday)
  {
    if ((lt->tm_yday > gm->tm_yday && lt->tm_year == gm->tm_year) ||
        (lt->tm_yday < gm->tm_yday && lt->tm_year != gm->tm_year))
      minswest -= 24 * 60;
    else
      minswest += 24 * 60;
  }

  plus = (minswest > 0) ? '-' : '+';
  if (minswest < 0)
    minswest = -minswest;

  sprintf(buf, "%s %s %d %d -- %02d:%02d %c%02d:%02d",
      weekdays[lt->tm_wday], months[lt->tm_mon], lt->tm_mday,
      1900 + lt->tm_year, lt->tm_hour, lt->tm_min,
      plus, minswest / 60, minswest % 60);

  return buf;
}

/*
 * myctime
 *
 * This is like standard ctime()-function, but it zaps away
 * the newline from the end of that string. Also, it takes
 * the time value as parameter, instead of pointer to it.
 * Note that it is necessary to copy the string to alternate
 * buffer (who knows how ctime() implements it, maybe it statically
 * has newline there and never 'refreshes' it -- zapping that
 * might break things in other places...)
 */
char *myctime(time_t value)
{
  static char buf[28];
  char *p;

  strcpy(buf, ctime(&value));
  if ((p = strchr(buf, '\n')) != NULL)
    *p = '\0';

  return buf;
}

/*
 *  get_client_name
 *       Return the name of the client for various tracking and
 *       admin purposes. The main purpose of this function is to
 *       return the "socket host" name of the client, if that
 *    differs from the advertised name (other than case).
 *    But, this can be used to any client structure.
 *
 *    Returns:
 *      "name[user@ip#.port]" if 'showip' is true;
 *      "name" if 'showip' is false.
 *
 *  NOTE 1:
 *    Watch out the allocation of "nbuf", if either sptr->name
 *    or sptr->sockhost gets changed into pointers instead of
 *    directly allocated within the structure...
 *
 *  NOTE 2:
 *    Function return either a pointer to the structure (sptr) or
 *    to internal buffer (nbuf). *NEVER* use the returned pointer
 *    to modify what it points!!!
 */
const char* get_client_name(const struct Client* sptr, int showip)
{
  static char nbuf[HOSTLEN * 2 + USERLEN + 5];

  if (MyConnect(sptr)) {
    if (showip)
      ircd_snprintf(0, nbuf, sizeof(nbuf), "%s[%s@%s]", cli_name(sptr),
            (IsIdented(sptr)) ? cli_username(sptr) : "", cli_sock_ip(sptr));
    else
        return cli_name(sptr);
    return nbuf;
  }
  return cli_name(sptr);
}

const char *get_client_host(const struct Client *cptr)
{
  return get_client_name(cptr, HIDE_IP);
}

/*
 * Form sockhost such that if the host is of form user@host, only the host
 * portion is copied.
 */
void get_sockhost(struct Client *cptr, char *host)
{
  char *s;
  if ((s = strchr(host, '@')))
    s++;
  else
    s = host;
  ircd_strncpy(cli_sockhost(cptr), s, HOSTLEN);
}

/*
 * Exit one client, local or remote. Assuming for local client that
 * all dependants already have been removed, and socket is closed.
 *
 * Rewritten by Run - 24 sept 94
 *
 * bcptr : client being (s)quitted
 * sptr : The source (prefix) of the QUIT or SQUIT
 *
 * --Run
 */
static void exit_one_client(struct Client* bcptr, const char* comment)
{
  struct SLink *lp;

  if (cli_serv(bcptr) && cli_serv(bcptr)->client_list)  /* Was SetServerYXX called ? */
    ClearServerYXX(bcptr);      /* Removes server from server_list[] */
  if (IsUser(bcptr)) {
    /*
     * clear out uping requests
     */
    if (IsUPing(bcptr))
      uping_cancel(bcptr, 0);
    /*
     * Stop a running /LIST clean
     */
    if (MyUser(bcptr) && cli_listing(bcptr)) {
      cli_listing(bcptr)->chptr->mode.mode &= ~MODE_LISTED;
      MyFree(cli_listing(bcptr));
      cli_listing(bcptr) = NULL;
    }
    /*
     * If a person is on a channel, send a QUIT notice
     * to every client (person) on the same channel (so
     * that the client can show the "**signoff" message).
     * (Note: The notice is to the local clients *only*)
     */
    sendcmdto_common_channels_butone(bcptr, CMD_QUIT, NULL, ":%s", comment);

    remove_user_from_all_channels(bcptr);

    /* Clean up invitefield */
    while ((lp = cli_user(bcptr)->invited))
      del_invite(bcptr, lp->value.chptr);

    /* Clean up silencefield */
    while ((lp = cli_user(bcptr)->silence))
      del_silence(bcptr, lp->value.cp);

    /* Clean up snotice lists */
    if (MyUser(bcptr))
      set_snomask(bcptr, ~0, SNO_DEL);

    if (IsInvisible(bcptr))
      --UserStats.inv_clients;
    if (IsOper(bcptr))
      --UserStats.opers;
    if (MyConnect(bcptr))
      Count_clientdisconnects(bcptr, UserStats);
    else {
      Count_remoteclientquits(UserStats, bcptr);
    }
  }
  else if (IsServer(bcptr))
  {
    /* Remove downlink list node of uplink */
    remove_dlink(&(cli_serv(cli_serv(bcptr)->up))->down, cli_serv(bcptr)->updown);
    cli_serv(bcptr)->updown = 0;

    if (MyConnect(bcptr))
      Count_serverdisconnects(UserStats);
    else
      Count_remoteserverquits(UserStats);
  }
  else if (IsMe(bcptr))
  {
    sendto_opmask_butone(0, SNO_OLDSNO, "ERROR: tried to exit me! : %s",
			 comment);
    return;                     /* ...must *never* exit self! */
  }
  else if (IsUnknown(bcptr) || IsConnecting(bcptr) || IsHandshake(bcptr))
    Count_unknowndisconnects(UserStats);

  /*
   * Update IPregistry
   */
  if (IsIPChecked(bcptr))
    IPcheck_disconnect(bcptr);

  /* 
   * Remove from serv->client_list
   * NOTE: user is *always* NULL if this is a server
   */
  if (cli_user(bcptr)) {
    assert(!IsServer(bcptr));
    /* bcptr->user->server->serv->client_list[IndexYXX(bcptr)] = NULL; */
    RemoveYXXClient(cli_user(bcptr)->server, cli_yxx(bcptr));
  }

  /* Remove bcptr from the client list */
#ifdef DEBUGMODE
  if (hRemClient(bcptr) != 0)
    Debug((DEBUG_ERROR, "%p !in tab %s[%s] %p %p %p %d %d %p",
          bcptr, cli_name(bcptr), cli_from(bcptr) ? cli_sockhost(cli_from(bcptr)) : "??host",
          cli_from(bcptr), cli_next(bcptr), cli_prev(bcptr), cli_fd(bcptr),
          cli_status(bcptr), cli_user(bcptr)));
#else
  hRemClient(bcptr);
#endif
  remove_client_from_list(bcptr);
}

/*
 * exit_downlinks - added by Run 25-9-94
 *
 * Removes all clients and downlinks (+clients) of any server
 * QUITs are generated and sent to local users.
 *
 * cptr    : server that must have all dependents removed
 * sptr    : source who thought that this was a good idea
 * comment : comment sent as sign off message to local clients
 */
static void exit_downlinks(struct Client *cptr, struct Client *sptr, char *comment)
{
  struct Client *acptr;
  struct DLink *next;
  struct DLink *lp;
  struct Client **acptrp;
  int i;

  /* Run over all its downlinks */
  for (lp = cli_serv(cptr)->down; lp; lp = next)
  {
    next = lp->next;
    acptr = lp->value.cptr;
    /* Remove the downlinks and client of the downlink */
    exit_downlinks(acptr, sptr, comment);
    /* Remove the downlink itself */
    exit_one_client(acptr, cli_name(&me));
  }
  /* Remove all clients of this server */
  acptrp = cli_serv(cptr)->client_list;
  for (i = 0; i <= cli_serv(cptr)->nn_mask; ++acptrp, ++i) {
    if (*acptrp)
      exit_one_client(*acptrp, comment);
  }
}

/*
 * exit_client, rewritten 25-9-94 by Run
 *
 * This function exits a client of *any* type (user, server, etc)
 * from this server. Also, this generates all necessary prototol
 * messages that this exit may cause.
 *
 * This function implicitly exits all other clients depending on
 * this connection.
 *
 * For convenience, this function returns a suitable value for
 * m_funtion return value:
 *
 *   CPTR_KILLED     if (cptr == bcptr)
 *   0                if (cptr != bcptr)
 *
 * This function can be called in two ways:
 * 1) From before or in parse(), exitting the 'cptr', in which case it was
 *    invoked as exit_client(cptr, cptr, &me,...), causing it to always
 *    return CPTR_KILLED.
 * 2) Via parse from a m_function call, in which case it was invoked as
 *    exit_client(cptr, acptr, sptr, ...). Here 'sptr' is known; the client
 *    that generated the message in a way that we can assume he already
 *    did remove acptr from memory himself (or in other cases we don't mind
 *    because he will be delinked.) Or invoked as:
 *    exit_client(cptr, acptr/sptr, &me, ...) when WE decide this one should
 *    be removed.
 * In general: No generated SQUIT or QUIT should be sent to source link
 * sptr->from. And CPTR_KILLED should be returned if cptr got removed (too).
 *
 * --Run
 */
int exit_client(struct Client *cptr,    /* Connection being handled by
                                   read_message right now */
    struct Client* victim,              /* Client being killed */
    struct Client* killer,              /* The client that made the decision
                                   to remove this one, never NULL */
    const char* comment)              /* Reason for the exit */
{
  struct Client* acptr = 0;
  struct DLink *dlp;
  time_t on_for;

  char comment1[HOSTLEN + HOSTLEN + 2];
  assert(killer);
  if (MyConnect(victim)) {
    SetFlag(victim, FLAG_CLOSING);

    if (feature_bool(FEAT_CONNEXIT_NOTICES) && IsUser(victim))
      sendto_opmask_butone(0, SNO_CONNEXIT,
			   "Client exiting: %s (%s@%s) [%s] [%s]",
			   cli_name(victim), cli_user(victim)->username,
			   cli_user(victim)->host, comment,
			   ircd_ntoa((const char*) &(cli_ip(victim))));

    update_load();

    on_for = CurrentTime - cli_firsttime(victim);

    if (IsUser(victim))
      log_write(LS_USER, L_TRACE, 0, "%s (%3d:%02d:%02d): %s@%s (%s)",
		myctime(cli_firsttime(victim)), on_for / 3600,
		(on_for % 3600) / 60, on_for % 60, cli_user(victim)->username,
		cli_sockhost(victim), cli_name(victim));

    if (victim != cli_from(killer)  /* The source knows already */
        && IsClient(victim))    /* Not a Ping struct or Log file */
    {
      if (IsServer(victim) || IsHandshake(victim))
	sendcmdto_one(killer, CMD_SQUIT, victim, "%s 0 :%s", cli_name(&me), comment);
      else if (!IsConnecting(victim)) {
        if (!IsDead(victim)) {
	  if (IsServer(victim))
	    sendcmdto_one(killer, CMD_ERROR, victim,
			  ":Closing Link: %s by %s (%s)", cli_name(victim),
			  cli_name(killer), comment);
	  else
	    sendrawto_one(victim, MSG_ERROR " :Closing Link: %s by %s (%s)",
			  cli_name(victim), IsServer(killer) ? cli_name(&me) :
			  cli_name(killer), comment);
	}
      }
      if ((IsServer(victim) || IsHandshake(victim) || IsConnecting(victim)) &&
          (killer == &me || (IsServer(killer) &&
          (strncmp(comment, "Leaf-only link", 14) ||
          strncmp(comment, "Non-Hub link", 12)))))
      {
        /*
         * Note: check user == user needed to make sure we have the same
         * client
         */
        if (cli_serv(victim)->user && *(cli_serv(victim))->by &&
            (acptr = findNUser(cli_serv(victim)->by))) {
          if (cli_user(acptr) == cli_serv(victim)->user) {
	    sendcmdto_one(&me, CMD_NOTICE, acptr,
			  "%C :Link with %s cancelled: %s", acptr,
			  cli_name(victim), comment);
          }
          else {
            /*
             * not right client, set by to empty string
             */
            acptr = 0;
            *(cli_serv(victim))->by = '\0';
          }
        }
        if (killer == &me)
	  sendto_opmask_butone(acptr, SNO_OLDSNO, "Link with %s cancelled: %s",
			       cli_name(victim), comment);
      }
    }
    /*
     *  Close the Client connection first.
     */
    close_connection(victim);
  }

  if (IsServer(victim)) {
    if (feature_bool(FEAT_HIS_NETSPLIT))
      strcpy(comment1, "*.net *.split");
    else {
      strcpy(comment1, cli_name(cli_serv(victim)->up));
      strcat(comment1, " ");
      strcat(comment1, cli_name(victim));
    }
    if (IsUser(killer))
      sendto_opmask_butone(killer, SNO_OLDSNO, "%s SQUIT by %s [%s]:",
			   (cli_user(killer)->server == victim ||
			    cli_user(killer)->server == cli_serv(victim)->up) ?
			   "Local" : "Remote",
			   get_client_name(killer, HIDE_IP),
			   cli_name(cli_user(killer)->server));
    else if (killer != &me && cli_serv(victim)->up != killer)
      sendto_opmask_butone(0, SNO_OLDSNO, "Received SQUIT %s from %s :",
			   cli_name(victim), IsServer(killer) ? cli_name(killer) :
			   get_client_name(killer, HIDE_IP));
    sendto_opmask_butone(0, SNO_NETWORK, "Net break: %C %C (%s)",
			 cli_serv(victim)->up, victim, comment);
  }

  /*
   * First generate the needed protocol for the other server links
   * except the source:
   */
  for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
    if (dlp->value.cptr != cli_from(killer) && dlp->value.cptr != victim) {
      if (IsServer(victim))
	sendcmdto_one(killer, CMD_SQUIT, dlp->value.cptr, "%s %Tu :%s",
		      cli_name(victim), cli_serv(victim)->timestamp, comment);
      else if (IsUser(victim) && !HasFlag(victim, FLAG_KILLED))
	sendcmdto_one(victim, CMD_QUIT, dlp->value.cptr, ":%s", comment);
    }
  }
  /* Then remove the client structures */
  if (IsServer(victim))
    exit_downlinks(victim, killer, comment1);
  exit_one_client(victim, comment);

  /*
   *  cptr can only have been killed if it was cptr itself that got killed here,
   *  because cptr can never have been a dependant of victim    --Run
   */
  return (cptr == victim) ? CPTR_KILLED : 0;
}

/*
 * Exit client with formatted message, added 25-9-94 by Run
 */
int vexit_client_msg(struct Client *cptr, struct Client *bcptr, struct Client *sptr,
    const char *pattern, va_list vl)
{
  char msgbuf[1024];
  ircd_vsnprintf(0, msgbuf, sizeof(msgbuf), pattern, vl);
  return exit_client(cptr, bcptr, sptr, msgbuf);
}

int exit_client_msg(struct Client *cptr, struct Client *bcptr,
    struct Client *sptr, const char *pattern, ...)
{
  va_list vl;
  char msgbuf[1024];

  va_start(vl, pattern);
  ircd_vsnprintf(0, msgbuf, sizeof(msgbuf), pattern, vl);
  va_end(vl);

  return exit_client(cptr, bcptr, sptr, msgbuf);
}

void initstats(void)
{
  memset(&ircst, 0, sizeof(ircst));
}

void tstats(struct Client *cptr, struct StatDesc *sd, int stat, char *param)
{
  struct Client *acptr;
  int i;
  struct ServerStatistics *sp;
  struct ServerStatistics tmp;

  sp = &tmp;
  memcpy(sp, ServerStats, sizeof(struct ServerStatistics));
  for (i = 0; i < MAXCONNECTIONS; i++)
  {
    if (!(acptr = LocalClientArray[i]))
      continue;
    if (IsServer(acptr))
    {
      sp->is_sbs += cli_sendB(acptr);
      sp->is_sbr += cli_receiveB(acptr);
      sp->is_sks += cli_sendK(acptr);
      sp->is_skr += cli_receiveK(acptr);
      sp->is_sti += CurrentTime - cli_firsttime(acptr);
      sp->is_sv++;
      if (sp->is_sbs > 1023)
      {
        sp->is_sks += (sp->is_sbs >> 10);
        sp->is_sbs &= 0x3ff;
      }
      if (sp->is_sbr > 1023)
      {
        sp->is_skr += (sp->is_sbr >> 10);
        sp->is_sbr &= 0x3ff;
      }
    }
    else if (IsUser(acptr))
    {
      sp->is_cbs += cli_sendB(acptr);
      sp->is_cbr += cli_receiveB(acptr);
      sp->is_cks += cli_sendK(acptr);
      sp->is_ckr += cli_receiveK(acptr);
      sp->is_cti += CurrentTime - cli_firsttime(acptr);
      sp->is_cl++;
      if (sp->is_cbs > 1023)
      {
        sp->is_cks += (sp->is_cbs >> 10);
        sp->is_cbs &= 0x3ff;
      }
      if (sp->is_cbr > 1023)
      {
        sp->is_ckr += (sp->is_cbr >> 10);
        sp->is_cbr &= 0x3ff;
      }
    }
    else if (IsUnknown(acptr))
      sp->is_ni++;
  }

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":accepts %u refused %u",
	     sp->is_ac, sp->is_ref);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":unknown commands %u prefixes %u", sp->is_unco, sp->is_unpf);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":nick collisions %u unknown closes %u", sp->is_kill, sp->is_ni);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":wrong direction %u empty %u", sp->is_wrdi, sp->is_empt);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":numerics seen %u mode fakes %u", sp->is_num, sp->is_fake);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
	     ":auth successes %u fails %u", sp->is_asuc, sp->is_abad);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":local connections %u",
	     sp->is_loc);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":Client server");
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":connected %u %u",
	     sp->is_cl, sp->is_sv);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":bytes sent %u.%uK %u.%uK",
	     sp->is_cks, sp->is_cbs, sp->is_sks, sp->is_sbs);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":bytes recv %u.%uK %u.%uK",
	     sp->is_ckr, sp->is_cbr, sp->is_skr, sp->is_sbr);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":time connected %Tu %Tu",
	     sp->is_cti, sp->is_sti);
}
