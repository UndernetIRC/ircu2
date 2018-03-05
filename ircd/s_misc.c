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
 */
/** @file
 * @brief Miscellaneous support functions.
 * @version $Id$
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
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "uping.h"
#include "userload.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/** Array of English month names (0 = January). */
static char *months[] = {
  "January", "February", "March", "April",
  "May", "June", "July", "August",
  "September", "October", "November", "December"
};

/** Array of English day names (0 = Sunday). */
static char *weekdays[] = {
  "Sunday", "Monday", "Tuesday", "Wednesday",
  "Thursday", "Friday", "Saturday"
};

/*
 * stats stuff
 */
/** Global statistics structure. */
static struct ServerStatistics ircst;
/** Public pointer to global statistics structure. */
struct ServerStatistics* ServerStats = &ircst;

/** Formats a Unix time as a readable string.
 * @param clock Unix time to format (0 means #CurrentTime).
 * @return Pointer to a static buffer containing something like
 * "Sunday January 1 2000 -- 09:30 +01:00"
 */
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

  /* There is unfortunately no clean portable way to extract time zone
   * offset information, so do ugly things.
   */
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

/** Like ctime() but with no trailing newline. Also, it takes
 * the time value as parameter, instead of pointer to it.
 * @param value Unix time to format.
 * @return Pointer to a static buffer containing formatted time.
 */
char *myctime(time_t value)
{
  /* Use a secondary buffer in case ctime() would not replace an
   * overwritten newline.
   */
  static char buf[28];
  char *p;

  strcpy(buf, ctime(&value));
  if ((p = strchr(buf, '\n')) != NULL)
    *p = '\0';

  return buf;
}

/** Return the name of the client for various tracking and admin
 * purposes. The main purpose of this function is to return the
 * "socket host" name of the client, if that differs from the
 * advertised name (other than case).  But, this can be used on any
 * client structure.
 * @param sptr Client to operate on.
 * @param showip If non-zero, append [username\@text-ip] to name.
 * @return Either cli_name(\a sptr) or a static buffer.
 */
const char* get_client_name(const struct Client* sptr, int showip)
{
  static char nbuf[HOSTLEN * 2 + USERLEN + 5];

  if (!MyConnect(sptr) || !showip)
    return cli_name(sptr);
  ircd_snprintf(0, nbuf, sizeof(nbuf), "%s[%s@%s]", cli_name(sptr),
                IsGotId(sptr) ? cli_username(sptr) : "",
                cli_sock_ip(sptr));
  return nbuf;
}

/**
 * Exit one client, local or remote. Assuming for local client that
 * all dependents already have been removed, and socket is closed.
 * @param bcptr Client being (s)quitted.
 * @param comment The QUIT comment to send.
 */
/* Rewritten by Run - 24 sept 94 */
static void exit_one_client(struct Client* bcptr, const char* comment)
{
  struct SLink *lp;
  struct Ban *bp;

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
    while ((bp = cli_user(bcptr)->silence)) {
      cli_user(bcptr)->silence = bp->next;
      free_ban(bp);
    }

    /* Clean up snotice lists */
    if (MyUser(bcptr))
      set_snomask(bcptr, ~0, SNO_DEL);

    if (IsInvisible(bcptr)) {
      assert(UserStats.inv_clients > 0);
      --UserStats.inv_clients;
    }
    if (IsOper(bcptr)) {
      assert(UserStats.opers > 0);
      --UserStats.opers;
    }
    if (MyConnect(bcptr))
      Count_clientdisconnects(bcptr, UserStats);
    else
      Count_remoteclientquits(UserStats, bcptr);
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

/* exit_downlinks - added by Run 25-9-94 */
/**
 * Removes all clients and downlinks (+clients) of any server
 * QUITs are generated and sent to local users.
 * @param cptr server that must have all dependents removed
 * @param sptr source who thought that this was a good idea
 * @param comment comment sent as sign off message to local clients
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

/* exit_client, rewritten 25-9-94 by Run */
/**
 * Exits a client of *any* type (user, server, etc)
 * from this server. Also, this generates all necessary prototol
 * messages that this exit may cause.
 *
 * This function implicitly exits all other clients depending on
 * this connection.
 *
 * For convenience, this function returns a suitable value for
 * m_function return value:
 *
 *   CPTR_KILLED     if (cptr == bcptr)
 *   0                if (cptr != bcptr)
 *
 * This function can be called in two ways:
 * 1) From before or in parse(), exiting the 'cptr', in which case it was
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
 * @param cptr Connection currently being handled by read_message.
 * @param victim Client being killed.
 * @param killer Client that made the decision to remove \a victim.
 * @param comment Reason for the exit.
 * @return CPTR_KILLED if cptr == bcptr, else 0.
 */
int exit_client(struct Client *cptr,
    struct Client* victim,
    struct Client* killer,
    const char* comment)
{
  struct Client* acptr = 0;
  struct DLink *dlp;
  time_t on_for;

  char comment1[HOSTLEN + HOSTLEN + 2];
  assert(killer);
  if (MyConnect(victim))
  {
    SetFlag(victim, FLAG_CLOSING);

    if (feature_bool(FEAT_CONNEXIT_NOTICES) && IsUser(victim))
      sendto_opmask_butone(0, SNO_CONNEXIT,
                           "Client exiting: %s (%s@%s) [%s] [%s] <%s%s>",
                           cli_name(victim), cli_user(victim)->username,
                           cli_user(victim)->host, comment,
                           ircd_ntoa(&cli_ip(victim)),
                           NumNick(victim) /* two %s's */);
    update_load();

    on_for = CurrentTime - cli_firsttime(victim);

    /* This intentionally excludes WebIRC ports to make port scanning
     * for it a little harder.
     */
    if (IsUser(victim) || IsUserPort(victim))
      auth_send_exit(victim);

    if (IsUser(victim))
      log_write(LS_USER, L_TRACE, 0, "%Tu %i %s@%s %s %s %s%s %s :%s",
		cli_firsttime(victim), on_for,
		cli_user(victim)->username, cli_sockhost(victim),
                ircd_ntoa(&cli_ip(victim)),
                cli_account(victim),
                NumNick(victim), /* two %s's */
                cli_name(victim), cli_info(victim));

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
			  cli_name(victim),
                          cli_name(IsServer(killer) ? &his : killer),
			  comment);
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
			  "%C :Link with %s canceled: %s", acptr,
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
	  sendto_opmask_butone(acptr, SNO_OLDSNO, "Link with %s canceled: %s",
			       cli_name(victim), comment);
      }
    }
    /*
     *  Close the Client connection first.
     */
    close_connection(victim);
  }

  if (IsServer(victim))
  {
    if (feature_bool(FEAT_HIS_NETSPLIT))
      strcpy(comment1, "*.net *.split");
    else
    {
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
    if (dlp->value.cptr != cli_from(killer) && dlp->value.cptr != victim)
    {
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
   *  because cptr can never have been a dependent of victim    --Run
   */
  return (cptr == victim) ? CPTR_KILLED : 0;
}

/**
 * Exit client with formatted va_list message.
 * Thin wrapper around exit_client().
 * @param cptr Connection being processed.
 * @param bcptr Connection being closed.
 * @param sptr Connection who asked to close the victim.
 * @param pattern Format string for message.
 * @param vl Stdargs argument list.
 * @return Has a tail call to exit_client().
 */
/* added 25-9-94 by Run */
int vexit_client_msg(struct Client *cptr, struct Client *bcptr, struct Client *sptr,
    const char *pattern, va_list vl)
{
  char msgbuf[1024];
  ircd_vsnprintf(0, msgbuf, sizeof(msgbuf), pattern, vl);
  return exit_client(cptr, bcptr, sptr, msgbuf);
}

/**
 * Exit client with formatted message using a variable-length argument list.
 * Thin wrapper around exit_client().
 * @param cptr Connection being processed.
 * @param bcptr Connection being closed.
 * @param sptr Connection who asked to close the victim.
 * @param pattern Format string for message.
 * @return Has a tail call to exit_client().
 */
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

/** Initialize global server statistics. */
/* (Kind of pointless since C guarantees it's already zero'ed, but... */
void initstats(void)
{
  memset(&ircst, 0, sizeof(ircst));
}

/** Report server statistics to a client.
 * @param cptr Client who wants statistics.
 * @param sd StatDesc structure being looked up (unused).
 * @param param Extra parameter passed by user (unused).
 */
void tstats(struct Client *cptr, const struct StatDesc *sd, char *param)
{
  struct Client *acptr;
  int i;
  struct ServerStatistics *sp;
  struct ServerStatistics tmp;
  unsigned int is_ref;
  unsigned int maxconn;

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
      sp->is_sti += CurrentTime - cli_firsttime(acptr);
      sp->is_sv++;
    }
    else if (IsUser(acptr))
    {
      sp->is_cbs += cli_sendB(acptr);
      sp->is_cbr += cli_receiveB(acptr);
      sp->is_cti += CurrentTime - cli_firsttime(acptr);
      sp->is_cl++;
    }
    else if (IsUnknown(acptr))
      sp->is_ni++;
  }

  is_ref = sp->is_inactive + sp->is_all_inuse + sp->is_bad_ip
    + sp->is_reg_collided + sp->is_bad_username + sp->is_k_lined
    + sp->is_bad_password + sp->is_no_client + sp->is_class_full
    + sp->is_ip_full + sp->is_bad_socket + sp->is_throttled
    + sp->is_not_hub + sp->is_crule_fail + sp->is_not_server
    + sp->is_bad_server;
  maxconn = MAXCONNECTIONS;
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":accepts %u refused %u",
	     sp->is_ac, is_ref);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":inactive %u all in use %u bad ip %u collided %u",
             sp->is_inactive, sp->is_all_inuse, sp->is_bad_ip,
             sp->is_reg_collided);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":bad username %u G/K-lined %u bad password %u no client block %u",
             sp->is_bad_username, sp->is_k_lined, sp->is_bad_password,
             sp->is_no_client);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":class full %u IP full %u bad socket %u throttled %u",
             sp->is_class_full, sp->is_ip_full, sp->is_bad_socket,
             sp->is_throttled);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":not hub %u crule faile %u no server block %u bad password %u",
             sp->is_not_hub, sp->is_crule_fail, sp->is_not_server,
             sp->is_bad_server);
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
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":connected %u %u maxconn %u",
	     sp->is_cl, sp->is_sv, maxconn);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":bytes sent %Lu %Lu",
	     sp->is_cbs, sp->is_sbs);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":bytes recv %Lu %Lu",
	     sp->is_cbr, sp->is_sbr);
  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG, ":time connected %Lu %Lu",
	     sp->is_cti, sp->is_sti);
}
