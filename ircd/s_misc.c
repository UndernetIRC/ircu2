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

#include "sys.h"
#include <sys/stat.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include "h.h"
#include "struct.h"
#include "s_serv.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "s_misc.h"
#include "common.h"
#include "match.h"
#include "hash.h"
#include "s_bsd.h"
#include "res.h"
#include "list.h"
#include "ircd.h"
#include "s_ping.h"
#include "channel.h"
#include "s_err.h"
#include "support.h"
#include "userload.h"
#include "parse.h"
#include "s_user.h"
#include "numnicks.h"
#include "sprintf_irc.h"
#include "querycmds.h"
#include "IPcheck.h"

#include <assert.h>

RCSTAG_CC("$Id$");

static void exit_one_client(aClient *, char *);

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
struct stats ircst, *ircstp = &ircst;

char *date(time_t clock)
{
  static char buf[80], plus;
  Reg1 struct tm *lt, *gm;
  struct tm gmbuf;
  int minswest;

  if (!clock)
    clock = now;
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
  Reg1 char *p;

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
 *      "name[sockethost]", if name and sockhost are different and
 *      showip is false; else
 *      "name".
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
char *get_client_name(aClient *sptr, int showip)
{
  static char nbuf[HOSTLEN * 2 + USERLEN + 5];

  if (MyConnect(sptr))
  {
    if (IsUnixSocket(sptr))
    {
      if (showip)
	sprintf_irc(nbuf, "%s[%s]", sptr->name, sptr->sockhost);
      else
	sprintf_irc(nbuf, "%s[%s]", sptr->name, me.name);
    }
    else
    {
      if (showip)
	sprintf_irc(nbuf, "%s[%s@%s]", sptr->name,
	    (!(sptr->flags & FLAGS_GOTID)) ? "" :
	    sptr->username, inetntoa(sptr->ip));
      else
      {
	if (strCasediff(sptr->name, sptr->sockhost))
	  sprintf_irc(nbuf, "%s[%s]", sptr->name, sptr->sockhost);
	else
	  return sptr->name;
      }
    }
    return nbuf;
  }
  return sptr->name;
}

char *get_client_host(aClient *cptr)
{
  static char nbuf[HOSTLEN * 2 + USERLEN + 5];

  if (!MyConnect(cptr))
    return cptr->name;
  if (!cptr->hostp)
    return get_client_name(cptr, FALSE);
  if (IsUnixSocket(cptr))
    sprintf_irc(nbuf, "%s[%s]", cptr->name, me.name);
  else
    sprintf(nbuf, "%s[%-.*s@%-.*s]", cptr->name, USERLEN,
	(!(cptr->flags & FLAGS_GOTID)) ? "" : cptr->username,
	HOSTLEN, cptr->hostp->h_name);
  return nbuf;
}

/*
 * Form sockhost such that if the host is of form user@host, only the host
 * portion is copied.
 */
void get_sockhost(aClient *cptr, char *host)
{
  Reg3 char *s;
  if ((s = strchr(host, '@')))
    s++;
  else
    s = host;
  strncpy(cptr->sockhost, s, sizeof(cptr->sockhost) - 1);
}

/*
 * Return wildcard name of my server name according to given config entry
 * --Jto
 */
char *my_name_for_link(char *name, aConfItem *aconf)
{
  static char namebuf[HOSTLEN];
  register int count = aconf->port;
  register char *start = name;

  if (count <= 0 || count > 5)
    return start;

  while (count-- && name)
  {
    name++;
    name = strchr(name, '.');
  }
  if (!name)
    return start;

  namebuf[0] = '*';
  strncpy(&namebuf[1], name, HOSTLEN - 1);
  namebuf[HOSTLEN - 1] = '\0';

  return namebuf;
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
static void exit_downlinks(aClient *cptr, aClient *sptr, char *comment)
{
  Reg1 aClient *acptr;
  Reg2 Dlink *next;
  Reg3 Dlink *lp;
  aClient **acptrp;
  int i;

  /* Run over all its downlinks */
  for (lp = cptr->serv->down; lp; lp = next)
  {
    next = lp->next;
    acptr = lp->value.cptr;
    /* Remove the downlinks and client of the downlink */
    exit_downlinks(acptr, sptr, comment);
    /* Remove the downlink itself */
    exit_one_client(acptr, me.name);
  }
  /* Remove all clients of this server */
  acptrp = cptr->serv->client_list;
  for (i = 0; i <= cptr->serv->nn_mask; ++acptrp, ++i)
    if (*acptrp)
      exit_one_client(*acptrp, comment);
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
int exit_client(aClient *cptr,	/* Connection being handled by
				   read_message right now */
    aClient *bcptr,		/* Client being killed */
    aClient *sptr,		/* The client that made the decision
				   to remove this one, never NULL */
    char *comment)		/* Reason for the exit */
{
  Reg1 aClient *acptr;
  Reg3 Dlink *dlp;
#ifdef	FNAME_USERLOG
  time_t on_for;
#endif
  char comment1[HOSTLEN + HOSTLEN + 2];

  if (MyConnect(bcptr))
  {
    bcptr->flags |= FLAGS_CLOSING;
#ifdef ALLOW_SNO_CONNEXIT
#ifdef SNO_CONNEXIT_IP
    if (IsUser(bcptr))
    {
      sprintf_irc(sendbuf,
	  ":%s NOTICE * :*** Notice -- Client exiting: %s (%s@%s) [%s] [%s]",
	  me.name, bcptr->name, bcptr->user->username, bcptr->user->host,
	  comment, inetntoa(bcptr->ip));
      sendbufto_op_mask(SNO_CONNEXIT);
    }
#else /* SNO_CONNEXIT_IP */
    if (IsUser(bcptr))
    {
      sprintf_irc(sendbuf,
	  ":%s NOTICE * :*** Notice -- Client exiting: %s (%s@%s) [%s]",
	  me.name, bcptr->name, bcptr->user->username, bcptr->user->host,
	  comment);
      sendbufto_op_mask(SNO_CONNEXIT);
    }
#endif /* SNO_CONNEXIT_IP */
#endif /* ALLOW_SNO_CONNEXIT */
    update_load();
#ifdef FNAME_USERLOG
    on_for = now - bcptr->firsttime;
#if defined(USE_SYSLOG) && defined(SYSLOG_USERS)
    if (IsUser(bcptr))
      syslog(LOG_NOTICE, "%s (%3d:%02d:%02d): %s@%s (%s)\n",
	  myctime(bcptr->firsttime), on_for / 3600, (on_for % 3600) / 60,
	  on_for % 60, bcptr->user->username, bcptr->sockhost, bcptr->name);
#else
    if (IsUser(bcptr))
      write_log(FNAME_USERLOG,
	  "%s (%3d:%02d:%02d): %s@%s [%s]\n",
	  myctime(bcptr->firsttime),
	  on_for / 3600, (on_for % 3600) / 60,
	  on_for % 60,
	  bcptr->user->username, bcptr->user->host, bcptr->username);
#endif
#endif
    if (bcptr != sptr->from	/* The source knows already */
	&& IsClient(bcptr))	/* Not a Ping struct or Log file */
    {
      if (IsServer(bcptr) || IsHandshake(bcptr))
	sendto_one(bcptr, ":%s SQUIT %s 0 :%s", sptr->name, me.name, comment);
      else if (!IsConnecting(bcptr))
	sendto_one(bcptr, "ERROR :Closing Link: %s by %s (%s)",
	    get_client_name(bcptr, FALSE), sptr->name, comment);
      if ((IsServer(bcptr) || IsHandshake(bcptr) || IsConnecting(bcptr)) &&
	  (sptr == &me || (IsServer(sptr) &&
	  (strncmp(comment, "Leaf-only link", 14) ||
	  strncmp(comment, "Non-Hub link", 12)))))
      {
	if (bcptr->serv->user && *bcptr->serv->by &&
	    (acptr = findNUser(bcptr->serv->by)) &&
	    acptr->user == bcptr->serv->user)
	{
	  if (MyUser(acptr) || Protocol(acptr->from) < 10)
	    sendto_one(acptr,
		":%s NOTICE %s :Link with %s cancelled: %s",
		me.name, acptr->name, bcptr->name, comment);
	  else
	    sendto_one(acptr,
		"%s NOTICE %s%s :Link with %s cancelled: %s",
		NumServ(&me), NumNick(acptr), bcptr->name, comment);
	}
	else
	  acptr = NULL;
	if (sptr == &me)
	  sendto_lops_butone(acptr, "Link with %s cancelled: %s",
	      bcptr->name, comment);
      }
    }
    /*
     *  Close the Client connection first.
     */
    close_connection(bcptr);
  }

  if (IsServer(bcptr))
  {
    strcpy(comment1, bcptr->serv->up->name);
    strcat(comment1, " ");
    strcat(comment1, bcptr->name);
    if (IsUser(sptr))
      sendto_lops_butone(sptr, "%s SQUIT by %s [%s]:",
	  (sptr->user->server == bcptr ||
	  sptr->user->server == bcptr->serv->up) ? "Local" : "Remote",
	  get_client_name(sptr, FALSE), sptr->user->server->name);
    else if (sptr != &me && bcptr->serv->up != sptr)
      sendto_ops("Received SQUIT %s from %s :", bcptr->name,
	  IsServer(sptr) ? sptr->name : get_client_name(sptr, FALSE));
    sendto_op_mask(SNO_NETWORK, "Net break: %s (%s)", comment1, comment);
  }

  /*
   * First generate the needed protocol for the other server links
   * except the source:
   */
  for (dlp = me.serv->down; dlp; dlp = dlp->next)
    if (dlp->value.cptr != sptr->from && dlp->value.cptr != bcptr)
    {
      if (IsServer(bcptr))
	sendto_one(dlp->value.cptr, ":%s SQUIT %s " TIME_T_FMT " :%s",
	    sptr->name, bcptr->name, bcptr->serv->timestamp, comment);
      else if (IsUser(bcptr) && (bcptr->flags & FLAGS_KILLED) == 0)
	sendto_one(dlp->value.cptr, ":%s QUIT :%s", bcptr->name, comment);
    }

  /* Then remove the client structures */
  if (IsServer(bcptr))
    exit_downlinks(bcptr, sptr, comment1);
  exit_one_client(bcptr, comment);

  /*
   *  cptr can only have been killed if it was cptr itself that got killed here,
   *  because cptr can never have been a dependant of bcptr    --Run
   */
  return (cptr == bcptr) ? CPTR_KILLED : 0;
}

/*
 * Exit client with formatted message, added 25-9-94 by Run
 */
int vexit_client_msg(aClient *cptr, aClient *bcptr, aClient *sptr,
    char *pattern, va_list vl)
{
  char msgbuf[1024];
  vsprintf_irc(msgbuf, pattern, vl);
  return exit_client(cptr, bcptr, sptr, msgbuf);
}

int exit_client_msg(aClient *cptr, aClient *bcptr,
    aClient *sptr, char *pattern, ...)
{
  va_list vl;
  char msgbuf[1024];

  va_start(vl, pattern);
  vsprintf_irc(msgbuf, pattern, vl);
  va_end(vl);

  return exit_client(cptr, bcptr, sptr, msgbuf);
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
static void exit_one_client(aClient *bcptr, char *comment)
{
  Link *lp;

  if (bcptr->serv && bcptr->serv->client_list)	/* Was SetServerYXX called ? */
    ClearServerYXX(bcptr);	/* Removes server from server_list[] */
  if (IsUser(bcptr))
  {
    /* Stop a running /LIST clean */
    if (MyUser(bcptr) && bcptr->listing)
    {
      bcptr->listing->chptr->mode.mode &= ~MODE_LISTED;
      RunFree(bcptr->listing);
      bcptr->listing = NULL;
    }

    if (AskedPing(bcptr))
      cancel_ping(bcptr, NULL);
    /*
     * If a person is on a channel, send a QUIT notice
     * to every client (person) on the same channel (so
     * that the client can show the "**signoff" message).
     * (Note: The notice is to the local clients *only*)
     */
    sendto_common_channels(bcptr, ":%s QUIT :%s", bcptr->name, comment);

    while ((lp = bcptr->user->channel))
      remove_user_from_channel(bcptr, lp->value.chptr);

    /* Clean up invitefield */
    while ((lp = bcptr->user->invited))
      del_invite(bcptr, lp->value.chptr);

    /* Clean up silencefield */
    while ((lp = bcptr->user->silence))
      del_silence(bcptr, lp->value.cp);

    if (IsInvisible(bcptr))
      --nrof.inv_clients;
    if (IsOper(bcptr))
      --nrof.opers;
    if (MyConnect(bcptr))
      Count_clientdisconnects(bcptr, nrof);
    else
      Count_remoteclientquits(nrof);
  }
  else if (IsServer(bcptr))
  {
    /* Remove downlink list node of uplink */
    remove_dlink(&bcptr->serv->up->serv->down, bcptr->serv->updown);

    if (MyConnect(bcptr))
      Count_serverdisconnects(nrof);
    else
      Count_remoteserverquits(nrof);
  }
  else if (IsPing(bcptr))	/* Apperently, we are closing ALL links */
  {
    del_queries((char *)bcptr);
    end_ping(bcptr);
    return;
  }
  else if (IsMe(bcptr))
  {
    sendto_ops("ERROR: tried to exit me! : %s", comment);
    return;			/* ...must *never* exit self! */
  }
  else if (IsUnknown(bcptr) || IsConnecting(bcptr) || IsHandshake(bcptr))
    Count_unknowndisconnects(nrof);

  /* Update IPregistry */
  if (IsIPChecked(bcptr))
    IPcheck_disconnect(bcptr);

  /* 
   * Remove from serv->client_list
   * NOTE: user is *always* NULL if this is a server
   */
  if (bcptr->user)
  {
    assert(!IsServer(bcptr));
    /* bcptr->user->server->serv->client_list[IndexYXX(bcptr)] = NULL; */
    RemoveYXXClient(bcptr->user->server, bcptr->yxx);
  }

  /* Remove bcptr from the client list */
#ifdef DEBUGMODE
  if (hRemClient(bcptr) != 0)
    Debug((DEBUG_ERROR, "%p !in tab %s[%s] %p %p %p %d %d %p",
	bcptr, bcptr->name, bcptr->from ? bcptr->from->sockhost : "??host",
	bcptr->from, bcptr->next, bcptr->prev, bcptr->fd,
	bcptr->status, bcptr->user));
#else
  hRemClient(bcptr);
#endif
  remove_client_from_list(bcptr);
  return;
}

void checklist(void)
{
  Reg1 aClient *acptr;
  Reg2 int i, j;

  if (!(bootopt & BOOT_AUTODIE))
    return;
  for (j = i = 0; i <= highest_fd; i++)
    if (!(acptr = loc_clients[i]))
      continue;
    else if (IsUser(acptr))
      j++;
  if (!j)
  {
#ifdef	USE_SYSLOG
    syslog(LOG_WARNING, "ircd exiting: autodie");
#endif
    exit(0);
  }
  return;
}

void initstats(void)
{
  memset(&ircst, 0, sizeof(ircst));
}

void tstats(aClient *cptr, char *name)
{
  Reg1 aClient *acptr;
  Reg2 int i;
  Reg3 struct stats *sp;
  struct stats tmp;

  sp = &tmp;
  memcpy(sp, ircstp, sizeof(*sp));
  for (i = 0; i < MAXCONNECTIONS; i++)
  {
    if (!(acptr = loc_clients[i]))
      continue;
    if (IsServer(acptr))
    {
      sp->is_sbs += acptr->sendB;
      sp->is_sbr += acptr->receiveB;
      sp->is_sks += acptr->sendK;
      sp->is_skr += acptr->receiveK;
      sp->is_sti += now - acptr->firsttime;
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
      sp->is_cbs += acptr->sendB;
      sp->is_cbr += acptr->receiveB;
      sp->is_cks += acptr->sendK;
      sp->is_ckr += acptr->receiveK;
      sp->is_cti += now - acptr->firsttime;
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

  sendto_one(cptr, ":%s %d %s :accepts %u refused %u",
      me.name, RPL_STATSDEBUG, name, sp->is_ac, sp->is_ref);
  sendto_one(cptr, ":%s %d %s :unknown commands %u prefixes %u",
      me.name, RPL_STATSDEBUG, name, sp->is_unco, sp->is_unpf);
  sendto_one(cptr, ":%s %d %s :nick collisions %u unknown closes %u",
      me.name, RPL_STATSDEBUG, name, sp->is_kill, sp->is_ni);
  sendto_one(cptr, ":%s %d %s :wrong direction %u empty %u",
      me.name, RPL_STATSDEBUG, name, sp->is_wrdi, sp->is_empt);
  sendto_one(cptr, ":%s %d %s :numerics seen %u mode fakes %u",
      me.name, RPL_STATSDEBUG, name, sp->is_num, sp->is_fake);
  sendto_one(cptr, ":%s %d %s :auth successes %u fails %u",
      me.name, RPL_STATSDEBUG, name, sp->is_asuc, sp->is_abad);
  sendto_one(cptr, ":%s %d %s :local connections %u udp packets %u",
      me.name, RPL_STATSDEBUG, name, sp->is_loc, sp->is_udp);
  sendto_one(cptr, ":%s %d %s :Client Server", me.name, RPL_STATSDEBUG, name);
  sendto_one(cptr, ":%s %d %s :connected %u %u",
      me.name, RPL_STATSDEBUG, name, sp->is_cl, sp->is_sv);
  sendto_one(cptr, ":%s %d %s :bytes sent %u.%uK %u.%uK",
      me.name, RPL_STATSDEBUG, name,
      sp->is_cks, sp->is_cbs, sp->is_sks, sp->is_sbs);
  sendto_one(cptr, ":%s %d %s :bytes recv %u.%uK %u.%uK",
      me.name, RPL_STATSDEBUG, name,
      sp->is_ckr, sp->is_cbr, sp->is_skr, sp->is_sbr);
  sendto_one(cptr, ":%s %d %s :time connected " TIME_T_FMT " " TIME_T_FMT,
      me.name, RPL_STATSDEBUG, name, sp->is_cti, sp->is_sti);
}
