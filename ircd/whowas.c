
/*
 * IRC - Internet Relay Chat, ircd/whowas.c
 * Copyright (C) 1990 Markku Savela
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

/*
 * --- avalon --- 6th April 1992
 * rewritten to scrap linked lists and use a table of structures which
 * is referenced like a circular loop. Should be faster and more efficient.
 */

/*
 * --- comstud --- 25th March 1997
 * Everything rewritten from scratch.  Avalon's code was bad.  My version
 * is faster and more efficient.  No more hangs on /squits and you can
 * safely raise NICKNAMEHISTORYLENGTH to a higher value without hurting
 * performance.
 */

/*
 * --- comstud --- 5th August 1997
 * Fixed for Undernet..
 */

/*
 * --- Run --- 27th August 1997
 * Speeded up the code, added comments.
 */

#include "sys.h"
#include <stdlib.h>
#include "common.h"
#include "h.h"
#include "struct.h"
#include "numeric.h"
#include "send.h"
#include "s_misc.h"
#include "s_err.h"
#include "whowas.h"
#include "ircd.h"
#include "list.h"
#include "s_user.h"
#include "support.h"

RCSTAG_CC("$Id$");

static aWhowas whowas[NICKNAMEHISTORYLENGTH];
static aWhowas *whowashash[WW_MAX];
static aWhowas *whowas_next = whowas;

static unsigned int hash_whowas_name(register const char *name);

extern char *canonize(char *);

/*
 * Since the introduction of numeric nicks (at least for upstream messages,
 * like MODE +o <nick>, KICK #chan <nick>, KILL <nick> etc), there is no
 * real important reason for a nick history anymore.
 * Nevertheless, there are two reason why we might want to keep it:
 * 1) The /WHOWAS command, which is often usefull to catch harrashing
 *    users or abusers in general.
 * 2) Clients still use the normal nicks in the client-server protocol,
 *    and it might be considered a nice feature that here we still have
 *    nick chasing.
 * Note however that BOTH reasons make it redundant to keep a whowas history
 * for users that split off.
 *
 * The rewrite of comstud was many to safe cpu during net.breaks and therefore
 * a bit redundant imho (Run).
 *
 * But - it was written anyway.  So lets look at the structure of the
 * whowas history now:
 *
 * We still have a static table of 'aWhowas' structures in which we add
 * new nicks (plus info) as in a rotating buffer.  We keep a global pointer
 * `whowas_next' that points to the next entry to be overwritten - or to
 * the oldest entry in the table (which is the same).
 *
 * Each entry keeps pointers for two doubly linked lists (thus four pointers):
 * A list of the entries that have the same hash value ('hashv list'), and
 * a list of the entries that have the same online pointer (`online list').
 * Note that the last list (pointers) is only updated as long as online points
 * to the corresponding client: As soon as the client signs off, this list
 * is not anymore maintained (and hopefully not used anymore either ;).
 *
 * So now we have two ways of accessing this database:
 * 1) Given a <nick> we can calculate a hashv and then whowashash[hashv] will
 *    point to the start of the 'hash list': all entries with the same hashv.
 *    We'll have to search this list to find the entry with the correct <nick>.
 *    Once we found the correct whowas entry, we have a pointer to the
 *    corresponding client - if still online - for nich chasing purposes.
 *    Note that the same nick can occur multiple times in the whowas history,
 *    each of these having the same hash value of course.  While a /WHOWAS on
 *    just a nick will return all entries, nick chasing will only find the
 *    first in the list.  Because new entries are added at the start of the
 *    'hash list' we will always find the youngest entry, which is what we want.
 * 2) Given an online client we have a pointer to the first whowas entry
 *    of the linked list of whowas entries that all belong to this client.
 *    We ONLY need this to reset all `online' pointers when this client
 *    signs off.
 *
 * 27/8/79:
 *
 * Note that following:
 *
 * a) We *only* (need to) change the 'hash list' and the 'online' list
 *    in add_history().
 * b) There we always ADD an entry to the BEGINNING of the 'hash list'
 *    and the 'online list': *new* entries are at the start of the lists.
 *    The oldest entries are at the end of the lists.
 * c) We always REMOVE the oldest entry we have (whowas_next), this means
 *    that this is always an entry that is at the *end* of the 'hash list'
 *    and 'online list' that it is a part of: the next pointer will
 *    always be NULL.
 * d) The previous pointer is *only* used to update the next pointer of the
 *    previous entry, therefore we could better use a pointer to this
 *    next pointer: That is faster - saves us a 'if' test (it will never be
 *    NULL because the last added entry will point to the pointer that
 *    points to the start of the list) and we won't need special code to
 *    update the list start pointers.
 *
 * I incorporated these considerations into the code below.
 *
 * --Run
 */

typedef union {
  aWhowas *newww;
  aWhowas *oldww;
} Current;

#define WHOWAS_UNUSED ((unsigned int)-1)

/*
 * add_history
 *
 * Add a client (cptr) that just changed nick (still_on == true), or
 * just signed off (still_on == false) to the `whowas' table.
 *
 * If the entry used was already in use, then this entry is
 * freed (lost).
 */
void add_history(aClient *cptr, int still_on)
{
  register Current ww;
  ww.newww = whowas_next;

  /* If this entry has already been used, remove it from the lists */
  if (ww.newww->hashv != WHOWAS_UNUSED)
  {
    if (ww.oldww->online)	/* No need to update cnext/cprev when offline! */
    {
      /* Remove ww.oldww from the linked list with the same `online' pointers */
      *ww.oldww->cprevnextp = ww.oldww->cnext;

      if (ww.oldww->cnext)
	MyCoreDump;
#if 0
      if (ww.oldww->cnext)	/* Never true, we always catch the
				   oldwwest nick of this client first */
	ww.oldww->cnext->cprevnextp = ww.oldww->cprevnextp;
#endif

    }
    /* Remove ww.oldww from the linked list with the same `hashv' */
    *ww.oldww->hprevnextp = ww.oldww->hnext;

    if (ww.oldww->hnext)
      MyCoreDump;
#if 0
    if (ww.oldww->hnext)
      ww.oldww->hnext->hprevnextp = ww.oldww->hprevnextp;
#endif

    if (ww.oldww->name)
      RunFree(ww.oldww->name);
    if (ww.oldww->username)
      RunFree(ww.oldww->username);
    if (ww.oldww->hostname)
      RunFree(ww.oldww->hostname);
    if (ww.oldww->servername)
      RunFree(ww.oldww->servername);
    if (ww.oldww->realname)
      RunFree(ww.oldww->realname);
    if (ww.oldww->away)
      RunFree(ww.oldww->away);
  }

  /* Initialize aWhoWas struct `newww' */
  ww.newww->hashv = hash_whowas_name(cptr->name);
  ww.newww->logoff = now;
  DupString(ww.newww->name, cptr->name);
  DupString(ww.newww->username, cptr->user->username);
  DupString(ww.newww->hostname, cptr->user->host);
  /* Should be changed to server numeric */
  DupString(ww.newww->servername, cptr->user->server->name);
  DupString(ww.newww->realname, cptr->info);
  if (cptr->user->away)
    DupString(ww.newww->away, cptr->user->away);
  else
    ww.newww->away = NULL;

  /* Update/initialize online/cnext/cprev: */
  if (still_on)			/* User just changed nicknames */
  {
    ww.newww->online = cptr;
    /* Add aWhowas struct `newww' to start of 'online list': */
    if ((ww.newww->cnext = cptr->whowas))
      ww.newww->cnext->cprevnextp = &ww.newww->cnext;
    ww.newww->cprevnextp = &cptr->whowas;
    cptr->whowas = ww.newww;
  }
  else				/* User quitting */
    ww.newww->online = NULL;

  /* Add aWhowas struct `newww' to start of 'hashv list': */
  if ((ww.newww->hnext = whowashash[ww.newww->hashv]))
    ww.newww->hnext->hprevnextp = &ww.newww->hnext;
  ww.newww->hprevnextp = &whowashash[ww.newww->hashv];
  whowashash[ww.newww->hashv] = ww.newww;

  /* Advance `whowas_next' to next entry in the `whowas' table: */
  if (++whowas_next == &whowas[NICKNAMEHISTORYLENGTH])
    whowas_next = whowas;
}

/*
 * off_history
 *
 * Client `cptr' signed off: Set all `online' pointers
 * corresponding to this client to NULL.
 */
void off_history(const aClient *cptr)
{
  aWhowas *temp;

  for (temp = cptr->whowas; temp; temp = temp->cnext)
    temp->online = NULL;
}

/*
 * get_history
 *
 * Return a pointer to a client that had nick `nick' not more then
 * `timelimit' seconds ago, if still on line.  Otherwise return NULL.
 *
 * This function is used for "nick chasing"; since the use of numeric
 * nicks for "upstream" messages in ircu2.10, this is only used for
 * looking up non-existing nicks in client->server messages.
 */
aClient *get_history(const char *nick, time_t timelimit)
{
  aWhowas *temp = whowashash[hash_whowas_name(nick)];
  timelimit = now - timelimit;

  for (; temp; temp = temp->hnext)
    if (!strCasediff(nick, temp->name) && temp->logoff > timelimit)
      return temp->online;

  return NULL;
}

void count_whowas_memory(int *wwu, size_t *wwum, int *wwa, size_t *wwam)
{
  register aWhowas *tmp;
  register int i;
  int u = 0, a = 0;
  size_t um = 0, am = 0;

  for (i = 0, tmp = whowas; i < NICKNAMEHISTORYLENGTH; i++, tmp++)
    if (tmp->hashv != WHOWAS_UNUSED)
    {
      u++;
      um += (strlen(tmp->name) + 1);
      um += (strlen(tmp->username) + 1);
      um += (strlen(tmp->hostname) + 1);
      um += (strlen(tmp->servername) + 1);
      if (tmp->away)
      {
	a++;
	am += (strlen(tmp->away) + 1);
      }
    }

  *wwu = u;
  *wwum = um;
  *wwa = a;
  *wwam = am;
}

/*
 * m_whowas
 *
 * parv[0] = sender prefix
 * parv[1] = nickname queried
 * parv[2] = maximum returned items (optional, default is unlimitted)
 * parv[3] = remote server target (Opers only, max returned items 20)
 */
int m_whowas(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
  register aWhowas *temp;
  register int cur = 0;
  int max = -1, found = 0;
  char *p, *nick, *s;

  if (parc < 2)
  {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, parv[0]);
    return 0;
  }
  if (parc > 2)
    max = atoi(parv[2]);
  if (parc > 3)
    if (hunt_server(1, cptr, sptr, ":%s WHOWAS %s %s :%s", 3, parc, parv))
      return 0;

  parv[1] = canonize(parv[1]);
  if (!MyConnect(sptr) && (max > 20))
    max = 20;			/* Set max replies at 20 */
  for (s = parv[1]; (nick = strtoken(&p, s, ",")); s = NULL)
  {
    /* Search through bucket, finding all nicknames that match */
    found = 0;
    for (temp = whowashash[hash_whowas_name(nick)]; temp; temp = temp->hnext)
    {
      if (!strCasediff(nick, temp->name))
      {
	sendto_one(sptr, rpl_str(RPL_WHOWASUSER),
	    me.name, parv[0], temp->name, temp->username,
	    temp->hostname, temp->realname);
	sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name, parv[0],
	    temp->name, temp->servername, myctime(temp->logoff));
	if (temp->away)
	  sendto_one(sptr, rpl_str(RPL_AWAY),
	      me.name, parv[0], temp->name, temp->away);
	cur++;
	found++;
      }
      if (max >= 0 && cur >= max)
	break;
    }
    if (!found)
      sendto_one(sptr, err_str(ERR_WASNOSUCHNICK), me.name, parv[0], nick);
    /* To keep parv[1] intact for ENDOFWHOWAS */
    if (p)
      p[-1] = ',';
  }
  sendto_one(sptr, rpl_str(RPL_ENDOFWHOWAS), me.name, parv[0], parv[1]);
  return 0;
}

void initwhowas(void)
{
  register int i;

  for (i = 0; i < NICKNAMEHISTORYLENGTH; i++)
    whowas[i].hashv = WHOWAS_UNUSED;
}

static unsigned int hash_whowas_name(register const char *name)
{
  register unsigned int hash = 0;
  register unsigned int hash2 = 0;
  register char lower;

  do
  {
    lower = toLower(*name);
    hash = (hash << 1) + lower;
    hash2 = (hash2 >> 1) + lower;
  }
  while (*++name);

  return ((hash & WW_MAX_INITIAL_MASK) << BITS_PER_COL) +
      (hash2 & BITS_PER_COL_MASK);
}
