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
 *
 * --- avalon --- 6th April 1992
 * rewritten to scrap linked lists and use a table of structures which
 * is referenced like a circular loop. Should be faster and more efficient.
 *
 * --- comstud --- 25th March 1997
 * Everything rewritten from scratch.  Avalon's code was bad.  My version
 * is faster and more efficient.  No more hangs on /squits and you can
 * safely raise NICKNAMEHISTORYLENGTH to a higher value without hurting
 * performance.
 *
 * --- comstud --- 5th August 1997
 * Fixed for Undernet..
 *
 * --- Run --- 27th August 1997
 * Speeded up the code, added comments.
 *
 * $Id$
 */
#include "whowas.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_string.h"
#include "list.h"
#include "numeric.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"
#include "msg.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


static struct Whowas  whowas[NICKNAMEHISTORYLENGTH];
static struct Whowas* whowas_next = whowas;
struct Whowas* whowashash[WW_MAX];

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
 * We still have a static table of 'struct Whowas' structures in which we add
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
  struct Whowas *newww;
  struct Whowas *oldww;
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
void add_history(struct Client *cptr, int still_on)
{
  Current ww;
  ww.newww = whowas_next;

  /* If this entry has already been used, remove it from the lists */
  if (ww.newww->hashv != WHOWAS_UNUSED)
  {
    if (ww.oldww->online)       /* No need to update cnext/cprev when offline! */
    {
      /* Remove ww.oldww from the linked list with the same `online' pointers */
      *ww.oldww->cprevnextp = ww.oldww->cnext;

      assert(0 == ww.oldww->cnext);

    }
    /* Remove ww.oldww from the linked list with the same `hashv' */
    *ww.oldww->hprevnextp = ww.oldww->hnext;

    assert(0 == ww.oldww->hnext);

    if (ww.oldww->name)
      MyFree(ww.oldww->name);
    if (ww.oldww->username)
      MyFree(ww.oldww->username);
    if (ww.oldww->hostname)
      MyFree(ww.oldww->hostname);
    if (ww.oldww->servername)
      MyFree(ww.oldww->servername);
    if (ww.oldww->realname)
      MyFree(ww.oldww->realname);
    if (ww.oldww->away)
      MyFree(ww.oldww->away);
  }

  /* Initialize aWhoWas struct `newww' */
  ww.newww->hashv = hash_whowas_name(cli_name(cptr));
  ww.newww->logoff = CurrentTime;
  DupString(ww.newww->name, cli_name(cptr));
  DupString(ww.newww->username, cli_user(cptr)->username);
  DupString(ww.newww->hostname, cli_user(cptr)->host);
  /* Should be changed to server numeric */
  DupString(ww.newww->servername, cli_name(cli_user(cptr)->server));
  DupString(ww.newww->realname, cli_info(cptr));
  if (cptr->user->away)
    DupString(ww.newww->away, cli_user(cptr)->away);
  else
    ww.newww->away = NULL;

  /* Update/initialize online/cnext/cprev: */
  if (still_on)                 /* User just changed nicknames */
  {
    ww.newww->online = cptr;
    /* Add struct Whowas struct `newww' to start of 'online list': */
    if ((ww.newww->cnext = cli_whowas(cptr)))
      ww.newww->cnext->cprevnextp = &ww.newww->cnext;
    ww.newww->cprevnextp = &(cli_whowas(cptr));
    cli_whowas(cptr) = ww.newww;
  }
  else                          /* User quitting */
    ww.newww->online = NULL;

  /* Add struct Whowas struct `newww' to start of 'hashv list': */
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
void off_history(const struct Client *cptr)
{
  struct Whowas *temp;

  for (temp = cli_whowas(cptr); temp; temp = temp->cnext)
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
struct Client *get_history(const char *nick, time_t timelimit)
{
  struct Whowas *temp = whowashash[hash_whowas_name(nick)];
  timelimit = CurrentTime - timelimit;

  for (; temp; temp = temp->hnext)
    if (0 == ircd_strcmp(nick, temp->name) && temp->logoff > timelimit)
      return temp->online;

  return NULL;
}

void count_whowas_memory(int *wwu, size_t *wwum, int *wwa, size_t *wwam)
{
  struct Whowas *tmp;
  int i;
  int u = 0;
  int a = 0;
  size_t um = 0;
  size_t am = 0;
  assert(0 != wwu);
  assert(0 != wwum);
  assert(0 != wwa);
  assert(0 != wwam);

  for (i = 0, tmp = whowas; i < NICKNAMEHISTORYLENGTH; i++, tmp++) {
    if (tmp->hashv != WHOWAS_UNUSED) {
      u++;
      um += (strlen(tmp->name) + 1);
      um += (strlen(tmp->username) + 1);
      um += (strlen(tmp->hostname) + 1);
      um += (strlen(tmp->servername) + 1);
      if (tmp->away) {
        a++;
        am += (strlen(tmp->away) + 1);
      }
    }
  }
  *wwu = u;
  *wwum = um;
  *wwa = a;
  *wwam = am;
}


void initwhowas(void)
{
  int i;

  for (i = 0; i < NICKNAMEHISTORYLENGTH; i++)
    whowas[i].hashv = WHOWAS_UNUSED;
}

unsigned int hash_whowas_name(const char *name)
{
  unsigned int hash = 0;
  unsigned int hash2 = 0;
  unsigned char lower;

  do
  {
    lower = ToLower(*name);
    hash = (hash << 1) + lower;
    hash2 = (hash2 >> 1) + lower;
  }
  while (*++name);

  return ((hash & WW_MAX_INITIAL_MASK) << BITS_PER_COL) +
      (hash2 & BITS_PER_COL_MASK);
}

