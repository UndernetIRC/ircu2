/*
 * IRC - Internet Relay Chat, ircd/m_who.c
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

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "support.h"
#include "whocmds.h"

#include <assert.h>
#include <string.h>


/*
 * A little spin-marking utility to tell us wich clients we have already
 * processed and wich not
 */
static int who_marker = 0;
static void move_marker(void)
{
  if (!++who_marker)
  {
    struct Client *cptr = GlobalClientList;
    while (cptr)
    {
      cli_marker(cptr) = 0;
      cptr = cli_next(cptr);
    }
    who_marker++;
  }
}

#define CheckMark(x, y) ((x == y) ? 0 : (x = y))
#define Process(cptr) CheckMark(cli_marker(cptr), who_marker)

/*
 * m_who - generic message handler
 *
 *  parv[0] = sender prefix
 *  parv[1] = nickname mask list
 *  parv[2] = additional selection flag, only 'o' for now.
 *            and %flags to specify what fields to output
 *            plus a ,querytype if the t flag is specified
 *            so the final thing will be like o%tnchu,777
 *  parv[3] = _optional_ parameter that overrides parv[1]
 *            This can be used as "/quote who foo % :The Black Hacker
 *            to find me, parv[3] _can_ contain spaces !.
 */
int m_who(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *mask;           /* The mask we are looking for              */
  char ch;                      /* Scratch char register                    */
  struct Channel *chptr;                /* Channel to show                          */
  struct Client *acptr;         /* Client to show                           */

  int bitsel;                   /* Mask of selectors to apply               */
  int matchsel;                 /* Wich fields the match should apply on    */
  int counter;                  /* Query size counter,
                                   initially used to count fields           */
  int commas;                   /* Does our mask contain any comma ?
                                   If so is a list..                        */
  int fields;                   /* Mask of fields to show                   */
  int isthere = 0;              /* When this set the user is member of chptr */
  char *nick;                   /* Single element extracted from
                                   the mask list                            */
  char *p;                      /* Scratch char pointer                     */
  char *qrt;                    /* Pointer to the query type                */
  static char mymask[512];      /* To save the mask before corrupting it    */

  /* Let's find where is our mask, and if actually contains something */
  mask = ((parc > 1) ? parv[1] : 0);
  if (parc > 3 && parv[3])
    mask = parv[3];
  if (mask && ((mask[0] == '\0') ||
      (mask[1] == '\0' && ((mask[0] == '0') || (mask[0] == '*')))))
    mask = 0;

  /* Evaluate the flags now, we consider the second parameter 
     as "matchFlags%fieldsToInclude,querytype"           */
  bitsel = fields = counter = matchsel = 0;
  qrt = 0;
  if (parc > 2 && parv[2] && *parv[2])
  {
    p = parv[2];
    while (((ch = *(p++))) && (ch != '%') && (ch != ','))
      switch (ch)
      {
        case 'o':
        case 'O':
          bitsel |= WHOSELECT_OPER;
          continue;
        case 'x':
        case 'X':
          bitsel |= WHOSELECT_EXTRA;
          if (HasPriv(sptr, PRIV_WHOX))
	    log_write(LS_WHO, L_INFO, LOG_NOSNOTICE, "%#C WHO %s %s", sptr,
		      (BadPtr(parv[3]) ? parv[1] : parv[3]), parv[2]);
          continue;
        case 'n':
        case 'N':
          matchsel |= WHO_FIELD_NIC;
          continue;
        case 'u':
        case 'U':
          matchsel |= WHO_FIELD_UID;
          continue;
        case 'h':
        case 'H':
          matchsel |= WHO_FIELD_HOS;
          continue;
        case 'i':
        case 'I':
          matchsel |= WHO_FIELD_NIP;
          continue;
        case 's':
        case 'S':
          matchsel |= WHO_FIELD_SER;
          continue;
        case 'r':
        case 'R':
          matchsel |= WHO_FIELD_REN;
          continue;
        case 'a':
        case 'A':
          matchsel |= WHO_FIELD_ACC;
          continue;
      }
    if (ch == '%')
      while ((ch = *p++) && (ch != ','))
      {
        counter++;
        switch (ch)
        {
          case 'c':
          case 'C':
            fields |= WHO_FIELD_CHA;
            break;
          case 'd':
          case 'D':
            fields |= WHO_FIELD_DIS;
            break;
          case 'f':
          case 'F':
            fields |= WHO_FIELD_FLA;
            break;
          case 'h':
          case 'H':
            fields |= WHO_FIELD_HOS;
            break;
          case 'i':
          case 'I':
            fields |= WHO_FIELD_NIP;
            break;
          case 'l':
          case 'L':
            fields |= WHO_FIELD_IDL;
          case 'n':
          case 'N':
            fields |= WHO_FIELD_NIC;
            break;
          case 'r':
          case 'R':
            fields |= WHO_FIELD_REN;
            break;
          case 's':
          case 'S':
            fields |= WHO_FIELD_SER;
            break;
          case 't':
          case 'T':
            fields |= WHO_FIELD_QTY;
            break;
          case 'u':
          case 'U':
            fields |= WHO_FIELD_UID;
            break;
          case 'a':
          case 'A':
            fields |= WHO_FIELD_ACC;
            break;
          default:
            break;
        }
      };
    if (ch)
      qrt = p;
  }

  if (!matchsel)
    matchsel = WHO_FIELD_DEF;
  if (!fields)
    counter = 7;

  if (feature_bool(FEAT_HIS_WHO_SERVERNAME) && !IsAnOper(sptr))
    matchsel &= ~WHO_FIELD_SER;

  if (qrt && (fields & WHO_FIELD_QTY))
  {
    p = qrt;
    if (!((*p > '9') || (*p < '0')))
      p++;
    if (!((*p > '9') || (*p < '0')))
      p++;
    if (!((*p > '9') || (*p < '0')))
      p++;
    *p = '\0';
  }
  else
    qrt = 0;

  /* I'd love to add also a check on the number of matches fields per time */
  counter = (2048 / (counter + 4));
  if (mask && (strlen(mask) > 510))
    mask[510] = '\0';
  move_marker();
  commas = (mask && strchr(mask, ','));

  /* First treat mask as a list of plain nicks/channels */
  if (mask)
  {
    strcpy(mymask, mask);
    for (p = 0, nick = ircd_strtok(&p, mymask, ","); nick;
        nick = ircd_strtok(&p, 0, ","))
    {
      if (IsChannelName(nick) && (chptr = FindChannel(nick)))
      {
        isthere = (find_channel_member(sptr, chptr) != 0);
        if (isthere || SEE_CHANNEL(sptr, chptr, bitsel))
        {
          struct Membership* member;
          for (member = chptr->members; member; member = member->next_member)
          {
            acptr = member->user;
            if ((bitsel & WHOSELECT_OPER) &&
		!(IsAnOper(acptr) && (HasPriv(acptr, PRIV_DISPLAY) ||
				      HasPriv(sptr, PRIV_SEE_OPERS))))
              continue;
            if ((acptr != sptr) && (member->status & CHFL_ZOMBIE))
              continue;
            if (!(isthere || (SEE_USER(sptr, acptr, bitsel))))
              continue;
            if (!Process(acptr))        /* This can't be moved before other checks */
              continue;
            if (!(isthere || (SHOW_MORE(sptr, counter))))
              break;
            do_who(sptr, acptr, chptr, fields, qrt);
          }
        }
      }
      else
      {
        if ((acptr = FindUser(nick)) &&
            ((!(bitsel & WHOSELECT_OPER)) ||
	     (IsAnOper(acptr) && (HasPriv(acptr, PRIV_DISPLAY) ||
				  HasPriv(sptr, PRIV_SEE_OPERS)))) &&
            Process(acptr) && SHOW_MORE(sptr, counter))
        {
          do_who(sptr, acptr, 0, fields, qrt);
        }
      }
    }
  }

  /* If we didn't have any comma in the mask treat it as a
     real mask and try to match all relevant fields */
  if (!(commas || (counter < 1)))
  {
    int minlen, cset;
    static struct in_mask imask;
    if (mask)
    {
      matchcomp(mymask, &minlen, &cset, mask);
      if (matchcompIP(&imask, mask))
        matchsel &= ~WHO_FIELD_NIP;
      if ((minlen > NICKLEN) || !(cset & NTL_IRCNK))
        matchsel &= ~WHO_FIELD_NIC;
      if ((matchsel & WHO_FIELD_SER) &&
          ((minlen > HOSTLEN) || (!(cset & NTL_IRCHN))
          || (!markMatchexServer(mymask, minlen))))
        matchsel &= ~WHO_FIELD_SER;
      if ((minlen > USERLEN) || !(cset & NTL_IRCUI))
        matchsel &= ~WHO_FIELD_UID;
      if ((minlen > HOSTLEN) || !(cset & NTL_IRCHN))
        matchsel &= ~WHO_FIELD_HOS;
    }

    /* First of all loop through the clients in common channels */
    if ((!(counter < 1)) && matchsel) {
      struct Membership* member;
      struct Membership* chan;
      for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel) {
        chptr = chan->channel;
        for (member = chptr->members; member; member = member->next_member)
        {
          acptr = member->user;
          if (!(IsUser(acptr) && Process(acptr)))
            continue;           /* Now Process() is at the beginning, if we fail
                                   we'll never have to show this acptr in this query */
	  if ((bitsel & WHOSELECT_OPER) &&
	      !(IsAnOper(acptr) && (HasPriv(acptr, PRIV_DISPLAY) ||
				    HasPriv(sptr, PRIV_SEE_OPERS))))
	    continue;
          if ((mask) &&
              ((!(matchsel & WHO_FIELD_NIC))
              || matchexec(cli_name(acptr), mymask, minlen))
              && ((!(matchsel & WHO_FIELD_UID))
              || matchexec(cli_user(acptr)->username, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_SER))
              || (!HasFlag(cli_user(acptr)->server, FLAG_MAP)))
              && ((!(matchsel & WHO_FIELD_HOS))
              || matchexec(cli_user(acptr)->host, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_HOS))
	      || !HasHiddenHost(acptr)
	      || !IsAnOper(sptr)
              || matchexec(cli_user(acptr)->realhost, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_REN))
              || matchexec(cli_info(acptr), mymask, minlen))
              && ((!(matchsel & WHO_FIELD_NIP))
	      || (HasHiddenHost(acptr) && !IsAnOper(sptr))
              || ((((cli_ip(acptr).s_addr & imask.mask.s_addr) !=
              imask.bits.s_addr)) || (imask.fall
              && matchexec(ircd_ntoa((const char*) &(cli_ip(acptr))), mymask, minlen)))))
            continue;
          if (!SHOW_MORE(sptr, counter))
            break;
          do_who(sptr, acptr, chptr, fields, qrt);
        }
      }
    }
    /* Loop through all clients :-\, if we still have something to match to 
       and we can show more clients */
    if ((!(counter < 1)) && matchsel)
      for (acptr = cli_prev(&me); acptr; acptr = cli_prev(acptr))
      {
        if (!(IsUser(acptr) && Process(acptr)))
          continue;
	if ((bitsel & WHOSELECT_OPER) &&
	    !(IsAnOper(acptr) && (HasPriv(acptr, PRIV_DISPLAY) ||
				  HasPriv(sptr, PRIV_SEE_OPERS))))
	  continue;
        if (!(SEE_USER(sptr, acptr, bitsel)))
          continue;
        if ((mask) &&
            ((!(matchsel & WHO_FIELD_NIC))
            || matchexec(cli_name(acptr), mymask, minlen))
            && ((!(matchsel & WHO_FIELD_UID))
            || matchexec(cli_user(acptr)->username, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_SER))
            || (!HasFlag(cli_user(acptr)->server, FLAG_MAP)))
            && ((!(matchsel & WHO_FIELD_HOS))
            || matchexec(cli_user(acptr)->host, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_HOS))
	    || !HasHiddenHost(acptr)
	    || !IsAnOper(sptr)
            || matchexec(cli_user(acptr)->realhost, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_REN))
            || matchexec(cli_info(acptr), mymask, minlen))
            && ((!(matchsel & WHO_FIELD_NIP))
	    || (HasHiddenHost(acptr) && !IsAnOper(sptr))
            || ((((cli_ip(acptr).s_addr & imask.mask.s_addr) != imask.bits.s_addr))
            || (imask.fall
            && matchexec(ircd_ntoa((const char*) &(cli_ip(acptr))), mymask, minlen)))))
          continue;
        if (!SHOW_MORE(sptr, counter))
          break;
        do_who(sptr, acptr, 0, fields, qrt);
      }
  }

  /* Make a clean mask suitable to be sent in the "end of" */
  if (mask && (p = strchr(mask, ' ')))
    *p = '\0';
  send_reply(sptr, RPL_ENDOFWHO, BadPtr(mask) ? "*" : mask);

  /* Notify the user if we decided that his query was too long */
  if (counter < 0)
    send_reply(sptr, ERR_QUERYTOOLONG, "WHO");

  return 0;
}
