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
#include "ircd_snprintf.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>


/** Variable storing current cli_marker() value to mark visited clients. */
static int who_marker = 0;
/** Increment #who_marker, handling overflow if necessary. */
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

#define WHOSELECT_OPER 1   /**< Flag for /WHO: Show IRC operators. */
#define WHOSELECT_EXTRA 2  /**< Flag for /WHO: Pull rank to see users. */
#define WHOSELECT_DELAY 4  /**< Flag for /WHO: Show join-delayed users. */

#define WHO_FIELD_QTY 1    /**< Display query type. */
#define WHO_FIELD_CHA 2    /**< Show common channel name. */
#define WHO_FIELD_UID 4    /**< Show username. */
#define WHO_FIELD_NIP 8    /**< Show IP address. */
#define WHO_FIELD_HOS 16   /**< Show hostname. */
#define WHO_FIELD_SER 32   /**< Show server. */
#define WHO_FIELD_NIC 64   /**< Show nickname. */
#define WHO_FIELD_FLA 128  /**< Show flags (away, oper, chanop, etc). */
#define WHO_FIELD_DIS 256  /**< Show hop count (distance). */
#define WHO_FIELD_REN 512  /**< Show realname (info). */
#define WHO_FIELD_IDL 1024 /**< Show idle time. */
#define WHO_FIELD_ACC 2048 /**< Show account name. */
#define WHO_FIELD_OPL 4096 /**< Show oplevel. */

/** Default fields for /WHO */
#define WHO_FIELD_DEF ( WHO_FIELD_NIC | WHO_FIELD_UID | WHO_FIELD_HOS | WHO_FIELD_SER )

/** Is \a ac plainly visible to \a s?
 * @param[in] s Client trying to see \a ac.
 * @param[in] ac Client being looked at.
 */
#define IS_VISIBLE_USER(s,ac) ((s==ac) || (!IsInvisible(ac)))

/** Can \a s see \a ac by using the flags in \a b?
 * @param[in] s Client trying to see \a ac.
 * @param[in] ac Client being looked at.
 * @param[in] b Bitset of extra flags (options: WHOSELECT_EXTRA).
 */
#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac) || \
                             ((b & WHOSELECT_EXTRA) && MyConnect(ac) && \
                             (HasPriv((s), PRIV_SHOW_INVIS) || \
                              HasPriv((s), PRIV_SHOW_ALL_INVIS))))

/** Can \a s see \a ac by using the flags in \a b?
 * @param[in] s Client trying to see \a ac.
 * @param[in] ac Client being looked at.
 * @param[in] b Bitset of extra flags (options: WHOSELECT_EXTRA).
 */
#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b) || \
                            ((b & WHOSELECT_EXTRA) && \
                              HasPriv((s), PRIV_SHOW_ALL_INVIS)))

/** Should we show more clients to \a sptr?
 * @param[in] sptr Client listing other users.
 * @param[in,out] counter Default count for clients.
 */
#define SHOW_MORE(sptr, counter) (HasPriv(sptr, PRIV_UNLIMIT_QUERY) || (!(counter-- < 0)) )

/** Can \a s see \a chptr?
 * @param[in] s Client trying to see \a chptr.
 * @param[in] chptr Channel being looked at.
 * @param[in] b Bitset of extra flags (options: WHOSELECT_EXTRA).
 */
#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SEE_CHAN)))

/** Send a WHO reply to a client who asked.
 * @param[in] sptr Client who is searching for other users.
 * @param[in] acptr Client who may be shown to \a sptr.
 * @param[in] repchan Shared channel that provides visibility.
 * @param[in] fields Bitmask of WHO_FIELD_* values, indicating what to show.
 * @param[in] qrt Query type string (ignored unless \a fields & WHO_FIELD_QTY).
 */
static void do_who(struct Client* sptr, struct Client* acptr,
                   struct Channel* repchan, int fields, char* qrt)
{
  char *p1;
  struct Membership *chan = 0;

  static char buf1[512];
  /* NOTE: with current fields list and sizes this _cannot_ overrun, 
     and also the message finally sent shouldn't ever be truncated */

  p1 = buf1;
  buf1[1] = '\0';

  /* If we don't have a channel and we need one... try to find it,
     unless the listing is for a channel service, we already know
     that there are no common channels, thus use PubChannel and not
     SeeChannel */
  if (repchan)
    chan = find_channel_member(acptr, repchan);
  else if ((!fields || (fields & (WHO_FIELD_CHA | WHO_FIELD_FLA)))
           && !IsChannelService(acptr))
  {
    for (chan = cli_user(acptr)->channel; chan; chan = chan->next_channel)
      if (PubChannel(chan->channel) &&
          (acptr == sptr || !IsZombie(chan)))
        break;
  }

  /* Place the fields one by one in the buffer and send it
     note that fields == NULL means "default query" */

  if (fields & WHO_FIELD_QTY)   /* Query type */
  {
    *(p1++) = ' ';
    if (BadPtr(qrt))
      *(p1++) = '0';
    else
      while ((*qrt) && (*(p1++) = *(qrt++)));
  }

  if (!fields || (fields & WHO_FIELD_CHA))
  {
    char *p2;
    *(p1++) = ' ';
    if ((p2 = (chan ? chan->channel->chname : NULL)))
      while ((*p2) && (*(p1++) = *(p2++)));
    else
      *(p1++) = '*';
  }

  if (!fields || (fields & WHO_FIELD_UID))
  {
    char *p2 = cli_user(acptr)->username;
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (fields & WHO_FIELD_NIP)
  {
    const char* p2 = HasHiddenHost(acptr) && !IsAnOper(sptr) ?
      feature_str(FEAT_HIDDEN_IP) :
      ircd_ntoa(&cli_ip(acptr));
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_HOS))
  {
    char *p2 = cli_user(acptr)->host;
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_SER))
  {
    const char *p2 = (feature_bool(FEAT_HIS_WHO_SERVERNAME) && !IsAnOper(sptr)) ?
                       feature_str(FEAT_HIS_SERVERNAME) :
                       cli_name(cli_user(acptr)->server);
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_NIC))
  {
    char *p2 = cli_name(acptr);
    *(p1++) = ' ';
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  if (!fields || (fields & WHO_FIELD_FLA))
  {
    *(p1++) = ' ';
    if (cli_user(acptr)->away)
      *(p1++) = 'G';
    else
      *(p1++) = 'H';
    if SeeOper(sptr,acptr)
      *(p1++) = '*';
    if (!chan) {
      /* No flags possible for the channel, so skip them all. */
    }
    else if (fields) {
      /* If you specified flags then we assume you know how to parse
       * multiple channel status flags, as this is currently the only
       * way to know if someone has @'s *and* is +'d.
       */
      if (IsChanOp(chan))
        *(p1++) = '@';
      if (HasVoice(chan))
        *(p1++) = '+';
      if (IsZombie(chan))
        *(p1++) = '!';
      if (IsDelayedJoin(chan))
        *(p1++) = '<';
    }
    else {
      if (IsChanOp(chan))
        *(p1++) = '@';
      else if (HasVoice(chan))
        *(p1++) = '+';
      else if (IsZombie(chan))
        *(p1++) = '!';
      else if (IsDelayedJoin(chan))
        *(p1++) = '<';
    }
    if (IsDeaf(acptr))
      *(p1++) = 'd';
    if (IsAnOper(sptr))
    {
      if (IsInvisible(acptr))
        *(p1++) = 'i';
      if (SendWallops(acptr))
        *(p1++) = 'w';
      if (SendDebug(acptr))
        *(p1++) = 'g';
    }
    if (HasHiddenHost(acptr))
      *(p1++) = 'x';
  }

  if (!fields || (fields & WHO_FIELD_DIS))
  {
    *p1++ = ' ';
    if (!fields)
      *p1++ = ':';              /* Place colon here for default reply */
    if (feature_bool(FEAT_HIS_WHO_HOPCOUNT) && !IsAnOper(sptr))
      *p1++ = (sptr == acptr) ? '0' : '3';
    else
      /* three digit hopcount maximum */
      p1 += ircd_snprintf(0, p1, 3, "%d", cli_hopcount(acptr));
  }

  if (fields & WHO_FIELD_IDL)
  {
    *p1++ = ' ';
    if (MyUser(acptr) &&
	(IsAnOper(sptr) || !feature_bool(FEAT_HIS_WHO_SERVERNAME) ||
	 acptr == sptr))
      p1 += ircd_snprintf(0, p1, 11, "%d",
                          CurrentTime - cli_user(acptr)->last);
    else
      *p1++ = '0';
  }

  if (fields & WHO_FIELD_ACC)
  {
    char *p2 = cli_user(acptr)->account;
    *(p1++) = ' ';
    if (*p2)
      while ((*p2) && (*(p1++) = *(p2++)));
    else
      *(p1++) = '0';
  }

  if (fields & WHO_FIELD_OPL)
  {
      if (!chan || !IsChanOp(chan))
      {
        strcpy(p1, " n/a");
        p1 += 4;
      }
      else
      {
        int vis_level = MAXOPLEVEL;
        if ((IsGlobalChannel(chan->channel->chname) ? IsOper(sptr) : IsAnOper(sptr))
            || is_chan_op(sptr, chan->channel))
          vis_level = OpLevel(chan);
        p1 += ircd_snprintf(0, p1, 5, " %d", vis_level);
      }
  }

  if (!fields || (fields & WHO_FIELD_REN))
  {
    char *p2 = cli_info(acptr);
    *p1++ = ' ';
    if (fields)
      *p1++ = ':';              /* Place colon here for special reply */
    while ((*p2) && (*(p1++) = *(p2++)));
  }

  /* The first char will always be an useless blank and we 
     need to terminate buf1 */
  *p1 = '\0';
  p1 = buf1;
  send_reply(sptr, fields ? RPL_WHOSPCRPL : RPL_WHOREPLY, ++p1);
}

/** Handle a WHO message.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is a nickname mask list
 * \li \a parv[2] is an additional selection flag string.  'i' selects
 * opers, 'd' shows join-delayed users as well, 'x' shows extended
 * information to opers with the WHOX privilege; %flags specifies
 * what fields to output; a ,querytype if the t flag is specified
 * so the final thing will be like o%tnchu,777.
 * \li \a parv[3] parv[3] is an _optional_ parameter that overrides
 * parv[1] This can be used as "/quote who foo % :The Black Hacker to
 * find me, parv[3] _can_ contain spaces!
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_who(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *mask;           /* The mask we are looking for              */
  char ch;                      /* Scratch char register                    */
  struct Channel *chptr;                /* Channel to show                          */
  struct Client *acptr;         /* Client to show                           */

  int bitsel;                   /* Mask of selectors to apply               */
  int matchsel;                 /* Which fields the match should apply on    */
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
        case 'd':
        case 'D':
          bitsel |= WHOSELECT_DELAY;
          continue;
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
          case 'o':
          case 'O':
            fields |= WHO_FIELD_OPL;
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
            if ((bitsel & WHOSELECT_OPER) && !SeeOper(sptr,acptr))
              continue;
            if ((acptr != sptr)
                && ((member->status & CHFL_ZOMBIE)
                    || ((member->status & CHFL_DELAYED)
                        && !(bitsel & WHOSELECT_DELAY))))
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
            ((!(bitsel & WHOSELECT_OPER)) || SeeOper(sptr,acptr)) &&
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
    struct irc_in_addr imask;
    int minlen, cset;
    unsigned char ibits;

    if (mask)
    {
      matchcomp(mymask, &minlen, &cset, mask);
      if (!ipmask_parse(mask, &imask, &ibits))
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
      if ((minlen > ACCOUNTLEN))
        matchsel &= ~WHO_FIELD_ACC;
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
 	  if ((bitsel & WHOSELECT_OPER) && !SeeOper(sptr,acptr))
	    continue;
          if ((mask)
              && ((!(matchsel & WHO_FIELD_NIC))
              || matchexec(cli_name(acptr), mymask, minlen))
              && ((!(matchsel & WHO_FIELD_UID))
              || matchexec(cli_user(acptr)->username, mymask, minlen))
              && ((!(matchsel & WHO_FIELD_SER))
              || (!(HasFlag(cli_user(acptr)->server, FLAG_MAP))))
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
              || !ipmask_check(&cli_ip(acptr), &imask, ibits))
              && ((!(matchsel & WHO_FIELD_ACC))
              || matchexec(cli_user(acptr)->account, mymask, minlen))
              )
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
	if ((bitsel & WHOSELECT_OPER) && !SeeOper(sptr,acptr))
	  continue;
        if (!(SEE_USER(sptr, acptr, bitsel)))
          continue;
        if ((mask)
            && ((!(matchsel & WHO_FIELD_NIC))
            || matchexec(cli_name(acptr), mymask, minlen))
            && ((!(matchsel & WHO_FIELD_UID))
            || matchexec(cli_user(acptr)->username, mymask, minlen))
            && ((!(matchsel & WHO_FIELD_SER))
                || (!(HasFlag(cli_user(acptr)->server, FLAG_MAP))))
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
            || !ipmask_check(&cli_ip(acptr), &imask, ibits))
            && ((!(matchsel & WHO_FIELD_ACC))
            || matchexec(cli_user(acptr)->account, mymask, minlen))
            )
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
