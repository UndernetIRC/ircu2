/*
 * IRC - Internet Relay Chat, ircd/m_cap.c
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
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

#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_user.h"

#include <stdlib.h>
#include <string.h>

typedef int (*bqcmp)(const void *, const void *);

static struct capabilities {
  enum Capab cap;
  char *capstr;
  unsigned long flags;
  char *name;
  int namelen;
} capab_list[] = {
#define _CAP(cap, flags, name)						      \
	{ CAP_ ## cap, #cap, (flags), (name), sizeof(name) - 1 }
  CAPLIST
#undef _CAP
};

#define CAPAB_LIST_LEN	(sizeof(capab_list) / sizeof(struct capabilities))

static struct CapSet clean_set; /* guaranteed to be all zeros (right?) */

static int
capab_sort(const struct capabilities *cap1, const struct capabilities *cap2)
{
  return ircd_strcmp(cap1->name, cap2->name);
}

static int
capab_search(const char *key, const struct capabilities *cap)
{
  const char *rb = cap->name;
  while (ToLower(*key) == ToLower(*rb)) /* walk equivalent part of strings */
    if (!*key++) /* hit the end, all right... */
      return 0;
    else /* OK, let's move on... */
      rb++;

  /* If the character they differ on happens to be a space, and it happens
   * to be the same length as the capability name, then we've found a
   * match; otherwise, return the difference of the two.
   */
  return (IsSpace(*key) && !*rb) ? 0 : (ToLower(*key) - ToLower(*rb));
}

static struct capabilities *
find_cap(const char **caplist_p, int *neg_p)
{
  static int inited = 0;
  const char *caplist = *caplist_p;
  struct capabilities *cap = 0;

  *neg_p = 0; /* clear negative flag... */

  if (!inited) { /* First, let's sort the array... */
    qsort(capab_list, CAPAB_LIST_LEN, sizeof(struct capabilities),
	  (bqcmp)capab_sort);
    inited++; /* remember that we've done this step... */
  }

  /* Next, find first non-whitespace character... */
  while (*caplist && IsSpace(*caplist))
    caplist++;

  /* We are now at the beginning of an element of the list; is it negative? */
  if (*caplist == '-') {
    caplist++; /* yes; step past the flag... */
    *neg_p = 1; /* remember that it is negative... */
  }

  /* OK, now see if we can look up the capability... */
  if (*caplist) {
    if (!(cap = (struct capabilities *)bsearch(caplist, capab_list,
					       CAPAB_LIST_LEN,
					       sizeof(struct capabilities),
					       (bqcmp)capab_search))) {
      /* Couldn't find the capability; advance to first whitespace character */
      while (*caplist && !IsSpace(*caplist))
	caplist++;
    } else
      caplist += cap->namelen; /* advance to end of capability name */
  }

  assert(caplist != *caplist_p || !*caplist); /* we *must* advance */

  /* move ahead in capability list string--or zero pointer if we hit end */
  *caplist_p = *caplist ? caplist : 0;

  return cap; /* and return the capability (if any) */
}

static int
send_caplist(struct Client *sptr, const struct CapSet *cs)
{
  char capbuf[BUFSIZE] = "";
  struct MsgBuf *mb;
  int i, loc, len;

  /* set up the buffer for the LSL message... */
  mb = msgq_make(sptr, "%:#C " MSG_CAP " LSL :", &me);

  for (i = 0, loc = 0; i < CAPAB_LIST_LEN; i++) {
    if (cs ? !CapHas(cs, capab_list[i].cap) :
	(capab_list[i].flags & CAPFL_HIDDEN))
      continue; /* not including this capability in the list */
      
    len = capab_list[i].namelen + (loc != 0); /* how much we'd add... */

    if (msgq_bufleft(mb) < loc + len) { /* would add too much; must flush */
      sendcmdto_one(&me, CMD_CAP, sptr, "LS :%s", capbuf);
      capbuf[(loc = 0)] = '\0'; /* re-terminate the buffer... */
    }

    loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s",
			 loc ? " " : "", capab_list[i].name);
  }

  msgq_append(0, mb, "%s", capbuf); /* append capabilities to the LSL cmd */
  send_buffer(sptr, mb, 0); /* send them out... */
  msgq_clean(mb); /* and release the buffer */

  return 0; /* convenience return */
}

static int
cap_empty(struct Client *sptr, const char *caplist)
{
  if (IsUnknown(sptr)) /* registration hasn't completed; suspend it... */
    cli_unreg(sptr) |= CLIREG_CAP;

  return send_caplist(sptr, 0); /* send list of capabilities */
}

static int
cap_req(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  struct CapSet cs = *cli_capab(sptr); /* capability set */
  struct CapSet as = *cli_active(sptr); /* active set */
  int neg;

  if (IsUnknown(sptr)) /* registration hasn't completed; suspend it... */
    cli_unreg(sptr) |= CLIREG_CAP;

  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) || /* look up capability... */
	(!neg && (cap->flags & CAPFL_PROHIBIT))) { /* is it prohibited? */
      sendcmdto_one(&me, CMD_CAP, sptr, "NAK :%s", caplist);
      return 0; /* can't complete requested op... */
    }

    if (neg) { /* set or clear the capability... */
      CapClr(&cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
	CapClr(&as, cap->cap);
    } else {
      CapSet(&cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
	CapSet(&as, cap->cap);
    }
  }

  sendcmdto_one(&me, CMD_CAP, sptr, "ACK :%s", caplist);

  *cli_capab(sptr) = cs; /* copy the completed results */
  *cli_active(sptr) = as;

  return 0;
}

static int
cap_ack(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  int neg;

  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) || /* look up capability... */
	(neg ? HasCap(sptr, cap->cap) : !HasCap(sptr, cap->cap))) /* uh... */
      continue;

    if (neg) /* set or clear the active capability... */
      CapClr(cli_active(sptr), cap->cap);
    else
      CapSet(cli_active(sptr), cap->cap);
  }

  return 0;
}

static int
cap_clear(struct Client *sptr, const char *caplist)
{
  sendcmdto_one(&me, CMD_CAP, sptr, "CLEAR"); /* Reply... */

  *cli_capab(sptr) = clean_set; /* then clear! */

  return 0;
}

static int
cap_end(struct Client *sptr, const char *caplist)
{
  if (!IsUnknown(sptr)) /* registration has completed... */
    return 0; /* so just ignore the message... */

  cli_unreg(sptr) &= ~CLIREG_CAP; /* capability negotiation is now done... */

  if (!cli_unreg(sptr)) /* if client is now done... */
    return register_user(sptr, sptr, cli_name(sptr), cli_user(sptr)->username);

  return 0; /* Can't do registration yet... */
}

static int
cap_list(struct Client *sptr, const char *caplist)
{
  /* Send the list of the client's capabilities */
  return send_caplist(sptr, cli_capab(sptr));
}

static struct subcmd {
  char *cmd;
  int (*proc)(struct Client *sptr, const char *caplist);
} cmdlist[] = {
  { "",      cap_empty },
  { "ACK",   cap_ack   },
  { "CLEAR", cap_clear },
  { "END",   cap_end   },
  { "LIST",  cap_list  },
  { "LS",    0         },
  { "LSL",   0         },
  { "NAK",   0         },
  { "REQ",   cap_req   }
};

static int
subcmd_search(const char *cmd, const struct subcmd *elem)
{
  return ircd_strcmp(cmd, elem->cmd);
}

/*
 * m_cap - user message handler
 *
 * parv[0] = Send prefix
 *
 * From user:
 *
 * parv[1] = [<subcommand>]
 * parv[2] = [<capab list>]
 *
 */
int
m_cap(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *subcmd = "", *caplist = 0;
  struct subcmd *cmd;

  if (parc > 1 && parv[1]) /* a subcommand was provided */
    subcmd = parv[1];
  if (parc > 2) /* a capability list was provided */
    caplist = parv[2];

  /* find the subcommand handler */
  if (!(cmd = (struct subcmd *)bsearch(subcmd, cmdlist,
				       sizeof(cmdlist) / sizeof(struct subcmd),
				       sizeof(struct subcmd),
				       (bqcmp)subcmd_search)))
    return send_reply(sptr, ERR_UNKNOWNCAPCMD, subcmd);

  /* then execute it... */
  return cmd->proc ? (cmd->proc)(sptr, caplist) : 0;
}
