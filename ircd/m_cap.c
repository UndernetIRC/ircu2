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
 */
/** @file
 * @brief Capability negotiation commands
 * @version $Id$
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
#include "s_auth.h"
#include "s_user.h"
#include "s_bsd.h"

#include <stdlib.h>
#include <string.h>

typedef int (*bqcmp)(const void *, const void *);

static struct capabilities {
  enum CapabBits cap;
  char *capstr;
  unsigned int config;
  unsigned long flags;
  char *name;
  int namelen;
  char value[256];
} capab_list[] = {
#define _CAP(cap, config, flags, name)      \
	{ CAP_ ## cap, #cap, (config), (flags), (name), sizeof(name) - 1, "" }
  CAPLIST
#undef _CAP
};

#define CAPAB_LIST_LEN	(sizeof(capab_list) / sizeof(struct capabilities))

void cap_set_value(enum Capab cap, const char *value)
{
  if (cap >= _E_CAP_LAST_CAP || !value)
    return;
  
  /* Find the capability in capab_list by bit mask */
  enum CapabBits cap_mask = (1u << cap);
  int i;
  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (capab_list[i].cap == cap_mask) {
      ircd_strncpy(capab_list[i].value, value, sizeof(capab_list[i].value) - 1);
      capab_list[i].value[sizeof(capab_list[i].value) - 1] = '\0';
      return;
    }
  }
}

void cap_update_availability(enum Capab cap, int available)
{
  int was_available;
  int i;
  enum CapabBits cap_mask;
  
  if (cap >= _E_CAP_LAST_CAP)
    return;
    
  /* Find the capability in capab_list by bit mask */
  cap_mask = (1u << cap);
  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (capab_list[i].cap == cap_mask) {
      /* Check previous state by looking at UNAVAILABLE flag */
      was_available = !(capab_list[i].flags & CAPFL_UNAVAILABLE);
      
      /* If availability changed, update capability visibility */
      if (was_available && !available) {
        /* Capability became unavailable - set UNAVAILABLE flag and send CAP DEL */
        capab_list[i].flags |= CAPFL_UNAVAILABLE;
        cap_del(cap);
      } else if (!was_available && available) {
        /* Capability became available - clear UNAVAILABLE flag and send CAP NEW */
        capab_list[i].flags &= ~CAPFL_UNAVAILABLE;
        cap_new(cap);
      }
      return;
    }
  }
}

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

/** Send a CAP \a subcmd list of capability changes to \a sptr.
 * If more than one line is necessary, each line before the last has
 * an added "*" parameter before that line's capability list.
 * @param[in] sptr Client receiving capability list.
 * @param[in] set Capabilities to show as set.
 * @param[in] rem Capabalities to show as removed.
 * @param[in] subcmd Name of capability subcommand.
 */
static int
send_caplist(struct Client *sptr, capset_t set,
             capset_t rem, const char *subcmd)
{
  char capbuf[BUFSIZE] = "", pfx[16];
  struct MsgBuf *mb;
  int i, loc, len, flags, pfx_len;

  /* set up the buffer for the final LS message... */
  mb = msgq_make(sptr, "%:#C " MSG_CAP " %C %s :", &me, sptr, subcmd);

  for (i = 0, loc = 0; i < CAPAB_LIST_LEN; i++) {
    flags = capab_list[i].flags;

    /* If the client has no capabilities set, and this is the LIST subcmd, break. */
    if (!set && !strcmp(subcmd, "LIST"))
      break;

    /* Check if the capability is enabled in features() */
    if (capab_list[i].config != 0 && !feature_bool(capab_list[i].config))
      continue;

    /* Check if capability is hidden from IRCv3.2 clients */
    if (!set && HasFlag(sptr, FLAG_CAP302) && (flags & CAPFL_HIDDEN_302))
      continue;

    /* This is a little bit subtle, but just involves applying de
     * Morgan's laws to the obvious check: We must display the
     * capability if (and only if) it is set in \a rem or \a set, or
     * if both are null and the capability is hidden.
     */
    if (!(rem && CapHas(rem, capab_list[i].cap))
        && !(set && CapHas(set, capab_list[i].cap))
        && (rem || set || (flags & CAPFL_HIDDEN)))
      continue;

    /* Build the prefix (space separator). */
    pfx_len = 0;
    if (loc)
      pfx[pfx_len++] = ' ';
    if (rem && CapHas(rem, capab_list[i].cap))
        pfx[pfx_len++] = '-';
    pfx[pfx_len] = '\0';

    /* Get capability value for LS command */
    const char *cap_value = "";
    if (!strcmp(subcmd, "LS")) {
      if (capab_list[i].value[0] != '\0' && HasFlag(sptr, FLAG_CAP302)) {
        cap_value = capab_list[i].value;
      }
    }

    /* Calculate length including value */
    int value_len = (cap_value && cap_value[0] != '\0') ? strlen(cap_value) + 1 : 0; /* +1 for = */
    len = capab_list[i].namelen + pfx_len + value_len; /* how much we'd add... */
    if (msgq_bufleft(mb) < loc + len + 2) { /* would add too much; must flush */
      sendcmdto_one(&me, CMD_CAP, sptr, "%C %s * :%s", sptr, subcmd, capbuf);
      capbuf[(loc = 0)] = '\0'; /* re-terminate the buffer... */
    }

    if (cap_value && cap_value[0] != '\0') {
      loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s=%s",
			   pfx, capab_list[i].name, cap_value);
    } else {
      loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s",
			   pfx, capab_list[i].name);
    }
  }

  msgq_append(0, mb, "%s", capbuf); /* append capabilities to the final cmd */
  send_buffer(sptr, mb, 0); /* send them out... */
  msgq_clean(mb); /* and release the buffer */

  return 0; /* convenience return */
}

static int
cap_ls(struct Client *sptr, const char *caplist)
{
  if (IsUserPort(sptr)) /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));
  
  /* Check if client supports IRCv3.2 (LS version >= 302) */
  if (caplist) {
    int version = atoi(caplist);
    if (version >= 302) {
      SetFlag(sptr, FLAG_CAP302);
      CapSet(cli_active(sptr), CAP_CAPNOTIFY);
    }
  }
  
  return send_caplist(sptr, 0, 0, "LS"); /* send list of capabilities */
}

static int
cap_req(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  capset_t set = 0, rem = 0;
  capset_t cs = cli_capab(sptr); /* capability set */
  capset_t as = cli_active(sptr); /* active set */
  int neg;

  if (IsUserPort(sptr)) /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));

  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) /* look up capability... */
        || (cap->config != 0 && !feature_bool(cap->config)) /* is it deactivated in config? */
        || (!neg && (cap->flags & CAPFL_PROHIBIT)) /* is it prohibited? */
        || (neg && (cap->flags & CAPFL_STICKY)) /* is it sticky? */
        || (neg && HasFlag(sptr, FLAG_CAP302) && (cap->flags & CAPFL_STICKY_302))) { /* is it sticky for IRCv3.2? */
      sendcmdto_one(&me, CMD_CAP, sptr, "%C NAK :%s", sptr, caplist);
      return 0; /* can't complete requested op... */
    }

    if (neg) { /* set or clear the capability... */
      CapSet(rem, cap->cap);
      CapClr(set, cap->cap);
      CapClr(cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
	      CapClr(as, cap->cap);
    } else {
      CapClr(rem, cap->cap);
      CapSet(set, cap->cap);
      CapSet(cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
	      CapSet(as, cap->cap);
    }
  }

  /* Notify client of accepted changes and copy over results. */
  send_caplist(sptr, set, rem, "ACK");
  cli_capab(sptr) = cs;
  cli_active(sptr) = as;

  return 0;
}

static int
cap_end(struct Client *sptr, const char *caplist)
{
  if (!IsUserPort(sptr)) /* registration has completed... */
    return 0; /* so just ignore the message... */

  return auth_cap_done(cli_auth(sptr));
}

static int
cap_list(struct Client *sptr, const char *caplist)
{
  /* Send the list of the client's capabilities */
  return send_caplist(sptr, cli_capab(sptr), 0, "LIST");
}

static struct subcmd {
  char *cmd;
  int (*proc)(struct Client *sptr, const char *caplist);
} cmdlist[] = {
  { "ACK",   0         },
  { "END",   cap_end   },
  { "LIST",  cap_list  },
  { "LS",    cap_ls    },
  { "NAK",   0         },
  { "NEW",   0         },
  { "DEL",   0         },
  { "REQ",   cap_req   }
};

/** Send CAP NEW to all clients with cap-notify capability
 * @param[in] cap Capability enum value
 */
void cap_new(enum Capab cap)
{
  struct Client* acptr;
  int i;
  int cap_index = -1;
  unsigned long flags;
  const char* cap_name = NULL;
  const char* cap_value = "";
  
  /* Find the capability in the list */
  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (capab_list[i].cap == (1u << cap)) {
      cap_index = i;
      cap_name = capab_list[i].name;
      cap_value = capab_list[i].value;
      flags = capab_list[i].flags;
      break;
    }
  }
  
  if (cap_index == -1) {
    return;
  }
  
  /* Check if the capability should be advertised */
  if (capab_list[cap_index].config != 0 && !feature_bool(capab_list[cap_index].config))
    return;
  
  /* Iterate through all local clients */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!(acptr = LocalClientArray[i]))
      continue;
      
    /* Only send to registered users with cap-notify capability */
    if (!IsUser(acptr) || !MyConnect(acptr) || !CapHas(cli_active(acptr), CAP_CAPNOTIFY))
      continue;
      
    /* Send CAP NEW message */
    if (cap_value && *cap_value && HasFlag(acptr, FLAG_CAP302)) {
      sendcmdto_one(&me, CMD_CAP, acptr, "%C NEW %s=%s", acptr, cap_name, cap_value);
    } else {
      sendcmdto_one(&me, CMD_CAP, acptr, "%C NEW %s", acptr, cap_name);
    }
  }
}

/** Send CAP DEL to all clients with cap-notify capability
 * @param[in] cap Capability enum value
 */
void cap_del(enum Capab cap)
{
  struct Client* acptr;
  int i;
  int cap_index = -1;
  unsigned long flags;
  const char* cap_name = NULL;
  
  /* Find the capability in the list */
  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (capab_list[i].cap == (1u << cap)) {
      cap_index = i;
      cap_name = capab_list[i].name;
      flags = capab_list[i].flags;
      break;
    }
  }
  
  if (cap_index == -1) {
    return;
  }
  
  /* Iterate through all local clients */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!(acptr = LocalClientArray[i]))
      continue;
      
    /* Only send to registered users with cap-notify capability */
    if (!IsUser(acptr) || !MyConnect(acptr) || !CapHas(cli_active(acptr), CAP_CAPNOTIFY))
      continue;
      
    /* Send CAP DEL message */
    sendcmdto_one(&me, CMD_CAP, acptr, "%C DEL :%s", acptr, cap_name);

    /* Disable the capability for this client. */
    CapClr(cli_active(acptr), capab_list[cap_index].cap);
  }
}

static int
subcmd_search(const char *cmd, const struct subcmd *elem)
{
  return ircd_strcmp(cmd, elem->cmd);
}

/** Handle a capability request or response from a client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int
m_cap(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *subcmd, *caplist = 0;
  struct subcmd *cmd;

  if (parc < 2) /* a subcommand is required */
    return 0;
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
