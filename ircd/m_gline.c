/*
 * IRC - Internet Relay Chat, ircd/m_gline.c
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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * ms_gline - server message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = Target: server numeric
 * parv[2] = (+|-)<G-line mask>
 * parv[3] = G-line lifetime
 *
 * From Uworld:
 *
 * parv[4] = Comment
 *
 * From somewhere else:
 *
 * parv[4] = Last modification time
 * parv[5] = Comment
 *
 */
int
ms_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Gline *agline;
  unsigned int flags = 0;
  time_t expire_off, lastmod = 0;
  char *mask = parv[2], *target = parv[1], *reason;

  if (parc == 4) {
    if (!find_conf_byhost(cptr->confs, sptr->name, CONF_UWORLD))
      return need_more_params(sptr, "GLINE");

    reason = parv[4];
    flags |= GLINE_FORCE;
  } else if (parc >= 5) {
    lastmod = atoi(parv[4]);
    reason = parv[5];
  } else
    return need_more_params(sptr, "GLINE");

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!(acptr = FindNServer(target)))
      return 0; /* no such server */

    if (!IsMe(acptr)) { /* manually propagate */
      if (IsServer(sptr)) {
	if (!lastmod)
	  sendto_one(acptr, "%s " TOK_GLINE " %s %s %s :%s", NumServ(sptr),
		     target, mask, parv[3], reason);
	else
	  sendto_one(acptr, "%s " TOK_GLINE " %s %s %s %s :%s", NumServ(sptr),
		     target, mask, parv[3], parv[4], reason);
      } else
	sendto_one(acptr, "%s%s " TOK_GLINE " %s %s %s %s :%s", NumNick(sptr),
		   target, mask, parv[3], parv[4], reason);

      return 0;
    }

    flags |= GLINE_LOCAL;
  }

  if (*server == '-')
    server++;
  else if (*server == '+') {
    flags |= GLINE_ACTIVE;
    server++;
  } else
    flags |= GLINE_ACTIVE;

  expire_off = atoi(parv[3]);

  agline = gline_find(mask, GLINE_ANY);

  if (agline) {
    if (GlineIsLocal(agline) && !(flags & GLINE_LOCAL)) /* global over local */
      gline_free(agline);
    else if (!lastmod || GlineLastMod(agline) < lastmod) { /* new mod */
      if (flags & GLINE_ACTIVE)
	return gline_activate(cptr, sptr, agline, lastmod);
      else
	return gline_deactivate(cptr, sptr, agline, lastmod);
    } else if (GlineLastMod(agline) == lastmod)
      return 0;
    else
      return gline_resend(cptr, agline); /* other server desynched WRT gline */
  }

  return gline_add(cptr, sptr, mask, reason, expire_off, lastmod, flags);
}

/*
 * mo_gline - oper message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [[+|-]<G-line mask>]
 *
 * Old style:
 *
 * parv[2] = [Expiration offset]
 * parv[3] = [Comment]
 *
 * New style:
 *
 * parv[2] = [target]
 * parv[3] = [Expiration offset]
 * parv[4] = [Comment]
 *
 */
int
mo_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Gline *agline;
  unsigned int flags = 0;
  time_t expire_off;
  char *mask = parv[1], *target = 0, *reason;

  if (parc < 2)
    return gline_list(sptr, 0);

  if (*mask == '+') {
    flags |= GLINE_ACTIVE;
    mask++;
  } else if (*mask == '-')
    mask++;
  else
    return gline_list(sptr, mask);

#ifndef LOCOP_LGLINE
  if (!IsOper(sptr)) {
    send_error_to_client(sptr, ERR_NOPRIVILEGES);
    return 0;
  }
#endif

  if (parc == 3) {
    expire_off = atoi(parv[2]);
    reason = parv[3];
    flags |= GLINE_LOCAL;
  } else if (parc >= 4) {
    target = parv[2];
    expire_off = atoi(parv[3]);
    reason = parv[4];
  } else
    return need_more_params(sptr, "GLINE");

  if (target) {
    if (!(target[0] == '*' && target[1] == '\0')) {
      if (!(acptr = find_match_server(target))) {
	send_error_to_client(sptr, ERR_NOSUCHSERVER, target);
	return 0;
      }

      if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
	if (!IsOper(sptr)) {
	  send_error_to_client(sptr, ERR_NOPRIVILEGES);
	  return 0;
	}

	sendto_one(acptr, "%s%s " TOK_GLINE " %s %c%s %s " TIME_T_FMT " :%s",
		   NumNick(sptr), NumServ(acptr),
		   flags & GLINE_ACTIVE ? '?' : '-', mask, parv[3], TStime(),
		   reason);
	return 0;
      }

      flags |= GLINE_LOCAL;
    } else if (!IsOper(sptr)) {
      send_error_to_client(sptr, ERR_NOPRIVILEGES);
      return 0;
    }
  }

  agline = gline_find(mask, GLINE_ANY);

  if (agline) {
    if (GlineIsLocal(agline) && !(flags & GLINE_LOCAL)) /* global over local */
      gline_free(agline);
    else {
      if (flags & GLINE_ACTIVE)
	return gline_activate(cptr, sptr, agline, TStime());
      else
	return gline_deactivate(cptr, sptr, agline, TStime());
    }
  }

  return gline_add(cptr, sptr, mask, reason, expire_off, TStime(), flags);
}

/*
 * m_gline - user message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [<server name>]
 *
 */
int
m_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return gline_list(sptr, 0);

  return gline_list(sptr, parv[1]);
}

#if 0
/*
 * ms_gline - server message handler
 *
 * parv[0] = Send prefix
 *
 * From server:
 *
 * parv[1] = Target: server numeric
 * parv[2] = [+|-]<G-line mask>
 * parv[3] = Expiration offset
 * parv[4] = Comment
 *
 * From client:
 *
 * parv[1] = [+|-]<G-line mask>
 * parv[2] = Expiration offset
 * parv[3] = Comment
 *
 */
int ms_gline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr = 0;  /* Init. to avoid compiler warning. */
  struct Gline*  gline;
  struct Gline*  prev;
  char*          user;
  char*          host;
  int            active;
  int            ip_mask;
  int            gtype = 0;
  time_t         expire = 0;

  /*
   * Remove expired G-lines
   */
  gline_remove_expired(TStime());
#ifdef BADCHAN
  /*
   * Remove expired bad channels
   */
  bad_channel_remove_expired(TStime());
#endif

  if (IsServer(cptr)) {
    if (find_conf_byhost(cptr->confs, sptr->name, CONF_UWORLD)) {
      if (parc < 3 || (*parv[2] != '-' && (parc < 5 || *parv[4] == '\0')))
        return need_more_params(sptr, "GLINE");

      if (*parv[2] == '-') /* add mode or delete mode? */
        active = 0;
      else
        active = 1;

      if (*parv[2] == '+' || *parv[2] == '-')
        parv[2]++; /* step past mode indicator */

      /*
       * forward the message appropriately
       */
      if (0 == ircd_strcmp(parv[1], "*")) {
        /*
         * global!
         */
        sendto_serv_butone(cptr,
                     active ? "%s " TOK_GLINE " %s +%s %s :%s" : "%s " TOK_GLINE " %s -%s",
                     NumServ(sptr), parv[1], parv[2], parv[3], parv[4]);
      }
      else if ((
#if 1
          /*
           * REMOVE THIS after all servers upgraded to 2.10.01 and
           * Uworld uses a numeric too
           */
          (strlen(parv[1]) != 1 && !(acptr = FindClient(parv[1])))) ||
          (strlen(parv[1]) == 1 &&
#endif
          !(acptr = FindNServer(parv[1]))))
        return 0;               /* no such server/user exists; forget it */
      else
#if 1
/*
 * REMOVE THIS after all servers upgraded to 2.10.01 and
 * Uworld uses a numeric too
 */
      if (IsServer(acptr) || !MyConnect(acptr))
#endif
      {
        /* single destination */
        sendto_one(acptr,
               active ? "%s " TOK_GLINE " %s +%s %s :%s" : "%s " TOK_GLINE " %s -%s",
               NumServ(sptr), parv[1], parv[2], parv[3], parv[4]);
        return 0;               /* only the intended  destination
                                   should add this gline */
      }

      if (!(host = strchr(parv[2], '@'))) {
        /*
         * convert user@host no @'s; assume username is '*'
         */
        user = "*";     
        host = parv[2];
      }
      else {
        user = parv[2];
        *(host++) = '\0';       /* break up string at the '@' */
      }
      ip_mask = check_if_ipmask(host);  /* Store this boolean */
#ifdef BADCHAN
      if ('#' == *host || '&' == *host || '+' == *host)
         gtype = 1;                /* BAD CHANNEL GLINE */
#endif
      for (gline = (gtype) ? BadChanGlineList : GlobalGlineList, prev = 0; gline;
           gline = gline->next)
      {
        if (0 == ircd_strcmp(gline->name, user) &&
            0 == ircd_strcmp(gline->host, host))
          break;
        prev = gline;
      }

      if (!active && gline)
      {
        /*
         * removing the gline, notify opers
         */
        sendto_op_mask(SNO_GLINE, "%s removing %s for %s@%s", parv[0],
            gtype ? "BADCHAN" : "GLINE", gline->name, gline->host);

#ifdef GPATH
       write_log(GPATH, "# " TIME_T_FMT " %s removing %s for %s@%s\n",
           TStime(), parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, 
            gline->host);
#endif /* GPATH */

        free_gline(gline, prev);        /* remove the gline */
      }
      else if (active)
      {                         /* must be adding a gline */
        expire = atoi(parv[3]) + TStime();      /* expire time? */
        if (gline && gline->expire < expire)
        {                       /* new expire time? */
          /* yes, notify the opers */
          sendto_op_mask(SNO_GLINE,
             "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
             parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host, 
             expire);
#ifdef GPATH
          write_log(GPATH, "# " TIME_T_FMT " %s resetting expiration time "
              "on %s for %s@%s to " TIME_T_FMT "\n",
              TStime(), parv[0], gtype ? "BADCHAN" : "GLINE",
              gline->name, gline->host, expire);
#endif /* GPATH */

          gline->expire = expire;       /* reset the expire time */
        }
        else if (!gline)
        {                       /* create gline */
          for (gline = (gtype) ? BadChanGlineList : GlobalGlineList; gline; gline = gline->next)
            if (!mmatch(gline->name, user) &&
                (ip_mask ? GlineIsIpMask(gline) : !GlineIsIpMask(gline)) &&
                !mmatch(gline->host, host))
              return 0;         /* found an existing G-line that matches */

          /* add the line: */
          add_gline(sptr, ip_mask, host, parv[4], user, expire, 0);
        }
      }
    }
  }
  else if (parc < 2 || *parv[1] == '\0')
  {
    /* Not enough args and a user; list glines */
    for (gline = GlobalGlineList; gline; gline = gline->next)
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0],
          gline->name, gline->host, gline->expire, gline->reason,
          GlineIsActive(gline) ? (GlineIsLocal(gline) ? " (local)" : "") :
          " (Inactive)");
    sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
  }
  else
  {
    int priv;

#ifdef LOCOP_LGLINE
    priv = IsAnOper(cptr);
#else
    priv = IsOper(cptr);
#endif

    if (priv)
    {                           /* non-oper not permitted to change things */
      if (*parv[1] == '-')
      {                         /* oper wants to deactivate the gline */
        active = 0;
        parv[1]++;
      }
      else if (*parv[1] == '+')
      {                         /* oper wants to activate inactive gline */
        active = 1;
        parv[1]++;
      }
      else
        active = -1;

      if (parc > 2)
        expire = atoi(parv[2]) + TStime();      /* oper wants to reset
                                                   expire TS */
    }
    else
      active = -1;

    if (!(host = strchr(parv[1], '@')))
    {
      user = "*";               /* no @'s; assume username is '*' */
      host = parv[1];
    }
    else
    {
      user = parv[1];
      *(host++) = '\0';         /* break up string at the '@' */
    }
    ip_mask = check_if_ipmask(host);    /* Store this boolean */
#ifdef BADCHAN
    if ('#' == *host || '&' == *host || '+' == *host)
#ifndef LOCAL_BADCHAN
     return 0;
#else
     gtype = 1;  /* BAD CHANNEL */
#endif
#endif

    for (gline = (gtype) ? BadChanGlineList : GlobalGlineList, prev = 0; gline;
         gline = gline->next)
    {
      if (!mmatch(gline->name, user) &&
          (ip_mask ? GlineIsIpMask(gline) : !GlineIsIpMask(gline)) &&
          !mmatch(gline->host, host))
        break;
      prev = gline;
    }

    if (!gline)
    {
#ifdef OPER_LGLINE
      if (priv && active && expire > CurrentTime)
      {
        /* Add local G-line */
        if (parc < 4 || !strchr(parv[3], ' '))
          return need_more_params(sptr, "GLINE");

        add_gline(sptr, ip_mask, host, parv[3], user, expire, 1);
      }
      else
#endif
        sendto_one(cptr, err_str(ERR_NOSUCHGLINE), me.name, parv[0], user,
            host);

      return 0;
    }

    if (expire <= gline->expire)
      expire = 0;

    if ((active == -1 ||
        (active ? GlineIsActive(gline) : !GlineIsActive(gline))) &&
        expire == 0)
    {
      /* oper wants a list of one gline only */
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0], gline->name,
          gline->host, gline->expire, gline->reason,
          GlineIsActive(gline) ? "" : " (Inactive)");
      sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
      return 0;
    }

    if (active != -1 &&
        (active ? !GlineIsActive(gline) : GlineIsActive(gline)))
    {
      if (active)               /* reset activation on gline */
        SetActive(gline);
#ifdef OPER_LGLINE
      else if (GlineIsLocal(gline))
      {
        /* Remove local G-line */
        sendto_op_mask(SNO_GLINE, "%s removed local %s for %s@%s",
            parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host);
#ifdef GPATH
        write_log(GPATH, "# " TIME_T_FMT
            " %s!%s@%s removed local %s for %s@%s\n",
            TStime(), parv[0], cptr->user->username, cptr->user->host,
            gtype ? "BADCHAN" : "GLINE",
            gline->name, gline->host);
#endif /* GPATH */
        free_gline(gline, prev);        /* remove the gline */
        return 0;
      }
#endif
      else
        ClearActive(gline);
    }
    else
      active = -1;              /* for later sendto_ops and logging functions */

    if (expire)
      gline->expire = expire;   /* reset expiration time */

    /* inform the operators what's up */
    if (active != -1)
    {                           /* changing the activation */
       sendto_op_mask(SNO_GLINE, !expire ? "%s %sactivating %s for %s@%s" :
          "%s %sactivating %s for %s@%s and "
          "resetting expiration time to " TIME_T_FMT,
          parv[0], active ? "re" : "de", gtype ? "BADCHAN" : "GLINE",
          gline->name, gline->host, gline->expire);
#ifdef GPATH
      write_log(GPATH, !expire ? "# " TIME_T_FMT " %s!%s@%s %sactivating "
          "%s for %s@%s\n" : "# " TIME_T_FMT " %s!%s@%s %sactivating %s "
          "for %s@%s and resetting expiration time to " TIME_T_FMT "\n",
          TStime(), parv[0], cptr->user->username, cptr->user->host,
          active ? "re" : "de", gtype ? "BADCHAN" : "GLINE", gline->name, 
          gline->host, gline->expire);
#endif /* GPATH */

    }
    else if (expire)
    {                           /* changing only the expiration */
      sendto_op_mask(SNO_GLINE,
          "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
          parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host, 
          gline->expire);
#ifdef GPATH
      write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s resetting expiration "
          "time on %s for %s@%s to " TIME_T_FMT "\n", TStime(), parv[0],
          cptr->user->username, cptr->user->host, gtype ? "BADCHAN" : "GLINE",
          gline->name, gline->host, gline->expire);
#endif /* GPATH */
    }
  }
  return 0;
}

/*
 * mo_gline - oper message handler
 *
 * parv[0] = Send prefix
 *
 * From server:
 *
 * parv[1] = Target: server numeric
 * parv[2] = [+|-]<G-line mask>
 * parv[3] = Expiration offset
 * parv[4] = Comment
 *
 * From client:
 *
 * parv[1] = [+|-]<G-line mask>
 * parv[2] = Expiration offset
 * parv[3] = Comment
 *
 */
int mo_gline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr = 0;  /* Init. to avoid compiler warning. */
  struct Gline*  gline;
  struct Gline*  prev;
  char*          user;
  char*          host;
  int            active;
  int            ip_mask;
  int            gtype = 0;
  time_t         expire = 0;

  /*
   * Remove expired G-lines
   */
  gline_remove_expired(TStime());
#ifdef BADCHAN
  /*
   * Remove expired bad channels
   */
  bad_channel_remove_expired(TStime());
#endif

  if (IsServer(cptr)) {
    if (find_conf_byhost(cptr->confs, sptr->name, CONF_UWORLD)) {
      if (parc < 3 || (*parv[2] != '-' && (parc < 5 || *parv[4] == '\0')))
        return need_more_params(sptr, "GLINE");

      if (*parv[2] == '-') /* add mode or delete mode? */
        active = 0;
      else
        active = 1;

      if (*parv[2] == '+' || *parv[2] == '-')
        parv[2]++; /* step past mode indicator */

      /*
       * forward the message appropriately
       */
      if (0 == ircd_strcmp(parv[1], "*")) {
        /*
         * global!
         */
        sendto_serv_butone(cptr,
                     active ? "%s " TOK_GLINE " %s +%s %s :%s" : "%s " TOK_GLINE " %s -%s",
                     NumServ(sptr), parv[1], parv[2], parv[3], parv[4]);
      }
      else if ((
#if 1
          /*
           * REMOVE THIS after all servers upgraded to 2.10.01 and
           * Uworld uses a numeric too
           */
          (strlen(parv[1]) != 1 && !(acptr = FindClient(parv[1])))) ||
          (strlen(parv[1]) == 1 &&
#endif
          !(acptr = FindNServer(parv[1]))))
        return 0;               /* no such server/user exists; forget it */
      else
#if 1
/*
 * REMOVE THIS after all servers upgraded to 2.10.01 and
 * Uworld uses a numeric too
 */
      if (IsServer(acptr) || !MyConnect(acptr))
#endif
      {
        /* single destination */
        sendto_one(acptr,
               active ? "%s " TOK_GLINE " %s +%s %s :%s" : "%s " TOK_GLINE " %s -%s",
               NumServ(sptr), parv[1], parv[2], parv[3], parv[4]);
        return 0;               /* only the intended  destination
                                   should add this gline */
      }

      if (!(host = strchr(parv[2], '@'))) {
        /*
         * convert user@host no @'s; assume username is '*'
         */
        user = "*";     
        host = parv[2];
      }
      else {
        user = parv[2];
        *(host++) = '\0';       /* break up string at the '@' */
      }
      ip_mask = check_if_ipmask(host);  /* Store this boolean */
#ifdef BADCHAN
      if ('#' == *host || '&' == *host || '+' == *host)
         gtype = 1;                /* BAD CHANNEL GLINE */
#endif
      for (gline = (gtype) ? BadChanGlineList : GlobalGlineList, prev = 0; gline;
           gline = gline->next)
      {
        if (0 == ircd_strcmp(gline->name, user) &&
            0 == ircd_strcmp(gline->host, host))
          break;
        prev = gline;
      }

      if (!active && gline)
      {
        /*
         * removing the gline, notify opers
         */
        sendto_op_mask(SNO_GLINE, "%s removing %s for %s@%s", parv[0],
            gtype ? "BADCHAN" : "GLINE", gline->name, gline->host);

#ifdef GPATH
       write_log(GPATH, "# " TIME_T_FMT " %s removing %s for %s@%s\n",
           TStime(), parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, 
            gline->host);
#endif /* GPATH */

        free_gline(gline, prev);        /* remove the gline */
      }
      else if (active)
      {                         /* must be adding a gline */
        expire = atoi(parv[3]) + TStime();      /* expire time? */
        if (gline && gline->expire < expire)
        {                       /* new expire time? */
          /* yes, notify the opers */
          sendto_op_mask(SNO_GLINE,
             "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
             parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host, 
             expire);
#ifdef GPATH
          write_log(GPATH, "# " TIME_T_FMT " %s resetting expiration time "
              "on %s for %s@%s to " TIME_T_FMT "\n",
              TStime(), parv[0], gtype ? "BADCHAN" : "GLINE",
              gline->name, gline->host, expire);
#endif /* GPATH */

          gline->expire = expire;       /* reset the expire time */
        }
        else if (!gline)
        {                       /* create gline */
          for (gline = (gtype) ? BadChanGlineList : GlobalGlineList; gline; gline = gline->next)
            if (!mmatch(gline->name, user) &&
                (ip_mask ? GlineIsIpMask(gline) : !GlineIsIpMask(gline)) &&
                !mmatch(gline->host, host))
              return 0;         /* found an existing G-line that matches */

          /* add the line: */
          add_gline(sptr, ip_mask, host, parv[4], user, expire, 0);
        }
      }
    }
  }
  else if (parc < 2 || *parv[1] == '\0')
  {
    /* Not enough args and a user; list glines */
    for (gline = GlobalGlineList; gline; gline = gline->next)
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0],
          gline->name, gline->host, gline->expire, gline->reason,
          GlineIsActive(gline) ? (GlineIsLocal(gline) ? " (local)" : "") :
          " (Inactive)");
    sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
  }
  else
  {
    int priv;

#ifdef LOCOP_LGLINE
    priv = IsAnOper(cptr);
#else
    priv = IsOper(cptr);
#endif

    if (priv)
    {                           /* non-oper not permitted to change things */
      if (*parv[1] == '-')
      {                         /* oper wants to deactivate the gline */
        active = 0;
        parv[1]++;
      }
      else if (*parv[1] == '+')
      {                         /* oper wants to activate inactive gline */
        active = 1;
        parv[1]++;
      }
      else
        active = -1;

      if (parc > 2)
        expire = atoi(parv[2]) + TStime();      /* oper wants to reset
                                                   expire TS */
    }
    else
      active = -1;

    if (!(host = strchr(parv[1], '@')))
    {
      user = "*";               /* no @'s; assume username is '*' */
      host = parv[1];
    }
    else
    {
      user = parv[1];
      *(host++) = '\0';         /* break up string at the '@' */
    }
    ip_mask = check_if_ipmask(host);    /* Store this boolean */
#ifdef BADCHAN
    if ('#' == *host || '&' == *host || '+' == *host)
#ifndef LOCAL_BADCHAN
     return 0;
#else
     gtype = 1;  /* BAD CHANNEL */
#endif
#endif

    for (gline = (gtype) ? BadChanGlineList : GlobalGlineList, prev = 0; gline;
         gline = gline->next)
    {
      if (!mmatch(gline->name, user) &&
          (ip_mask ? GlineIsIpMask(gline) : !GlineIsIpMask(gline)) &&
          !mmatch(gline->host, host))
        break;
      prev = gline;
    }

    if (!gline)
    {
#ifdef OPER_LGLINE
      if (priv && active && expire > CurrentTime)
      {
        /* Add local G-line */
        if (parc < 4 || !strchr(parv[3], ' '))
          return need_more_params(sptr, "GLINE");

        add_gline(sptr, ip_mask, host, parv[3], user, expire, 1);
      }
      else
#endif
        sendto_one(cptr, err_str(ERR_NOSUCHGLINE), me.name, parv[0], user,
            host);

      return 0;
    }

    if (expire <= gline->expire)
      expire = 0;

    if ((active == -1 ||
        (active ? GlineIsActive(gline) : !GlineIsActive(gline))) &&
        expire == 0)
    {
      /* oper wants a list of one gline only */
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0], gline->name,
          gline->host, gline->expire, gline->reason,
          GlineIsActive(gline) ? "" : " (Inactive)");
      sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
      return 0;
    }

    if (active != -1 &&
        (active ? !GlineIsActive(gline) : GlineIsActive(gline)))
    {
      if (active)               /* reset activation on gline */
        SetActive(gline);
#ifdef OPER_LGLINE
      else if (GlineIsLocal(gline))
      {
        /* Remove local G-line */
        sendto_op_mask(SNO_GLINE, "%s removed local %s for %s@%s",
            parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host);
#ifdef GPATH
        write_log(GPATH, "# " TIME_T_FMT
            " %s!%s@%s removed local %s for %s@%s\n",
            TStime(), parv[0], cptr->user->username, cptr->user->host,
            gtype ? "BADCHAN" : "GLINE",
            gline->name, gline->host);
#endif /* GPATH */
        free_gline(gline, prev);        /* remove the gline */
        return 0;
      }
#endif
      else
        ClearActive(gline);
    }
    else
      active = -1;              /* for later sendto_ops and logging functions */

    if (expire)
      gline->expire = expire;   /* reset expiration time */

    /* inform the operators what's up */
    if (active != -1)
    {                           /* changing the activation */
       sendto_op_mask(SNO_GLINE, !expire ? "%s %sactivating %s for %s@%s" :
          "%s %sactivating %s for %s@%s and "
          "resetting expiration time to " TIME_T_FMT,
          parv[0], active ? "re" : "de", gtype ? "BADCHAN" : "GLINE",
          gline->name, gline->host, gline->expire);
#ifdef GPATH
      write_log(GPATH, !expire ? "# " TIME_T_FMT " %s!%s@%s %sactivating "
          "%s for %s@%s\n" : "# " TIME_T_FMT " %s!%s@%s %sactivating %s "
          "for %s@%s and resetting expiration time to " TIME_T_FMT "\n",
          TStime(), parv[0], cptr->user->username, cptr->user->host,
          active ? "re" : "de", gtype ? "BADCHAN" : "GLINE", gline->name, 
          gline->host, gline->expire);
#endif /* GPATH */

    }
    else if (expire)
    {                           /* changing only the expiration */
      sendto_op_mask(SNO_GLINE,
          "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
          parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host, 
          gline->expire);
#ifdef GPATH
      write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s resetting expiration "
          "time on %s for %s@%s to " TIME_T_FMT "\n", TStime(), parv[0],
          cptr->user->username, cptr->user->host, gtype ? "BADCHAN" : "GLINE",
          gline->name, gline->host, gline->expire);
#endif /* GPATH */
    }
  }
  return 0;
}


#if 0
/*
 * m_gline
 *
 * parv[0] = Send prefix
 *
 * From server:
 *
 * parv[1] = Target: server numeric
 * parv[2] = [+|-]<G-line mask>
 * parv[3] = Expiration offset
 * parv[4] = Comment
 *
 * From client:
 *
 * parv[1] = [+|-]<G-line mask>
 * parv[2] = Expiration offset
 * parv[3] = Comment
 *
 */
int m_gline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client* acptr = 0;  /* Init. to avoid compiler warning. */
  struct Gline*  gline;
  struct Gline*  prev;
  char*          user;
  char*          host;
  int            active;
  int            ip_mask;
  int            gtype = 0;
  time_t         expire = 0;

  /*
   * Remove expired G-lines
   */
  gline_remove_expired(TStime());
#ifdef BADCHAN
  /*
   * Remove expired bad channels
   */
  bad_channel_remove_expired(TStime());
#endif

  if (IsServer(cptr)) {
    if (find_conf_byhost(cptr->confs, sptr->name, CONF_UWORLD)) {
      if (parc < 3 || (*parv[2] != '-' && (parc < 5 || *parv[4] == '\0')))
        return need_more_params(sptr, "GLINE");

      if (*parv[2] == '-') /* add mode or delete mode? */
        active = 0;
      else
        active = 1;

      if (*parv[2] == '+' || *parv[2] == '-')
        parv[2]++; /* step past mode indicator */

      /*
       * forward the message appropriately
       */
      if (0 == ircd_strcmp(parv[1], "*")) {
        /*
         * global!
         */
        sendto_serv_butone(cptr,
                     active ? "%s " TOK_GLINE " %s +%s %s :%s" : "%s " TOK_GLINE " %s -%s",
                     NumServ(cptr), parv[1], parv[2], parv[3], parv[4]);
      }
      else if ((
#if 1
          /*
           * REMOVE THIS after all servers upgraded to 2.10.01 and
           * Uworld uses a numeric too
           */
          (strlen(parv[1]) != 1 && !(acptr = FindClient(parv[1])))) ||
          (strlen(parv[1]) == 1 &&
#endif
          !(acptr = FindNServer(parv[1]))))
        return 0;               /* no such server/user exists; forget it */
      else
#if 1
/*
 * REMOVE THIS after all servers upgraded to 2.10.01 and
 * Uworld uses a numeric too
 */
      if (IsServer(acptr) || !MyConnect(acptr))
#endif
      {
        /* single destination */
        sendto_one(acptr,
               active ? "%s " TOK_GLINE " %s +%s %s :%s" : "%s " TOK_GLINE " %s -%s",
               NumServ(sptr), parv[1], parv[2], parv[3], parv[4]);
        return 0;               /* only the intended  destination
                                   should add this gline */
      }

      if (!(host = strchr(parv[2], '@'))) {
        /*
         * convert user@host no @'s; assume username is '*'
         */
        user = "*";     
        host = parv[2];
      }
      else {
        user = parv[2];
        *(host++) = '\0';       /* break up string at the '@' */
      }
      ip_mask = check_if_ipmask(host);  /* Store this boolean */
#ifdef BADCHAN
      if ('#' == *host || '&' == *host || '+' == *host)
         gtype = 1;                /* BAD CHANNEL GLINE */
#endif
      for (gline = (gtype) ? BadChanGlineList : GlobalGlineList, prev = 0; gline;
           gline = gline->next)
      {
        if (0 == ircd_strcmp(gline->name, user) &&
            0 == ircd_strcmp(gline->host, host))
          break;
        prev = gline;
      }

      if (!active && gline)
      {
        /*
         * removing the gline, notify opers
         */
        sendto_op_mask(SNO_GLINE, "%s removing %s for %s@%s", parv[0],
            gtype ? "BADCHAN" : "GLINE", gline->name, gline->host);

#ifdef GPATH
       write_log(GPATH, "# " TIME_T_FMT " %s removing %s for %s@%s\n",
           TStime(), parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, 
            gline->host);
#endif /* GPATH */

        free_gline(gline, prev);        /* remove the gline */
      }
      else if (active)
      {                         /* must be adding a gline */
        expire = atoi(parv[3]) + TStime();      /* expire time? */
        if (gline && gline->expire < expire)
        {                       /* new expire time? */
          /* yes, notify the opers */
          sendto_op_mask(SNO_GLINE,
             "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
             parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host, 
             expire);
#ifdef GPATH
          write_log(GPATH, "# " TIME_T_FMT " %s resetting expiration time "
              "on %s for %s@%s to " TIME_T_FMT "\n",
              TStime(), parv[0], gtype ? "BADCHAN" : "GLINE",
              gline->name, gline->host, expire);
#endif /* GPATH */

          gline->expire = expire;       /* reset the expire time */
        }
        else if (!gline)
        {                       /* create gline */
          for (gline = (gtype) ? BadChanGlineList : GlobalGlineList; gline; gline = gline->next)
            if (!mmatch(gline->name, user) &&
                (ip_mask ? GlineIsIpMask(gline) : !GlineIsIpMask(gline)) &&
                !mmatch(gline->host, host))
              return 0;         /* found an existing G-line that matches */

          /* add the line: */
          add_gline(sptr, ip_mask, host, parv[4], user, expire, 0);
        }
      }
    }
  }
  else if (parc < 2 || *parv[1] == '\0')
  {
    /* Not enough args and a user; list glines */
    for (gline = GlobalGlineList; gline; gline = gline->next)
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0],
          gline->name, gline->host, gline->expire, gline->reason,
          GlineIsActive(gline) ? (GlineIsLocal(gline) ? " (local)" : "") :
          " (Inactive)");
    sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
  }
  else
  {
    int priv;

#ifdef LOCOP_LGLINE
    priv = IsAnOper(cptr);
#else
    priv = IsOper(cptr);
#endif

    if (priv)
    {                           /* non-oper not permitted to change things */
      if (*parv[1] == '-')
      {                         /* oper wants to deactivate the gline */
        active = 0;
        parv[1]++;
      }
      else if (*parv[1] == '+')
      {                         /* oper wants to activate inactive gline */
        active = 1;
        parv[1]++;
      }
      else
        active = -1;

      if (parc > 2)
        expire = atoi(parv[2]) + TStime();      /* oper wants to reset
                                                   expire TS */
    }
    else
      active = -1;

    if (!(host = strchr(parv[1], '@')))
    {
      user = "*";               /* no @'s; assume username is '*' */
      host = parv[1];
    }
    else
    {
      user = parv[1];
      *(host++) = '\0';         /* break up string at the '@' */
    }
    ip_mask = check_if_ipmask(host);    /* Store this boolean */
#ifdef BADCHAN
    if ('#' == *host || '&' == *host || '+' == *host)
#ifndef LOCAL_BADCHAN
     return 0;
#else
     gtype = 1;  /* BAD CHANNEL */
#endif
#endif

    for (gline = (gtype) ? BadChanGlineList : GlobalGlineList, prev = 0; gline;
         gline = gline->next)
    {
      if (!mmatch(gline->name, user) &&
          (ip_mask ? GlineIsIpMask(gline) : !GlineIsIpMask(gline)) &&
          !mmatch(gline->host, host))
        break;
      prev = gline;
    }

    if (!gline)
    {
#ifdef OPER_LGLINE
      if (priv && active && expire > CurrentTime)
      {
        /* Add local G-line */
        if (parc < 4 || !strchr(parv[3], ' '))
          return need_more_params(sptr, "GLINE");

        add_gline(sptr, ip_mask, host, parv[3], user, expire, 1);
      }
      else
#endif
        sendto_one(cptr, err_str(ERR_NOSUCHGLINE), me.name, parv[0], user,
            host);

      return 0;
    }

    if (expire <= gline->expire)
      expire = 0;

    if ((active == -1 ||
        (active ? GlineIsActive(gline) : !GlineIsActive(gline))) &&
        expire == 0)
    {
      /* oper wants a list of one gline only */
      sendto_one(cptr, rpl_str(RPL_GLIST), me.name, parv[0], gline->name,
          gline->host, gline->expire, gline->reason,
          GlineIsActive(gline) ? "" : " (Inactive)");
      sendto_one(cptr, rpl_str(RPL_ENDOFGLIST), me.name, parv[0]);
      return 0;
    }

    if (active != -1 &&
        (active ? !GlineIsActive(gline) : GlineIsActive(gline)))
    {
      if (active)               /* reset activation on gline */
        SetActive(gline);
#ifdef OPER_LGLINE
      else if (GlineIsLocal(gline))
      {
        /* Remove local G-line */
        sendto_op_mask(SNO_GLINE, "%s removed local %s for %s@%s",
            parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host);
#ifdef GPATH
        write_log(GPATH, "# " TIME_T_FMT
            " %s!%s@%s removed local %s for %s@%s\n",
            TStime(), parv[0], cptr->user->username, cptr->user->host,
            gtype ? "BADCHAN" : "GLINE",
            gline->name, gline->host);
#endif /* GPATH */
        free_gline(gline, prev);        /* remove the gline */
        return 0;
      }
#endif
      else
        ClearActive(gline);
    }
    else
      active = -1;              /* for later sendto_ops and logging functions */

    if (expire)
      gline->expire = expire;   /* reset expiration time */

    /* inform the operators what's up */
    if (active != -1)
    {                           /* changing the activation */
       sendto_op_mask(SNO_GLINE, !expire ? "%s %sactivating %s for %s@%s" :
          "%s %sactivating %s for %s@%s and "
          "resetting expiration time to " TIME_T_FMT,
          parv[0], active ? "re" : "de", gtype ? "BADCHAN" : "GLINE",
          gline->name, gline->host, gline->expire);
#ifdef GPATH
      write_log(GPATH, !expire ? "# " TIME_T_FMT " %s!%s@%s %sactivating "
          "%s for %s@%s\n" : "# " TIME_T_FMT " %s!%s@%s %sactivating %s "
          "for %s@%s and resetting expiration time to " TIME_T_FMT "\n",
          TStime(), parv[0], cptr->user->username, cptr->user->host,
          active ? "re" : "de", gtype ? "BADCHAN" : "GLINE", gline->name, 
          gline->host, gline->expire);
#endif /* GPATH */

    }
    else if (expire)
    {                           /* changing only the expiration */
      sendto_op_mask(SNO_GLINE,
          "%s resetting expiration time on %s for %s@%s to " TIME_T_FMT,
          parv[0], gtype ? "BADCHAN" : "GLINE", gline->name, gline->host, 
          gline->expire);
#ifdef GPATH
      write_log(GPATH, "# " TIME_T_FMT " %s!%s@%s resetting expiration "
          "time on %s for %s@%s to " TIME_T_FMT "\n", TStime(), parv[0],
          cptr->user->username, cptr->user->host, gtype ? "BADCHAN" : "GLINE",
          gline->name, gline->host, gline->expire);
#endif /* GPATH */
    }
  }
  return 0;
}

#endif /* 0 */

#endif /* 0 */
