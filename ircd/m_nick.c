/*
 * IRC - Internet Relay Chat, ircd/m_nick.c
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
#include "IPcheck.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * m_nick - message handler for local clients
 * parv[0] = sender prefix
 * parv[1] = nickname
 */
int m_nick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char           nick[NICKLEN + 2];
  char*          arg;
  char*          s;
  const char*    client_name;

  assert(0 != cptr);
  assert(cptr == sptr);

  /*
   * parv[0] will be empty for clients connecting for the first time
   */
  client_name = (*sptr->name) ? sptr->name : "*";

  if (parc < 2) {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, client_name);
    return 0;
  }
  /*
   * Don't let them send make us send back a really long string of
   * garbage
   */
  arg = parv[1];
  if (strlen(arg) > NICKLEN)
    arg[NICKLEN] = '\0';

  if ((s = strchr(arg, '~')))
    *s = '\0';

  strcpy(nick, arg);

  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (0 == do_nick_name(nick)) {
    sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name, client_name, arg);
    return 0;
  }

  /* 
   * Check if this is a LOCAL user trying to use a reserved (Juped)
   * nick, if so tell him that it's a nick in use...
   */
  if (isNickJuped(nick)) {
    sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name, client_name, nick);
    return 0;                        /* NICK message ignored */
  }

  if (!(acptr = FindClient(nick))) {
    /*
     * No collisions, all clear...
     */
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  if (IsServer(acptr)) {
    sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name, client_name, nick);
    return 0;                        /* NICK message ignored */
  }
  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr) {
    /*
     * If acptr == sptr, then we have a client doing a nick
     * change between *equivalent* nicknames as far as server
     * is concerned (user is changing the case of his/her
     * nickname or somesuch)
     */
    if (0 != strcmp(acptr->name, nick)) {
      /*
       * Allows change of case in his/her nick
       */
      return set_nick_name(cptr, sptr, nick, parc, parv);
    }
    /*
     * This is just ':old NICK old' type thing.
     * Just forget the whole thing here. There is
     * no point forwarding it to anywhere,
     * especially since servers prior to this
     * version would treat it as nick collision.
     */
    return 0;
  }
  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  assert(acptr != sptr);
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   *
   * XXX - hmmm can this happen after one is registered?
   */
  if (IsUnknown(acptr) && MyConnect(acptr)) {
    ++ServerStats->is_ref;
    IPcheck_connect_fail(acptr->ip);
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  /*
   * NICK is coming from local client connection. Just
   * send error reply and ignore the command.
   */
  sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name, client_name, nick);
  return 0;                        /* NICK message ignored */
}


/*
 * ms_nick - server message handler for nicks
 * parv[0] = sender prefix
 * parv[1] = nickname
 *
 * If from server, source is client:
 *   parv[2] = timestamp
 *
 * Source is server:
 *   parv[2] = hopcount
 *   parv[3] = timestamp
 *   parv[4] = username
 *   parv[5] = hostname
 *   parv[6] = umode (optional)
 *   parv[parc-3] = IP#                 <- Only Protocol >= 10
 *   parv[parc-2] = YXX, numeric nick   <- Only Protocol >= 10
 *   parv[parc-1] = info
 *   parv[0] = server
 */
int ms_nick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char           nick[NICKLEN + 2];
  time_t         lastnick = 0;
  int            differ = 1;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if ((IsServer(sptr) && parc < 8) || parc < 3) {
    sendto_ops("bad NICK param count for %s from %s", parv[1], cptr->name);
    return need_more_params(sptr, "NICK");
  }

  ircd_strncpy(nick, parv[1], NICKLEN);
  nick[NICKLEN] = '\0';

  if (!IsBurstOrBurstAck(sptr)) {
     if (IsServer(sptr)) {
       lastnick = atoi(parv[3]);
       if (lastnick > OLDEST_TS) 
         sptr->serv->lag = TStime() - lastnick;
     }
     else {
       lastnick = atoi(parv[2]); 
       if (lastnick > OLDEST_TS)
         sptr->user->server->serv->lag = TStime() - lastnick;
     }
  }
  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (0 == do_nick_name(nick) || 0 != strcmp(nick, parv[1])) {
    sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name, parv[0], parv[1]);

    ++ServerStats->is_kill;
    sendto_ops("Bad Nick: %s From: %s %s", parv[1], parv[0], cptr->name);
    sendto_one(cptr, "%s " TOK_KILL " %s :%s (%s <- %s[%s])",
               NumServ(&me), IsServer(sptr) ? parv[parc - 2] : parv[0], me.name,
               parv[1], nick, cptr->name);
    if (!IsServer(sptr)) {
      /*
       * bad nick _change_
       */
      sendto_highprot_butone(cptr, 10, "%s " TOK_KILL " %s :%s (%s <- %s!%s@%s)",
                             NumServ(&me), parv[0], me.name, cptr->name,
                             parv[0], sptr->user ? sptr->username : "",
                             sptr->user ? sptr->user->server->name : cptr->name);
    }
    return 0;
  }
  /*
   * Check against nick name collisions.
   *
   * Put this 'if' here so that the nesting goes nicely on the screen :)
   * We check against server name list before determining if the nickname
   * is present in the nicklist (due to the way the below for loop is
   * constructed). -avalon
   */
  if (!(acptr = FindClient(nick))) {
    /*
     * No collisions, all clear...
     */
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  assert(0 != acptr);

  if (IsServer(acptr)) {
    /*
     * We have a nickname trying to use the same name as
     * a server. Send out a nick collision KILL to remove
     * the nickname. As long as only a KILL is sent out,
     * there is no danger of the server being disconnected.
     * Ultimate way to jupiter a nick ? >;-). -avalon
     */
    sendto_ops("Nick collision on %s(%s <- %s)", sptr->name, acptr->from->name, cptr->name);
    ++ServerStats->is_kill;

    sendto_one(cptr, "%s " TOK_KILL " %s%s :%s (%s <- %s)",
               NumServ(&me), NumNick(sptr), me.name, acptr->from->name,
               cptr->name);

    sptr->flags |= FLAGS_KILLED;
    /*
     * if sptr is a server it is exited here, nothing else to do
     */
    return exit_client(cptr, sptr, &me, "Nick/Server collision");
  }

  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr) {
    if (strcmp(acptr->name, nick) != 0)
      /*
       * Allows change of case in his/her nick
       */
      return set_nick_name(cptr, sptr, nick, parc, parv);
    else
      /*
       * This is just ':old NICK old' type thing.
       * Just forget the whole thing here. There is
       * no point forwarding it to anywhere,
       * especially since servers prior to this
       * version would treat it as nick collision.
       */
      return 0;                        /* NICK Message ignored */
  }

  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  assert(acptr != sptr);
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   */
  if (IsUnknown(acptr) && MyConnect(acptr)) {
    ++ServerStats->is_ref;
    IPcheck_connect_fail(acptr->ip);
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  /*
   * Decide, we really have a nick collision and deal with it
   */
  /*
   * NICK was coming from a server connection.
   * This means we have a race condition (two users signing on
   * at the same time), or two net fragments reconnecting with the same nick.
   * The latter can happen because two different users connected
   * or because one and the same user switched server during a net break.
   * If the TimeStamps are equal, we kill both (or only 'new'
   * if it was a ":server NICK new ...").
   * Otherwise we kill the youngest when user@host differ,
   * or the oldest when they are the same.
   * We treat user and ~user as different, because if it wasn't
   * a faked ~user the AUTH wouldn't have added the '~'.
   * --Run
   *
   */
  if (IsServer(sptr)) {
    /*
     * A new NICK being introduced by a neighbouring
     * server (e.g. message type ":server NICK new ..." received)
     *
     * compare IP address and username
     */
    differ =  (acptr->ip.s_addr != htonl(base64toint(parv[parc - 3]))) ||
              (0 != ircd_strcmp(acptr->user->username, parv[4]));
    sendto_ops("Nick collision on %s (%s " TIME_T_FMT " <- %s " TIME_T_FMT
               " (%s user@host))", acptr->name, acptr->from->name, acptr->lastnick,
               cptr->name, lastnick, differ ? "Different" : "Same");
  }
  else {
    /*
     * A NICK change has collided (e.g. message type ":old NICK new").
     *
     * compare IP address and username
     */
    differ =  (acptr->ip.s_addr != sptr->ip.s_addr) ||
              (0 != ircd_strcmp(acptr->user->username, sptr->user->username));              
    sendto_ops("Nick change collision from %s to %s (%s " TIME_T_FMT " <- %s "
               TIME_T_FMT ")", sptr->name, acptr->name, acptr->from->name,
               acptr->lastnick, cptr->name, lastnick);
  }
  /*
   * Now remove (kill) the nick on our side if it is the youngest.
   * If no timestamp was received, we ignore the incoming nick
   * (and expect a KILL for our legit nick soon ):
   * When the timestamps are equal we kill both nicks. --Run
   * acptr->from != cptr should *always* be true (?).
   *
   * This exits the client sending the NICK message
   */
  if (acptr->from != cptr) {
    if ((differ && lastnick >= acptr->lastnick) || (!differ && lastnick <= acptr->lastnick)) {
      if (!IsServer(sptr)) {
        ++ServerStats->is_kill;
        sendto_highprot_butone(cptr, 10,        /* Kill old from outgoing servers */
                              "%s " TOK_KILL " %s%s :%s (%s <- %s (Nick collision))",
                              NumServ(&me), NumNick(sptr), me.name, acptr->from->name,
                              cptr->name);
        assert(!MyConnect(sptr));
#if 0
        /*
         * XXX - impossible
         */
        if (MyConnect(sptr))
          sendto_one(cptr, "%s " TOK_KILL " %s%s :%s (Ghost 2)",
                     NumServ(&me), NumNick(sptr), me.name);
#endif
        sptr->flags |= FLAGS_KILLED;
        exit_client(cptr, sptr, &me, "Nick collision (you're a ghost)");
        /*
         * we have killed sptr off, zero out it's pointer so if it's used
         * again we'll know about it --Bleep
         */
        sptr = 0;
      }
      if (lastnick != acptr->lastnick)
        return 0;                /* Ignore the NICK */
    }
    sendto_one(acptr, err_str(ERR_NICKCOLLISION), me.name, acptr->name, nick);
  }

  ++ServerStats->is_kill;
  acptr->flags |= FLAGS_KILLED;
  /*
   * This exits the client we had before getting the NICK message
   */
  if (differ) {
    sendto_highprot_butone(cptr, 10,        /* Kill our old from outgoing servers */
                           "%s " TOK_KILL " %s%s :%s (%s <- %s (older nick overruled))",
                           NumServ(&me), NumNick(acptr), me.name, acptr->from->name,
                           cptr->name);
    if (MyConnect(acptr))
      sendto_one(cptr, "%s%s " TOK_QUIT " :Local kill by %s (Ghost)",
                 NumNick(acptr), me.name);
    exit_client(cptr, acptr, &me, "Nick collision (older nick overruled)");
  }
  else {
    sendto_highprot_butone(cptr, 10,        /* Kill our old from outgoing servers */
                          "%s " TOK_KILL " %s%s :%s (%s <- %s (nick collision from same user@host))",
                          NumServ(&me), NumNick(acptr), me.name, acptr->from->name,
                          cptr->name);
    if (MyConnect(acptr))
      sendto_one(cptr,
                 "%s%s " TOK_QUIT " :Local kill by %s (Ghost: switched servers too fast)",
                  NumNick(acptr), me.name);
    exit_client(cptr, acptr, &me, "Nick collision (You collided yourself)");
  }
  if (lastnick == acptr->lastnick)
    return 0;

  assert(0 != sptr);
  return set_nick_name(cptr, sptr, nick, parc, parv);
}

#if 0
/*
 * m_nick
 *
 * parv[0] = sender prefix
 * parv[1] = nickname
 *
 * If from server, source is client:
 *   parv[2] = timestamp
 *
 * Source is server:
 *   parv[2] = hopcount
 *   parv[3] = timestamp
 *   parv[4] = username
 *   parv[5] = hostname
 *   parv[6] = umode (optional)
 *   parv[parc-3] = IP#                 <- Only Protocol >= 10
 *   parv[parc-2] = YXX, numeric nick   <- Only Protocol >= 10
 *   parv[parc-1] = info
 *   parv[0] = server
 */
int m_nick(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client* acptr;
  char           nick[NICKLEN + 2];
  char*          s;
  time_t         lastnick = 0;
  int            differ = 1;

  if (parc < 2) {
    sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN), me.name, parv[0]);
    return 0;
  }
  else if ((IsServer(sptr) && parc < 8) || (IsServer(cptr) && parc < 3))
  {
    need_more_params(sptr, "NICK");
    sendto_ops("bad NICK param count for %s from %s", parv[1], cptr->name);
    return 0;
  }
  if (MyConnect(sptr) && (s = strchr(parv[1], '~')))
    *s = '\0';
  ircd_strncpy(nick, parv[1], NICKLEN);
  nick[NICKLEN] = '\0';
  if (IsServer(cptr)) {
    if (IsServer(sptr)) {
      lastnick = atoi(parv[3]);
      if (lastnick > OLDEST_TS) 
      	sptr->serv->lag = TStime() - lastnick;
    } else {
      lastnick = atoi(parv[2]); 
      if (lastnick > OLDEST_TS)
       sptr->user->server->serv->lag = TStime() - lastnick;
    }
  }
  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (do_nick_name(nick) == 0 || (IsServer(cptr) && strcmp(nick, parv[1])))
  {
    sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name, parv[0], parv[1]);

    if (IsServer(cptr))
    {
      ServerStats->is_kill++;
      sendto_ops("Bad Nick: %s From: %s %s",
          parv[1], parv[0], cptr->name);
      sendto_one(cptr, "%s " TOK_KILL " %s :%s (%s <- %s[%s])",
            NumServ(&me), IsServer(sptr) ? parv[parc - 2] : parv[0], me.name,
            parv[1], nick, cptr->name);
      if (!IsServer(sptr))        /* bad nick _change_ */
      {
        sendto_highprot_butone(cptr, 10, "%s " TOK_KILL " %s :%s (%s <- %s!%s@%s)",
            NumServ(&me), parv[0], me.name, cptr->name,
            parv[0], sptr->user ? sptr->username : "",
            sptr->user ? sptr->user->server->name : cptr->name);
      }
    }
    return 0;
  }

  /* 
   * Check if this is a LOCAL user trying to use a reserved (Juped)
   * nick, if so tell him that it's a nick in use...
   */
  if ((!IsServer(cptr)) && isNickJuped(nick))
  {
    sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
        /* parv[0] is empty when connecting */
        EmptyString(parv[0]) ? "*" : parv[0], nick);
    return 0;                        /* NICK message ignored */
  }

  /*
   * Check against nick name collisions.
   *
   * Put this 'if' here so that the nesting goes nicely on the screen :)
   * We check against server name list before determining if the nickname
   * is present in the nicklist (due to the way the below for loop is
   * constructed). -avalon
   */
  if ((acptr = FindServer(nick))) {
    if (MyConnect(sptr))
    {
      sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
          EmptyString(parv[0]) ? "*" : parv[0], nick);
      return 0;                        /* NICK message ignored */
    }
    /*
     * We have a nickname trying to use the same name as
     * a server. Send out a nick collision KILL to remove
     * the nickname. As long as only a KILL is sent out,
     * there is no danger of the server being disconnected.
     * Ultimate way to jupiter a nick ? >;-). -avalon
     */
    sendto_ops("Nick collision on %s(%s <- %s)",
               sptr->name, acptr->from->name, cptr->name);
    ServerStats->is_kill++;
    sendto_one(cptr, "%s " TOK_KILL " %s%s :%s (%s <- %s)",
               NumServ(&me), NumNick(sptr), me.name, acptr->from->name,
               cptr->name);
    sptr->flags |= FLAGS_KILLED;
    return exit_client(cptr, sptr, &me, "Nick/Server collision");
  }

  if (!(acptr = FindClient(nick)))
    return set_nick_name(cptr, sptr, nick, parc, parv);  /* No collisions, all clear... */
  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr)
  {
    if (strcmp(acptr->name, nick) != 0)
      /*
       * Allows change of case in his/her nick
       */
      return set_nick_name(cptr, sptr, nick, parc, parv);
    else
      /*
       * This is just ':old NICK old' type thing.
       * Just forget the whole thing here. There is
       * no point forwarding it to anywhere,
       * especially since servers prior to this
       * version would treat it as nick collision.
       */
      return 0;                        /* NICK Message ignored */
  }

  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   */
  if (IsUnknown(acptr) && MyConnect(acptr))
  {
    ++ServerStats->is_ref;
    IPcheck_connect_fail(acptr->ip);
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  /*
   * Decide, we really have a nick collision and deal with it
   */
  if (!IsServer(cptr))
  {
    /*
     * NICK is coming from local client connection. Just
     * send error reply and ignore the command.
     */
    sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
        /* parv[0] is empty when connecting */
        EmptyString(parv[0]) ? "*" : parv[0], nick);
    return 0;                        /* NICK message ignored */
  }
  /*
   * NICK was coming from a server connection.
   * This means we have a race condition (two users signing on
   * at the same time), or two net fragments reconnecting with the same nick.
   * The latter can happen because two different users connected
   * or because one and the same user switched server during a net break.
   * If the TimeStamps are equal, we kill both (or only 'new'
   * if it was a ":server NICK new ...").
   * Otherwise we kill the youngest when user@host differ,
   * or the oldest when they are the same.
   * We treat user and ~user as different, because if it wasn't
   * a faked ~user the AUTH wouldn't have added the '~'.
   * --Run
   *
   */
  if (IsServer(sptr))
  {
    /*
     * A new NICK being introduced by a neighbouring
     * server (e.g. message type ":server NICK new ..." received)
     */
    differ =  (acptr->ip.s_addr != htonl(base64toint(parv[parc - 3]))) ||
            (0 != ircd_strcmp(acptr->user->username, parv[4]));
    sendto_ops("Nick collision on %s (%s " TIME_T_FMT " <- %s " TIME_T_FMT
               " (%s user@host))", acptr->name, acptr->from->name, acptr->lastnick,
               cptr->name, lastnick, differ ? "Different" : "Same");
  }
  else
  {
    /*
     * A NICK change has collided (e.g. message type ":old NICK new").
     */
    lastnick = atoi(parv[2]);
    differ =  (acptr->ip.s_addr != sptr->ip.s_addr) ||
            (0 != ircd_strcmp(acptr->user->username, sptr->user->username));              
    sendto_ops("Nick change collision from %s to %s (%s " TIME_T_FMT " <- %s "
               TIME_T_FMT ")", sptr->name, acptr->name, acptr->from->name,
               acptr->lastnick, cptr->name, lastnick);
  }
  /*
   * Now remove (kill) the nick on our side if it is the youngest.
   * If no timestamp was received, we ignore the incoming nick
   * (and expect a KILL for our legit nick soon ):
   * When the timestamps are equal we kill both nicks. --Run
   * acptr->from != cptr should *always* be true (?).
   */
  if (acptr->from != cptr)
  {
    if ((differ && lastnick >= acptr->lastnick) ||
        (!differ && lastnick <= acptr->lastnick))
    {
      if (!IsServer(sptr))
      {
        ServerStats->is_kill++;
        sendto_highprot_butone(cptr, 10,        /* Kill old from outgoing servers */
                               "%s " TOK_KILL " %s%s :%s (%s <- %s (Nick collision))",
                               NumServ(&me), NumNick(sptr), me.name, acptr->from->name,
                               cptr->name);
        if (MyConnect(sptr) && IsServer(cptr) && Protocol(cptr) > 9)
          sendto_one(cptr, "%s " TOK_KILL " %s%s :%s (Ghost2)",
                     NumServ(&me), NumNick(sptr), me.name);
        sptr->flags |= FLAGS_KILLED;
        exit_client(cptr, sptr, &me, "Nick collision (you're a ghost)");
      }
      if (lastnick != acptr->lastnick)
        return 0;                /* Ignore the NICK */
    }
    sendto_one(acptr, err_str(ERR_NICKCOLLISION), me.name, acptr->name, nick);
  }
  ServerStats->is_kill++;
  acptr->flags |= FLAGS_KILLED;
  if (differ)
  {
    sendto_highprot_butone(cptr, 10,        /* Kill our old from outgoing servers */
                           "%s " TOK_KILL " %s%s :%s (%s <- %s (older nick overruled))",
                           NumServ(&me), NumNick(acptr), me.name, acptr->from->name,
                           cptr->name);
    if (MyConnect(acptr) && IsServer(cptr) && Protocol(cptr) > 9)
      sendto_one(cptr, "%s%s " TOK_QUIT " :Local kill by %s (Ghost)",
          NumNick(acptr), me.name);
    exit_client(cptr, acptr, &me, "Nick collision (older nick overruled)");
  }
  else
  {
    sendto_highprot_butone(cptr, 10,        /* Kill our old from outgoing servers */
                           "%s " TOK_KILL " %s%s :%s (%s <- %s (nick collision from same user@host))",
                           NumServ(&me), NumNick(acptr), me.name, acptr->from->name,
                           cptr->name);
    if (MyConnect(acptr) && IsServer(cptr) && Protocol(cptr) > 9)
      sendto_one(cptr,
          "%s%s " TOK_QUIT " :Local kill by %s (Ghost: switched servers too fast)",
          NumNick(acptr), me.name);
    exit_client(cptr, acptr, &me, "Nick collision (You collided yourself)");
  }
  if (lastnick == acptr->lastnick)
    return 0;

  return set_nick_name(cptr, sptr, nick, parc, parv);
}

#endif /* 0 */
