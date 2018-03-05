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
#include "config.h"

#include "IPcheck.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

 /*
* 'do_nick_name' ensures that the given parameter (nick) is really a proper
* string for a nickname (note, the 'nick' may be modified in the process...)
*
* RETURNS the length of the final NICKNAME (0, if nickname is invalid)
*
* Nickname characters are in range 'A'..'}', '_', '-', '0'..'9'
*  anything outside the above set will terminate nickname.
* In addition, the first character cannot be '-' or a Digit.
*
* Note:
*  The '~'-character should be allowed, but a change should be global,
*  some confusion would result if only few servers allowed it...
*/
static int do_nick_name(char* nick)
{
  char* ch  = nick;
  char* end = ch + NICKLEN;
  assert(0 != ch);
  
  /* first character in [0..9-] */
  if (*ch == '-' || IsDigit(*ch))
    return 0;
  for ( ; (ch < end) && *ch; ++ch)
    if (!IsNickChar(*ch))
      break;

  *ch = '\0';

  return (ch - nick);
}

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

  assert(0 != cptr);
  assert(cptr == sptr);

  if (IsServerPort(cptr))
    return exit_client(cptr, cptr, &me, "Use a different port");
  if (IsWebircPort(cptr) && !cli_wline(cptr))
    return exit_client(cptr, cptr, &me, "WebIRC authorization required");

  if (parc < 2) {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  /*
   * Don't let them send make us send back a really long string of
   * garbage
   */
  arg = parv[1];
  if (strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
    arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';

  if ((s = strchr(arg, '~')))
    *s = '\0';

  strcpy(nick, arg);

  /*
   * If do_nick_name() returns a null name then reject it.
   */
  if (0 == do_nick_name(nick)) {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, arg);
    return 0;
  }

  /* 
   * Check if this is a LOCAL user trying to use a reserved (Juped)
   * nick, if so tell him that it's a nick in use...
   */
  if (isNickJuped(nick)) {
    send_reply(sptr, ERR_NICKNAMEINUSE, nick);
    return 0;                        /* NICK message ignored */
  }

  if (!(acptr = FindClient(nick))) {
    /*
     * No collisions, all clear...
     */
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  if (IsServer(acptr)) {
    send_reply(sptr, ERR_NICKNAMEINUSE, nick);
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
    if (0 != strcmp(cli_name(acptr), nick)) {
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
   *
   * Yes, client 1 connects to IRC and registers, client 2 connects and
   * sends "NICK foo" but doesn't send anything more.  client 1 now does
   * /nick foo, they should succeed and client 2 gets disconnected with
   * the message below.
   */
  if (IsUnknown(acptr) && MyConnect(acptr)) {
    ++ServerStats->is_reg_collided;
    IPcheck_connect_fail(acptr, 0);
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv);
  }
  /*
   * NICK is coming from local client connection. Just
   * send error reply and ignore the command.
   */
  send_reply(sptr, ERR_NICKNAMEINUSE, nick);
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
  struct Client *acptr;
  char nick[NICKLEN + 2];
  time_t lastnick = 0;
  int differ = 1;
  const char *type;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if ((IsServer(sptr) && parc < 8) || parc < 3)
  {
    sendto_opmask_butone(0, SNO_OLDSNO, "bad NICK param count for %s from %C",
			 parv[1], cptr);
    return need_more_params(sptr, "NICK");
  }

  ircd_strncpy(nick, parv[1], NICKLEN);
  nick[NICKLEN] = '\0';

  if (IsServer(sptr))
  {
    lastnick = atoi(parv[3]);
    if (lastnick > OLDEST_TS && !IsBurstOrBurstAck(sptr)) 
      cli_serv(sptr)->lag = TStime() - lastnick;
  }
  else
  {
    lastnick = atoi(parv[2]); 
    if (lastnick > OLDEST_TS && !IsBurstOrBurstAck(sptr))
      cli_serv(cli_user(sptr)->server)->lag = TStime() - lastnick;
  }
  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (!do_nick_name(nick) || strcmp(nick, parv[1]))
  {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, parv[1]);
    
    ++ServerStats->is_kill;
    sendto_opmask_butone(0, SNO_OLDSNO, "Bad Nick: %s From: %s %C", parv[1],
			 parv[0], cptr);
    sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (%s <- %s[%s])",
		  IsServer(sptr) ? parv[parc - 2] : parv[0], cli_name(&me), parv[1],
		  nick, cli_name(cptr));
    if (!IsServer(sptr))
    {
      /*
       * bad nick _change_
       */
      sendcmdto_serv_butone(&me, CMD_KILL, 0, "%s :%s (%s <- %s!%s@%s)",
			    parv[0], cli_name(&me), cli_name(cptr), parv[0],
			    cli_user(sptr) ? cli_username(sptr) : "",
			    cli_user(sptr) ? cli_name(cli_user(sptr)->server) :
			    cli_name(cptr));
    }
    return 0;
  }
  /* Check against nick name collisions. */
  if ((acptr = FindClient(nick)) == NULL)
    /* No collisions, all clear... */
    return set_nick_name(cptr, sptr, nick, parc, parv);

  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr)
  {
    if (strcmp(cli_name(acptr), nick) != 0)
      /* Allows change of case in his/her nick */
      return set_nick_name(cptr, sptr, nick, parc, parv);
    else
      /* Setting their nick to what it already is? Ignore it. */
      return 0;
  }
  /* now we know we have a real collision. */
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
  if (IsUnknown(acptr) && MyConnect(acptr))
  {
    ++ServerStats->is_reg_collided;
    IPcheck_connect_fail(acptr, 0);
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
  if (IsServer(sptr))
  {
    struct irc_in_addr ip;
    /*
     * A new NICK being introduced by a neighbouring
     * server (e.g. message type ":server NICK new ..." received)
     *
     * compare IP address and username
     */
    base64toip(parv[parc - 3], &ip);
    differ =  (0 != memcmp(&cli_ip(acptr), &ip, sizeof(cli_ip(acptr)))) ||
              (0 != ircd_strcmp(cli_user(acptr)->username, parv[4]));
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick collision on %C (%C %Tu <- "
			 "%C %Tu (%s user@host))", acptr, cli_from(acptr),
			 cli_lastnick(acptr), cptr, lastnick,
			 differ ? "Different" : "Same");
  }
  else
  {
    /*
     * A NICK change has collided (e.g. message type ":old NICK new").
     *
     * compare IP address and username
     */
    differ =  (0 != memcmp(&cli_ip(acptr), &cli_ip(sptr), sizeof(cli_ip(acptr)))) ||
              (0 != ircd_strcmp(cli_user(acptr)->username, cli_user(sptr)->username));
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick change collision from %C to "
			 "%C (%C %Tu <- %C %Tu)", sptr, acptr, cli_from(acptr),
			 cli_lastnick(acptr), cptr, lastnick);
  }
  type = differ ? "overruled by older nick" : "nick collision from same user@host";
  /*
   * Now remove (kill) the nick on our side if it is the youngest.
   * If no timestamp was received, we ignore the incoming nick
   * (and expect a KILL for our legit nick soon ):
   * When the timestamps are equal we kill both nicks. --Run
   * acptr->from != cptr should *always* be true (?).
   *
   * This exits the client sending the NICK message
   */
  if ((differ && lastnick >= cli_lastnick(acptr)) ||
      (!differ && lastnick <= cli_lastnick(acptr)))
  {
    ServerStats->is_kill++;
    if (!IsServer(sptr))
    {
      /* If this was a nick change and not a nick introduction, we
       * need to ensure that we remove our record of the client, and
       * send a KILL to the whole network.
       */
      assert(!MyConnect(sptr));
      /* Inform the rest of the net... */
      sendcmdto_serv_butone(&me, CMD_KILL, 0, "%C :%s (%s)",
                            sptr, cli_name(&me), type);
      /* Don't go sending off a QUIT message... */
      SetFlag(sptr, FLAG_KILLED);
      /* Remove them locally. */
      exit_client_msg(cptr, sptr, &me,
                      "Killed (%s (%s))",
                      feature_str(FEAT_HIS_SERVERNAME), type);
    }
    else
    {
      /* If the origin is a server, this was a new client, so we only
       * send the KILL in the direction it came from.  We have no
       * client record that we would have to clean up.
       */
      sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (%s)",
                    parv[parc - 2], cli_name(&me), type);
    }
    /* If the timestamps differ and we just killed sptr, we don't need to kill
     * acptr as well.
     */
    if (lastnick != cli_lastnick(acptr))
      return 0;
  }
  /* Tell acptr why we are killing it. */
  send_reply(acptr, ERR_NICKCOLLISION, nick);

  ServerStats->is_kill++;
  SetFlag(acptr, FLAG_KILLED);
  /*
   * This exits the client we had before getting the NICK message
   */
  sendcmdto_serv_butone(&me, CMD_KILL, NULL, "%C :%s (%s)",
                        acptr, feature_str(FEAT_HIS_SERVERNAME),
                        type);
  exit_client_msg(cptr, acptr, &me, "Killed (%s (%s))",
                  feature_str(FEAT_HIS_SERVERNAME), type);
  if (lastnick == cli_lastnick(acptr))
    return 0;
  if (sptr == NULL)
    return 0;
  return set_nick_name(cptr, sptr, nick, parc, parv);
}
