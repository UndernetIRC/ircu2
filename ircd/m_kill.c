/*
 * IRC - Internet Relay Chat, ircd/m_kill.c
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

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_misc.h"
#include "send.h"
#include "whowas.h"

#include <assert.h>
#include <string.h>

/*
 * do_kill - Performs the generic work involved in killing a client
 *
 */
static int do_kill(struct Client* cptr, struct Client* sptr,
		   struct Client* victim, char* inpath, char* path, char* msg)
{
  assert(0 != cptr);
  assert(0 != sptr);
  assert(!IsServer(victim));

  /*
   * Notify all *local* opers about the KILL (this includes the one
   * originating the kill, if from this server--the special numeric
   * reply message is not generated anymore).
   *
   * Note: "victim->name" is used instead of "user" because we may
   *       have changed the target because of the nickname change.
   */
  sendto_opmask_butone(0, IsServer(sptr) ? SNO_SERVKILL : SNO_OPERKILL,
                       "Received KILL message for %s. From %s Path: %s!%s %s",
                       get_client_name(victim, SHOW_IP), cli_name(sptr),
                       inpath, path, msg);
  log_write_kill(victim, sptr, inpath, path, msg);

  /*
   * And pass on the message to other servers. Note, that if KILL
   * was changed, the message has to be sent to all links, also
   * back.
   * Client suicide kills are NOT passed on --SRB
   */
  if (IsServer(cptr) || !MyConnect(victim)) {
    sendcmdto_serv_butone(sptr, CMD_KILL, cptr, "%C :%s!%s %s", victim,
                          inpath, path, msg);

    /*
     * Set FLAG_KILLED. This prevents exit_one_client from sending
     * the unnecessary QUIT for this. (This flag should never be
     * set in any other place)
     */
    SetFlag(victim, FLAG_KILLED);
  }

  /*
   * Tell the victim she/he has been zapped, but *only* if
   * the victim is on current server--no sense in sending the
   * notification chasing the above kill, it won't get far
   * anyway (as this user don't exist there any more either)
   * In accordance with the new hiding rules, the victim
   * always sees the kill as coming from me.
   */
  if (MyConnect(victim))
    sendcmdto_one(feature_bool(FEAT_HIS_KILLWHO) ? &me : sptr, CMD_KILL, 
		  victim, "%C :%s %s", victim, feature_bool(FEAT_HIS_KILLWHO)
		  ? feature_str(FEAT_HIS_SERVERNAME) : cli_name(sptr), msg);
  return exit_client_msg(cptr, victim, feature_bool(FEAT_HIS_KILLWHO)
			 ? &me : sptr, "Killed (%s %s)",
			 feature_bool(FEAT_HIS_KILLWHO) ? 
			 feature_str(FEAT_HIS_SERVERNAME) : cli_name(sptr),
			 msg);
}

/*
 * ms_kill - server message handler template
 *
 * NOTE: IsServer(cptr) == true;
 *
 * parv[0]      = sender prefix
 * parv[1]      = kill victim
 * parv[parc-1] = kill path
 */
int ms_kill(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* victim;
  char*          path;
  char*          msg;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  /*
   * XXX - a server sending less than 3 params could really desync
   * things
   */
  if (parc < 3) {
    protocol_violation(sptr,"Too few arguments for KILL");
    return need_more_params(sptr, "KILL");
  }

  path = parv[parc - 1];        /* Either defined or NULL (parc >= 3) */

  if (!(msg = strchr(path, ' '))) /* Extract out the message */
    msg = "(No reason supplied)";
  else
    *(msg++) = '\0'; /* Remove first character (space) and terminate path */

  if (!(victim = findNUser(parv[1]))) {
    if (IsUser(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :KILL target disconnected "
		    "before I got him :(", sptr);
    return 0;
  }

  /*
   * We *can* have crossed a NICK with this numeric... --Run
   *
   * Note the following situation:
   *  KILL SAA -->       X
   *  <-- S NICK ... SAA | <-- SAA QUIT <-- S NICK ... SAA <-- SQUIT S
   * Where the KILL reaches point X before the QUIT does.
   * This would then *still* cause an orphan because the KILL doesn't reach S
   * (because of the SQUIT), the QUIT is ignored (because of the KILL)
   * and the second NICK ... SAA causes an orphan on the server at the
   * right (which then isn't removed when the SQUIT arrives).
   * Therefore we still need to detect numeric nick collisions too.
   *
   * Bounce the kill back to the originator, if the client can't be found
   * by the next hop (short lag) the bounce won't propagate further.
   */
  if (MyConnect(victim)) {
    sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (Ghost 5 Numeric Collided)",
                  victim, path);
  }
  return do_kill(cptr, sptr, victim, cli_name(cptr), path, msg);
}

/*
 * mo_kill - oper message handler template
 *
 * NOTE: IsPrivileged(sptr), IsAnOper(sptr) == true
 *       IsServer(cptr), IsServer(sptr) == false
 *
 * parv[0]      = sender prefix
 * parv[1]      = kill victim
 * parv[parc-1] = kill path
 */
int mo_kill(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* victim;
  char*          user;
  char           msg[TOPICLEN + 3]; /* (, ), and \0 */

  assert(0 != cptr);
  assert(0 != sptr);
  /*
   * oper connection to this server, cptr is always sptr
   */
  assert(cptr == sptr);
  assert(IsAnOper(sptr));

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return need_more_params(sptr, "KILL");

  user = parv[1];
  ircd_snprintf(0, msg, sizeof(msg), "(%.*s)", TOPICLEN, parv[parc - 1]);

  if (!(victim = FindClient(user))) {
    /*
     * If the user has recently changed nick, we automaticly
     * rewrite the KILL for this new nickname--this keeps
     * servers in synch when nick change and kill collide
     */
    if (!(victim = get_history(user, (long)15)))
      return send_reply(sptr, ERR_NOSUCHNICK, user);

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Changed KILL %s into %s", sptr,
		  user, cli_name(victim));
  }
  if (!HasPriv(sptr, MyConnect(victim) ? PRIV_LOCAL_KILL : PRIV_KILL))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (IsServer(victim) || IsMe(victim)) {
    return send_reply(sptr, ERR_CANTKILLSERVER);
  }
  /*
   * if the user is +k, prevent a kill from local user
   */
  if (IsChannelService(victim))
    return send_reply(sptr, ERR_ISCHANSERVICE, "KILL", cli_name(victim));


  if (!MyConnect(victim) && !HasPriv(sptr, PRIV_KILL)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Nick %s isnt on your server",
		  sptr, cli_name(victim));
    return 0;
  }
  return do_kill(cptr, sptr, victim, cli_user(sptr)->host, cli_name(sptr),
		 msg);
}
