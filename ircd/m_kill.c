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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_misc.h"
#include "send.h"
#include "whowas.h"

#include <assert.h>
#include <string.h>

#if defined(DEBUGMODE)
#define SYSLOG_KILL
#endif

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
  const char*    inpath;
  char*          user;
  char*          path;
  char*          killer;
  char           buf[BUFSIZE];

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  /*
   * XXX - a server sending less than 3 params could really desync
   * things
   */
  if (parc < 3)
    return need_more_params(sptr, "KILL");

  user = parv[1];
  path = parv[parc - 1];        /* Either defined or NULL (parc >= 3) */

  if (!(victim = findNUser(parv[1]))) {
    if (IsUser(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :KILL target disconnected "
		    "before I got him :(", sptr);
    return 0;
  }
#if 0
  /*
   * XXX - strictly speaking, the next 2 checks shouldn't be needed
   * this function only handles kills from servers, and the check
   * is done before the message is propagated --Bleep
   */
  if (IsServer(victim) || IsMe(victim)) {
    return send_error_to_client(sptr, ERR_CANTKILLSERVER); /* XXX DEAD */
    return 0;
  }
  if (IsLocOp(sptr) && !MyConnect(victim)) {
    return send_error_to_client(sptr, ERR_NOPRIVILEGES); /* XXX DEAD */
    return 0;
  }
  /*
   * XXX - this is guaranteed by the parser not to happen
   */
  if (EmptyString(path))
    path = "*no-path*";                /* Bogus server sending??? */
#endif
  /*
   * Notify all *local* opers about the KILL (this includes the one
   * originating the kill, if from this server--the special numeric
   * reply message is not generated anymore).
   *
   * Note: "victim->name" is used instead of "user" because we may
   *       have changed the target because of the nickname change.
   */
  inpath = cptr->name;

  sendto_opmask_butone(0, IsServer(sptr) ? SNO_SERVKILL : SNO_OPERKILL,
		       "Received KILL message for %s. From %s Path: %C!%s",
		       get_client_name(victim,SHOW_IP), parv[0], cptr, path);

#if defined(SYSLOG_KILL)
  ircd_log_kill(victim, sptr, cptr->name, path);
#endif
  /*
   * And pass on the message to other servers. Note, that if KILL
   * was changed, the message has to be sent to all links, also
   * back.
   */
  sendcmdto_serv_butone(sptr, CMD_KILL, cptr, "%C :%s!%s", victim, cptr->name,
			path);
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
  if (MyConnect(victim))
    sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s!%s (Ghost 5 Numeric Collided)",
		  victim, cptr->name, path);
  /*
   * Set FLAGS_KILLED. This prevents exit_one_client from sending
   * the unnecessary QUIT for this. (This flag should never be
   * set in any other place)
   */
  victim->flags |= FLAGS_KILLED;

  /*
   * Tell the victim she/he has been zapped, but *only* if
   * the victim is on current server--no sense in sending the
   * notification chasing the above kill, it won't get far
   * anyway (as this user don't exist there any more either)
   */
  if (MyConnect(victim))
    sendcmdto_one(sptr, CMD_KILL, victim, "%C :%s!%s", victim, NumServ(cptr),
		  path);
  /*
   * the first space in path will be at the end of the
   * opers name:
   * bla.bla.bla!host.net.dom!opername (comment)
   */
  if ((killer = strchr(path, ' '))) {
    while (killer > path && '!' != *killer)
      --killer;
    if ('!' == *killer)
      ++killer;
  }
  else
    killer = path;
  sprintf_irc(buf, "Killed (%s)", killer);

  return exit_client(cptr, victim, sptr, buf);
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
  const char*    inpath;
  char*          user;
  char*          path;
  char*          comment;
  char           buf[BUFSIZE];

  assert(0 != cptr);
  assert(0 != sptr);
  /*
   * oper connection to this server, cptr is always sptr
   */
  assert(cptr == sptr);
  assert(IsAnOper(sptr));

#if defined(OPER_KILL)

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return need_more_params(sptr, "KILL");

  user = parv[1];
  if (!(victim = FindClient(user))) {
    /*
     * If the user has recently changed nick, we automaticly
     * rewrite the KILL for this new nickname--this keeps
     * servers in synch when nick change and kill collide
     */
    if (!(victim = get_history(user, (long)15)))
      return send_reply(sptr, ERR_NOSUCHNICK, user);

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Changed KILL %s into %s", sptr,
		  user, victim->name);
  }
  if (!MyConnect(victim) && IsLocOp(cptr))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (IsServer(victim) || IsMe(victim)) {
    return send_reply(sptr, ERR_CANTKILLSERVER);
  }
  /*
   * if the user is +k, prevent a kill from local user
   */
  if (IsChannelService(victim))
    return send_reply(sptr, ERR_ISCHANSERVICE, "KILL", victim->name);


#ifdef LOCAL_KILL_ONLY
  if (!MyConnect(victim)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Nick %s isnt on your server", sptr,
	       victim->name);
    return 0;
  }
#endif
  /*
   * The kill originates from this server, initialize path.
   * (In which case the 'path' may contain user suplied
   * explanation ...or some nasty comment, sigh... >;-)
   *
   * ...!operhost!oper
   * ...!operhost!oper (comment)
   */

  comment = parv[parc - 1];        /* Either defined or NULL (parc >= 3) */

  if (strlen(comment) > TOPICLEN)
    comment[TOPICLEN] = '\0';

  inpath = sptr->user->host;

  sprintf_irc(buf,
              "%s%s (%s)", cptr->name, IsOper(sptr) ? "" : "(L)", comment);
  path = buf;

  /*
   * Notify all *local* opers about the KILL (this includes the one
   * originating the kill, if from this server--the special numeric
   * reply message is not generated anymore).
   *
   * Note: "victim->name" is used instead of "user" because we may
   *       have changed the target because of the nickname change.
   */
  sendto_opmask_butone(0, SNO_OPERKILL,
		       "Received KILL message for %s. From %s Path: %s!%s",
		       get_client_name(victim,SHOW_IP), parv[0], inpath, path);

#if defined(SYSLOG_KILL)
  ircd_log_kill(victim, sptr, inpath, path);
#endif
  /*
   * And pass on the message to other servers. Note, that if KILL
   * was changed, the message has to be sent to all links, also
   * back.
   * Suicide kills are NOT passed on --SRB
   */
  if (!MyConnect(victim)) {
    sendcmdto_serv_butone(sptr, CMD_KILL, cptr, "%C :%s!%s", victim, inpath,
			  path);

   /*
    * Set FLAGS_KILLED. This prevents exit_one_client from sending
    * the unnecessary QUIT for this. (This flag should never be
    * set in any other place)
    */
    victim->flags |= FLAGS_KILLED;

    sprintf_irc(buf, "Killed by %s (%s)", sptr->name, comment);
  }
  else {
  /*
   * Tell the victim she/he has been zapped, but *only* if
   * the victim is on current server--no sense in sending the
   * notification chasing the above kill, it won't get far
   * anyway (as this user don't exist there any more either)
   */
    sendcmdto_one(sptr, CMD_KILL, victim, "%C :%s!%s", victim, inpath, path);
    sprintf_irc(buf, "Local kill by %s (%s)", sptr->name, comment);
  }

  return exit_client(cptr, victim, sptr, buf);

#else /* !defined(OPER_KILL) */

  return send_reply(sptr, ERR_NOPRIVILEGES);

#endif /* !defined(OPER_KILL) */
}

#if 0
/*
 * m_kill
 *
 * parv[0] = sender prefix
 * parv[1] = kill victim
 * parv[parc-1] = kill path
 */
int m_kill(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client* acptr;
  const char*    inpath = get_client_name(cptr, HIDE_IP);
  char*          user;
  char*          path;
  char*          killer;
  int            chasing = 0;
  char           buf[BUFSIZE];
  char           buf2[BUFSIZE];

  if (parc < 3 || *parv[1] == '\0')
    return need_more_params(sptr, parv[0], "KILL");

  user = parv[1];
  path = parv[parc - 1];        /* Either defined or NULL (parc >= 3) */

#ifdef        OPER_KILL
  if (!IsPrivileged(cptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }
#else
  if (!IsServer(cptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }
#endif
  if (IsAnOper(cptr))
  {
    if (EmptyString(path))
      return need_more_params(sptr, parv[0], "KILL");

    if (strlen(path) > TOPICLEN)
      path[TOPICLEN] = '\0';
  }

  if (MyUser(sptr))
  {
    if (!(acptr = FindClient(user)))
    {
      /*
       * If the user has recently changed nick, we automaticly
       * rewrite the KILL for this new nickname--this keeps
       * servers in synch when nick change and kill collide
       */
      if (!(acptr = get_history(user, (long)15)))
      {
        sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], user); /* XXX DEAD */
        return 0;
      }
      sendto_one(sptr, ":%s NOTICE %s :Changed KILL %s into %s", /* XXX DEAD */
          me.name, parv[0], user, acptr->name);
      chasing = 1;
    }
  }
  else if (!(acptr = findNUser(user)))
  {
    if (IsUser(sptr))
      sendto_one(sptr, /* XXX DEAD */
          "%s NOTICE %s%s :KILL target disconnected before I got him :(",
          NumServ(&me), NumNick(sptr));
    return 0;
  }
  if (!MyConnect(acptr) && IsLocOp(cptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }
  if (IsServer(acptr) || IsMe(acptr))
  {
    sendto_one(sptr, err_str(ERR_CANTKILLSERVER), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }

  /* if the user is +k, prevent a kill from local user */
  if (IsChannelService(acptr) && MyUser(sptr))
  {
    sendto_one(sptr, err_str(ERR_ISCHANSERVICE), me.name, /* XXX DEAD */
        parv[0], "KILL", acptr->name);
    return 0;
  }

#ifdef        LOCAL_KILL_ONLY
  if (MyConnect(sptr) && !MyConnect(acptr))
  {
    sendto_one(sptr, ":%s NOTICE %s :Nick %s isnt on your server", /* XXX DEAD */
        me.name, parv[0], acptr->name);
    return 0;
  }
#endif
  if (!IsServer(cptr))
  {
    /*
     * The kill originates from this server, initialize path.
     * (In which case the 'path' may contain user suplied
     * explanation ...or some nasty comment, sigh... >;-)
     *
     * ...!operhost!oper
     * ...!operhost!oper (comment)
     */
    inpath = cptr->sockhost;

    if (!EmptyString(path))
    {
      sprintf_irc(buf,
          "%s%s (%s)", cptr->name, IsOper(sptr) ? "" : "(L)", path);
      path = buf;
    }
    else
      path = cptr->name;
  }
  else if (EmptyString(path))
    path = "*no-path*";                /* Bogus server sending??? */
  /*
   * Notify all *local* opers about the KILL (this includes the one
   * originating the kill, if from this server--the special numeric
   * reply message is not generated anymore).
   *
   * Note: "acptr->name" is used instead of "user" because we may
   *       have changed the target because of the nickname change.
   */
  if (IsLocOp(sptr) && !MyConnect(acptr))
  {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]); /* XXX DEAD */
    return 0;
  }
  sendto_op_mask(IsServer(sptr) ? SNO_SERVKILL : SNO_OPERKILL, /* XXX DEAD */
      "Received KILL message for %s. From %s Path: %s!%s",
      acptr->name, parv[0], inpath, path);
#if defined(USE_SYSLOG) && defined(SYSLOG_KILL)
  if (MyUser(acptr))
  {                                /* get more infos when your local
                                   clients are killed -- _dl */
    if (IsServer(sptr))
      ircd_log(L_TRACE,
          "A local client %s!%s@%s KILLED from %s [%s] Path: %s!%s)",
          acptr->name, acptr->user->username, acptr->user->host,
          parv[0], sptr->name, inpath, path);
    else
      ircd_log(L_TRACE,
          "A local client %s!%s@%s KILLED by %s [%s!%s@%s] (%s!%s)",
          acptr->name, acptr->user->username, acptr->user->host,
          parv[0], sptr->name, sptr->user->username, sptr->user->host,
          inpath, path);
  }
  else if (IsOper(sptr))
    ircd_log(L_TRACE, "KILL From %s For %s Path %s!%s",
        parv[0], acptr->name, inpath, path);
#endif
  /*
   * And pass on the message to other servers. Note, that if KILL
   * was changed, the message has to be sent to all links, also
   * back.
   * Suicide kills are NOT passed on --SRB
   */
  if (!MyConnect(acptr) || !MyConnect(sptr) || !IsAnOper(sptr))
  {
    sendto_highprot_butone(cptr, 10, ":%s " TOK_KILL " %s%s :%s!%s", /* XXX DEAD */
        parv[0], NumNick(acptr), inpath, path);
    /* We *can* have crossed a NICK with this numeric... --Run */
    /* Note the following situation:
     *  KILL SAA -->       X
     *  <-- S NICK ... SAA | <-- SAA QUIT <-- S NICK ... SAA <-- SQUIT S
     * Where the KILL reaches point X before the QUIT does.
     * This would then *still* cause an orphan because the KILL doesn't reach S
     * (because of the SQUIT), the QUIT is ignored (because of the KILL)
     * and the second NICK ... SAA causes an orphan on the server at the
     * right (which then isn't removed when the SQUIT arrives).
     * Therefore we still need to detect numeric nick collisions too.
     */
    if (MyConnect(acptr) && IsServer(cptr))
      sendto_one(cptr, "%s " TOK_KILL " %s%s :%s!%s (Ghost5)", /* XXX DEAD */
          NumServ(&me), NumNick(acptr), inpath, path);
    acptr->flags |= FLAGS_KILLED;
  }

  /*
   * Tell the victim she/he has been zapped, but *only* if
   * the victim is on current server--no sense in sending the
   * notification chasing the above kill, it won't get far
   * anyway (as this user don't exist there any more either)
   */
  if (MyConnect(acptr))
    sendto_prefix_one(acptr, sptr, ":%s KILL %s :%s!%s", /* XXX DEAD */
        parv[0], acptr->name, inpath, path);
  /*
   * Set FLAGS_KILLED. This prevents exit_one_client from sending
   * the unnecessary QUIT for this. (This flag should never be
   * set in any other place)
   */
  if (MyConnect(acptr) && MyConnect(sptr) && IsAnOper(sptr))
    sprintf_irc(buf2, "Local kill by %s (%s)", sptr->name,
        EmptyString(parv[parc - 1]) ? sptr->name : parv[parc - 1]);
  else
  {
    if ((killer = strchr(path, ' ')))
    {
      while (*killer && *killer != '!')
        killer--;
      if (!*killer)
        killer = path;
      else
        killer++;
    }
    else
      killer = path;
    sprintf_irc(buf2, "Killed (%s)", killer);
  }
  return exit_client(cptr, acptr, sptr, buf2);
}

#endif /* 0 */

