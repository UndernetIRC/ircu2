/*
 * IRC - Internet Relay Chat, ircd/m_ping.c
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
 * Stupid ircd Tricks
 * Excerpt from conversation on #coder-com:
 *  > the number horks it
 *  <Gte-> yea
 *  > thinks it's a numeric?
 *  > no
 *  <Gte-> hm
 *  > why would the number hork it
 *  <Gte-> why is it even looking up servers in a client ping :)
 *  > it's a server ping
 *  <Gte-> true
 *  > oh
 *  > I know why :)
 *  >   origin = parv[1];
 *  >   destination = parv[2];
 *  >   acptr = FindClient(origin);
 *  >   if (acptr && acptr != sptr)
 *  >     origin = cptr->name;
 *  > heh, that's a bug :)
 *  <Gte-> yea, client/server handling in the same function sucks :P
 *  > blindly pass a bogus origin around, and where do you send the reply to?
 *  <Gte-> I tried /quote ping 12345 uworld.blah.net locally, and uworld
 *  +recieved -> ":Gte- PING N :Uworld.blah.net"
 *  <Gte-> oh no, sorry, I did ping N :)
 *  > right, it's broken
 *  <Gte-> good thing it doesn't have a fit replying to it
 *  > hmm
 *  *** plano.tx.us.undernet.org: PONG received from plano.tx.us.undernet.org
 *  > you can send a number for the first ping .. but if you ping a remote server
 *  +it goes to the remote end where it's received as a unsolicited pong by the
 *  +server closest to the target
 *  > hahaha
 *  <Gte-> cool
 *  <Gte-> Parsing: :Gte PING 12345 :widnes.uk.eu.blah.net
 *  <Gte-> Sending [:widnes.uk.eu.blah.net PONG widnes.uk.eu.blah.net
 *  +:12345] to alphatest.blah.net
 *  <Gte-> Parsing: :alphatest.blah.net 402 widnes.uk.eu.blah.net
 *  +12345 :No such server
 *  > oh even better, the pongee sends no such server :)
 *  > bwhahahah
 *  <Gte-> for a second, I thought you could trigger a loop, which would be
 *  +hideously nasty, but it doesn't look like
 *  > it goes a ------ > b ------- > c ------- > d then c <------- d then c -----
 *  +> d :)
 *  <Gte-> weeee
 *  <Gte-> [04:15] -> Server: ping Gte- Dallas-R.Tx.US.Undernet.org
 *  <Gte-> *** PONG from Dallas-R.Tx.US.Undernet.org: Gte-
 *  <Gte-> there we go
 *  <Gte-> I can get a ping reply from a server I'm not on :)
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_debug.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Handle a PING message from a normal client connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the message to send in the PONG response
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_ping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NOORIGIN);

  sendcmdto_one(&me, CMD_PONG, sptr, "%C :%s", &me, parv[1]);
  return 0;
}

/** Handle a PING message from an operator's connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the message to send in the PONG response
 * \li \a parv[2] (optional) is the server to ping
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_ping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char *destination, *origin;
  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NOORIGIN);

  origin = parv[1];
  destination = parv[2];        /* Will get NULL or pointer (parc >= 2!!) */

  if (!EmptyString(destination) && 0 != ircd_strcmp(destination, cli_name(&me))) {
    if ((acptr = FindServer(destination)))
      sendcmdto_prio_one(sptr, CMD_PING, acptr, "%C :%s", sptr, destination);
    else
      send_reply(sptr, ERR_NOSUCHSERVER, destination);
  }
  else {
    /*
     * NOTE: clients rely on this to return the origin string.
     * it's pointless to send more than 64 bytes back tho'
     */
    char* origin = parv[1];
    
    /* Is this supposed to be here? */
    acptr = FindClient(origin);
    if (acptr && acptr != sptr)
      origin = cli_name(cptr);
    
    if (strlen(origin) > 64)
      origin[64] = '\0';
    sendcmdto_one(&me, CMD_PONG, sptr, "%C :%s", &me, origin);
  }
  return 0;
}

/*
 * Extension notes
 *
 * <Vek> bleep:  here's the change you make to PING:
 * <Vek> F TOK_PING F G 7777777777.7777777
 * <Vek> then optional parameter for further enhancement
 * <Vek> G TOK_PONG G F 7777777777.7777777 0.1734637
 */

/** Handle a PING message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the numnick of the client or server who
 *   originated the PING
 * \li \a parv[2] (optional) is the PING destination
 * \li \a parv[3] (optional) is an AsLL ping timestamp (seconds.msec)
 *
 * For AsLL pings, \a parv[1] and \a parv[2] are ignored.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_ping(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char*          origin;
  char*          destination;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if (parc < 2 || EmptyString(parv[1])) {
    /*
     * don't bother sending the error back
     */
    return 0;
  }
  origin      = parv[1];
  destination = parv[2];        /* Will get NULL or pointer (parc >= 2!!) */

  if (parc > 3)
  {
    /* AsLL ping, send reply back */
    int diff = atoi(militime_float(parv[3]));
    sendcmdto_prio_one(&me, CMD_PONG, sptr, "%C %s %s %i %s", &me, origin,
                       parv[3], diff, militime_float(NULL));
    return 0;
  }
  if (!EmptyString(destination) && 0 != ircd_strcmp(destination, cli_name(&me))) {
    if ((acptr = FindServer(destination))) {
      /*
       * Servers can just forward the origin
       */
      sendcmdto_prio_one(sptr, CMD_PING, acptr, "%s :%s", origin, destination);
    }
    else {
      /*
       * this can happen if server split before the ping got here
       */
      send_reply(sptr, ERR_NOSUCHSERVER, destination);
    }
  }
  else {
    /*
     * send pong back
     * NOTE:  sptr is never local so if pong handles numerics everywhere we
     * could send a numeric here.
     */
    sendcmdto_prio_one(&me, CMD_PONG, sptr, "%C :%s", &me, origin);
  }
  return 0;
}
